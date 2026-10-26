"""Retention: a purge deletes an old prefix, leaves a signed checkpoint, and is audited."""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import timedelta
from typing import Any

import psycopg
import pytest

from chain_support import age, rechain, stored
from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.actions import PURGE_ACTION, register_audit_actions
from warden.audit.checkpoint import Checkpoint
from warden.audit.retention import MIN_RETENTION_DAYS, RetentionError, purge
from warden.audit.store import AuditRow
from warden.audit.verify import verify_chain
from warden.db import Database
from warden.keys import KeyStore

pytestmark = pytest.mark.db


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    register_audit_actions(registry)
    return registry


@pytest.fixture
def recorder(pool: Any, registry: ActionRegistry) -> AuditRecorder:
    return AuditRecorder(Database(pool), registry)


@pytest.fixture
async def keys(pool: Any) -> KeyStore:
    store = KeyStore(Database(pool), MemorySecrets())
    await store.rotate()
    return store


def _all(dsn: str) -> list[AuditRow]:
    return stored(dsn)


def _age(dsn: str, ids: list[int], days: int) -> None:
    age(dsn, ids, days)


async def _record(recorder: AuditRecorder, n: int) -> int:
    return await recorder.record(
        AuditEvent(action="product.export", outcome="success", actor=f"user-{n}")
    )


async def test_retention_below_the_minimum_is_refused(
    recorder: AuditRecorder, keys: KeyStore
) -> None:
    with pytest.raises(RetentionError, match="minimum"):
        await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS - 1)


async def test_nothing_old_enough_purges_nothing(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str
) -> None:
    await _record(recorder, 0)
    result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert result.purged_rows == 0
    assert result.checkpoint_id is None
    assert len(_all(migrated_dsn)) == 1


async def test_a_purge_deletes_the_old_prefix_and_leaves_a_signed_checkpoint(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids = [await _record(recorder, n) for n in range(5)]
    _age(migrated_dsn, ids[:3], MIN_RETENTION_DAYS + 10)
    through_hash = next(r.row_hash for r in _all(migrated_dsn) if r.id == ids[2])

    result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS, actor="ops-1")

    assert (result.purged_rows, result.through_id) == (3, ids[2])
    rows = _all(migrated_dsn)
    assert [r.id for r in rows] == [*ids[3:], result.checkpoint_id]
    checkpoint_row = rows[-1]
    assert (checkpoint_row.action, checkpoint_row.outcome, checkpoint_row.actor) == (
        PURGE_ACTION,
        "success",
        "ops-1",
    )
    checkpoint = Checkpoint.from_details(checkpoint_row.details)
    assert (checkpoint.first_purged_id, checkpoint.through_id) == (ids[0], ids[2])
    assert checkpoint.through_hash == through_hash == rows[0].prev_hash
    assert checkpoint.purged_rows == 3
    assert checkpoint.retention_days == MIN_RETENTION_DAYS
    assert await keys.verify_historical(
        checkpoint.message(), checkpoint.signature, checkpoint.key_id
    )

    report = await verify_chain(Database(pool), keys)
    assert report.ok, report.broken
    assert (report.rows, report.first_id, report.checkpoints) == (3, ids[3], 1)


async def test_purge_never_deletes_a_row_younger_than_the_cutoff(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str
) -> None:
    """Only a prefix goes: an old row after a young one (a clock step) is kept."""
    ids = [await _record(recorder, n) for n in range(4)]
    _age(migrated_dsn, [ids[0], ids[2]], MIN_RETENTION_DAYS + 10)
    result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert result.through_id == ids[0]
    assert [r.id for r in _all(migrated_dsn)][:3] == ids[1:]


async def test_purging_everything_leaves_only_the_checkpoint(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids = [await _record(recorder, n) for n in range(3)]
    _age(migrated_dsn, ids, MIN_RETENTION_DAYS + 10)
    result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert [r.id for r in _all(migrated_dsn)] == [result.checkpoint_id]
    report = await verify_chain(Database(pool), keys)
    assert report.ok, report.broken
    # The chain carries on from the checkpoint.
    await _record(recorder, 9)
    assert (await verify_chain(Database(pool), keys)).ok


async def test_verification_continues_across_successive_purges(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids = [await _record(recorder, n) for n in range(3)]
    _age(migrated_dsn, ids[:1], MIN_RETENTION_DAYS + 10)
    first = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    more = [await _record(recorder, n) for n in range(3, 5)]
    assert first.checkpoint_id is not None
    _age(migrated_dsn, [*ids[1:], first.checkpoint_id], MIN_RETENTION_DAYS + 10)
    second = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert [r.id for r in _all(migrated_dsn)] == [*more, second.checkpoint_id]
    report = await verify_chain(Database(pool), keys)
    assert report.ok, report.broken


async def _purged_trail(recorder: AuditRecorder, keys: KeyStore, dsn: str) -> list[int]:
    ids = [await _record(recorder, n) for n in range(4)]
    _age(dsn, ids[:2], MIN_RETENTION_DAYS + 10)
    await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    return ids


async def test_a_forged_checkpoint_fails(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """A checkpoint not signed by warden's key fails, even with every hash recomputed."""
    ids = await _purged_trail(recorder, keys, migrated_dsn)
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute(
            "UPDATE warden.audit_events SET details = jsonb_set(details,"
            " '{checkpoint,purged_rows}', '1') WHERE action = %s",
            (PURGE_ACTION,),
        )
        rechain(conn)
    report = await verify_chain(Database(pool), keys)
    assert report.broken is not None
    assert (report.broken.row_id, report.broken.reason) == (ids[2], "checkpoint_signature")


async def test_a_checkpoint_signed_by_another_key_fails(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from warden.audit.checkpoint import CHECKPOINT_KEY

    ids = await _purged_trail(recorder, keys, migrated_dsn)
    (row,) = [r for r in _all(migrated_dsn) if r.action == PURGE_ACTION]
    genuine = Checkpoint.from_details(row.details)
    forged = dataclasses.replace(
        genuine, signature=Ed25519PrivateKey.generate().sign(genuine.message())
    )
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute(
            "UPDATE warden.audit_events SET details = %s WHERE id = %s",
            (psycopg.types.json.Jsonb(forged.to_details()), row.id),
        )
        rechain(conn)
    assert CHECKPOINT_KEY in row.details
    report = await verify_chain(Database(pool), keys)
    assert report.broken is not None
    assert (report.broken.row_id, report.broken.reason) == (ids[2], "checkpoint_signature")


async def test_a_checkpoint_survives_routine_key_retirement(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    await _purged_trail(recorder, keys, migrated_dsn)
    old = await keys.active_key()
    await keys.rotate()
    await keys.retire(old.key_id)
    report = await verify_chain(Database(pool), keys)
    assert report.ok, report.broken


async def test_a_checkpoint_signed_by_a_revoked_key_fails_and_says_so(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids = await _purged_trail(recorder, keys, migrated_dsn)
    old = await keys.active_key()
    await keys.rotate()
    await keys.revoke(old.key_id)
    report = await verify_chain(Database(pool), keys)
    assert report.broken is not None
    assert (report.broken.row_id, report.broken.reason) == (ids[2], "checkpoint_revoked_key")


async def test_a_purge_refuses_to_launder_a_broken_segment(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str
) -> None:
    ids = [await _record(recorder, n) for n in range(4)]
    _age(migrated_dsn, ids[:2], MIN_RETENTION_DAYS + 10)
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute("UPDATE warden.audit_events SET actor = 'intruder' WHERE id = %s", (ids[1],))
    with pytest.raises(RetentionError, match=f"row {ids[1]}"):
        await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS, actor="ops-1")
    rows = _all(migrated_dsn)
    assert [r.id for r in rows[:4]] == ids
    refusal = rows[-1]
    assert (refusal.action, refusal.outcome, refusal.actor) == (PURGE_ACTION, "failure", "ops-1")
    assert refusal.details == {"reason": "chain_broken", "row_id": ids[1]}


async def test_appends_racing_a_purge_keep_the_chain_intact(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids = [await _record(recorder, n) for n in range(6)]
    _age(migrated_dsn, ids[:4], MIN_RETENTION_DAYS + 10)
    barrier = asyncio.Barrier(5)

    async def writer(n: int) -> int:
        await barrier.wait()
        return await _record(recorder, 100 + n)

    async def purger() -> Any:
        await barrier.wait()
        return await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)

    results = await asyncio.gather(purger(), *(writer(n) for n in range(4)))
    assert results[0].purged_rows == 4
    report = await verify_chain(Database(pool), keys)
    assert report.ok, report.broken
    assert report.rows == 2 + 4 + 1


async def test_concurrent_purges_purge_once(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids = [await _record(recorder, n) for n in range(4)]
    _age(migrated_dsn, ids[:3], MIN_RETENTION_DAYS + 10)
    barrier = asyncio.Barrier(2)

    async def purger() -> Any:
        await barrier.wait()
        try:
            return await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
        except RetentionError as exc:
            return exc

    results = await asyncio.gather(purger(), purger())
    succeeded = [r for r in results if not isinstance(r, RetentionError)]
    assert sum(r.purged_rows for r in succeeded) == 3
    rows = _all(migrated_dsn)
    assert sum(1 for r in rows if r.action == PURGE_ACTION and r.outcome == "success") == 1
    report = await verify_chain(Database(pool), keys)
    assert report.ok, report.broken


async def test_the_checkpoint_is_never_truncated(
    pool: Any, registry: ActionRegistry, keys: KeyStore, migrated_dsn: str
) -> None:
    recorder = AuditRecorder(Database(pool), registry, details_max_bytes=256)
    ids = [await _record(recorder, n) for n in range(2)]
    _age(migrated_dsn, ids[:1], MIN_RETENTION_DAYS + 10)
    await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert (await verify_chain(Database(pool), keys)).ok


def test_minimum_retention_is_at_least_a_year() -> None:
    assert timedelta(days=MIN_RETENTION_DAYS) >= timedelta(days=365)
