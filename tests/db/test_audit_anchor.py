"""Anchoring: signed head attestations, and verifying a chain against anchors held outside it.

The acceptance tests of the anchor workstream: altering a row before the
latest external anchor, deleting the tail and rewriting from genesis are each
detected and named; a forged anchor signature and a revoked key are refused;
a retired key still verifies; anchors survive a purge.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Any

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chain_support import age, rechain, stored
from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.actions import ANCHOR_ACTION, register_audit_actions
from warden.audit.anchor import Anchor, AnchorRecord, ExternalAnchor, anchor, read_anchors
from warden.audit.chain import canonical_json
from warden.audit.export import ndjson_lines
from warden.audit.query import AuditQuery, iter_events
from warden.audit.retention import MIN_RETENTION_DAYS, purge
from warden.audit.syslog import AuditRecord, SyslogSettings, format_message
from warden.audit.verify import AnchorReport, verify_anchors, verify_chain
from warden.db import Database
from warden.keys import KeyStore, KeyStoreError

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


async def _record(recorder: AuditRecorder, n: int) -> int:
    return await recorder.record(
        AuditEvent(action="product.export", outcome="success", actor=f"user-{n}")
    )


async def _anchor(recorder: AuditRecorder, keys: KeyStore, **kw: Any) -> AnchorRecord:
    written = await anchor(recorder, keys, **kw)
    assert written is not None
    return written


def _external(*records: AnchorRecord) -> list[ExternalAnchor]:
    return [
        ExternalAnchor(line=n, row_id=r.row_id, anchor=r.anchor)
        for n, r in enumerate(records, start=1)
    ]


def _statuses(report: AnchorReport) -> list[str]:
    return [check.status for check in report.anchors]


def _sql(dsn: str, statement: str, params: tuple[Any, ...] = ()) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute(statement, params)


# anchor()


async def test_an_anchor_signs_the_committed_head(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids = [await _record(recorder, n) for n in range(3)]
    written = await _anchor(recorder, keys, actor="scheduler")

    rows = stored(migrated_dsn)
    head, carrier = rows[-2], rows[-1]
    assert head.id == ids[-1] == written.anchor.head_id
    assert carrier.id == written.row_id
    assert (carrier.action, carrier.outcome, carrier.actor) == (
        ANCHOR_ACTION,
        "success",
        "scheduler",
    )
    # Nothing else was recorded meanwhile, so the anchor row follows its head.
    assert carrier.prev_hash == head.row_hash == written.anchor.head_hash
    assert Anchor.from_details(carrier.details) == written.anchor
    assert written.anchor.key_id == (await keys.active_key()).key_id
    assert await keys.verify_historical(
        written.anchor.message(), written.anchor.signature, written.anchor.key_id
    )
    assert (await verify_chain(Database(pool), keys)).ok


async def test_an_empty_trail_is_not_anchored(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str
) -> None:
    assert await anchor(recorder, keys) is None
    assert stored(migrated_dsn) == []


async def test_anchoring_without_a_signing_key_writes_nothing(
    recorder: AuditRecorder, pool: Any, migrated_dsn: str
) -> None:
    await _record(recorder, 0)
    with pytest.raises(KeyStoreError):
        await anchor(recorder, KeyStore(Database(pool), MemorySecrets()))
    assert [r.action for r in stored(migrated_dsn)] == ["product.export"]


async def test_the_anchor_is_never_truncated(
    pool: Any, registry: ActionRegistry, keys: KeyStore, migrated_dsn: str
) -> None:
    recorder = AuditRecorder(Database(pool), registry, details_max_bytes=256)
    await _record(recorder, 0)
    written = await _anchor(recorder, keys)
    carrier = stored(migrated_dsn)[-1]
    assert len(canonical_json(carrier.details)) > 256
    assert Anchor.from_details(carrier.details) == written.anchor


async def test_an_actor_too_long_to_forward_whole_is_refused(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str
) -> None:
    from warden.audit.anchor import MAX_ANCHOR_ACTOR

    await _record(recorder, 0)
    with pytest.raises(ValueError, match="actor"):
        await anchor(recorder, keys, actor="a" * (MAX_ANCHOR_ACTOR + 1))
    assert await anchor(recorder, keys, actor="a" * MAX_ANCHOR_ACTOR) is not None
    assert [r.action for r in stored(migrated_dsn)] == ["product.export", ANCHOR_ACTION]


async def test_min_rows_anchors_only_after_enough_new_rows(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str
) -> None:
    for n in range(2):
        await _record(recorder, n)
    assert await anchor(recorder, keys, min_rows=3) is None
    await _record(recorder, 2)
    assert await anchor(recorder, keys, min_rows=3) is not None
    # The anchor row itself does not count, so an idle trail is not anchored again.
    assert await anchor(recorder, keys, min_rows=1) is None
    await _record(recorder, 3)
    assert await anchor(recorder, keys, min_rows=1) is not None
    assert [r.action for r in stored(migrated_dsn)].count(ANCHOR_ACTION) == 2
    with pytest.raises(ValueError, match="min_rows"):
        await anchor(recorder, keys, min_rows=0)


async def test_anchors_racing_writers_attest_committed_heads_without_starving_the_pool(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """More concurrent writers and anchors than the pool has connections (six)."""
    await _record(recorder, 0)
    barrier = asyncio.Barrier(8)

    async def writer(n: int) -> int:
        await barrier.wait()
        return await _record(recorder, 100 + n)

    async def anchorer() -> AnchorRecord:
        await barrier.wait()
        return await _anchor(recorder, keys)

    results = await asyncio.gather(*(writer(n) for n in range(5)), *(anchorer() for _ in range(3)))
    anchors = [r for r in results if isinstance(r, AnchorRecord)]
    assert len(anchors) == 3
    hashes = {row.id: row.row_hash for row in stored(migrated_dsn)}
    for written in anchors:
        assert written.anchor.head_id < written.row_id
        assert hashes[written.anchor.head_id] == written.anchor.head_hash
    assert (await verify_chain(Database(pool), keys)).ok
    report = await verify_anchors(Database(pool), keys, _external(*anchors))
    assert report.ok, report


# verify_anchors(): the acceptance tests.


async def _trail(
    recorder: AuditRecorder, keys: KeyStore
) -> tuple[list[int], AnchorRecord, AnchorRecord]:
    """Five rows, an anchor, three rows, an anchor, two rows."""
    ids = [await _record(recorder, n) for n in range(5)]
    first = await _anchor(recorder, keys)
    ids += [await _record(recorder, n) for n in range(5, 8)]
    second = await _anchor(recorder, keys)
    ids += [await _record(recorder, n) for n in range(8, 10)]
    return ids, first, second


async def test_an_intact_trail_matches_its_anchors(
    recorder: AuditRecorder, keys: KeyStore, pool: Any
) -> None:
    _, first, second = await _trail(recorder, keys)
    report = await verify_anchors(Database(pool), keys, _external(first, second))
    assert report.ok
    assert report.chain.ok
    assert _statuses(report) == ["matched", "matched"]
    assert [c.head_id for c in report.anchors] == [first.anchor.head_id, second.anchor.head_id]


async def test_altering_a_row_before_the_latest_anchor_is_named(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids, first, second = await _trail(recorder, keys)
    target = ids[6]  # after the first anchor's head, before the second's
    _sql(migrated_dsn, "UPDATE warden.audit_events SET actor = 'intruder' WHERE id = %s", (target,))
    report = await verify_anchors(Database(pool), keys, _external(first, second))
    assert not report.ok
    assert report.chain.broken is not None
    assert (report.chain.broken.row_id, report.chain.broken.reason) == (target, "row_hash")


async def test_a_rewrite_that_recomputes_every_hash_is_named_by_the_anchor(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """The chain alone verifies after a full re-hash; the external anchor does not match."""
    ids, first, second = await _trail(recorder, keys)
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute("UPDATE warden.audit_events SET actor = 'intruder' WHERE id = %s", (ids[6],))
        rechain(conn)
    report = await verify_anchors(Database(pool), keys, _external(first, second))
    assert report.chain.ok
    assert not report.ok
    assert _statuses(report) == ["matched", "head_hash"]
    assert "rewritten" in report.anchors[1].description


async def test_deleting_the_tail_is_named(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids, first, second = await _trail(recorder, keys)
    _sql(migrated_dsn, "DELETE FROM warden.audit_events WHERE id >= %s", (ids[6],))
    report = await verify_anchors(Database(pool), keys, _external(first, second))
    assert report.chain.ok  # the chain alone cannot see a missing tail
    assert not report.ok
    assert _statuses(report) == ["matched", "head_missing"]
    assert "tail" in report.anchors[1].description


async def test_rewriting_from_genesis_with_the_same_ids_is_named(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    ids, first, second = await _trail(recorder, keys)
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute("UPDATE warden.audit_events SET actor = 'intruder' WHERE id = %s", (ids[0],))
        rechain(conn)
    report = await verify_anchors(Database(pool), keys, _external(first, second))
    assert report.chain.ok
    assert _statuses(report) == ["head_hash", "head_hash"]


async def test_rewriting_from_genesis_as_a_fresh_chain_is_named(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    _, first, second = await _trail(recorder, keys)
    _sql(migrated_dsn, "DELETE FROM warden.audit_events")
    for n in range(3):
        await _record(recorder, 50 + n)
    report = await verify_anchors(Database(pool), keys, _external(first, second))
    assert report.chain.ok
    assert _statuses(report) == ["head_missing", "head_missing"]


async def test_a_forged_anchor_signature_is_refused(
    recorder: AuditRecorder, keys: KeyStore, pool: Any
) -> None:
    _, first, second = await _trail(recorder, keys)
    other = Ed25519PrivateKey.generate()
    forged = dataclasses.replace(second, anchor=dataclasses.replace(
        second.anchor, signature=other.sign(second.anchor.message())
    ))  # fmt: skip
    report = await verify_anchors(Database(pool), keys, _external(first, forged))
    assert _statuses(report) == ["matched", "anchor_signature"]
    assert not report.ok


async def test_an_anchor_whose_claim_was_edited_is_refused(
    recorder: AuditRecorder, keys: KeyStore, pool: Any
) -> None:
    """Moving a genuine anchor to another head breaks its signature."""
    ids, first, _ = await _trail(recorder, keys)
    moved = dataclasses.replace(first, anchor=dataclasses.replace(first.anchor, head_id=ids[0]))
    report = await verify_anchors(Database(pool), keys, _external(moved))
    assert _statuses(report) == ["anchor_signature"]


async def test_a_checkpoint_signature_cannot_stand_in_for_an_anchor(
    recorder: AuditRecorder, keys: KeyStore, pool: Any
) -> None:
    """Signed by warden's own key, but over another domain's message: refused."""
    _, first, _ = await _trail(recorder, keys)
    body = canonical_json(first.anchor.payload())
    signed = await keys.sign(b"warden.audit.checkpoint.v1\n" + body)
    crossed = dataclasses.replace(
        first, anchor=dataclasses.replace(first.anchor, signature=signed.signature)
    )
    report = await verify_anchors(Database(pool), keys, _external(crossed))
    assert _statuses(report) == ["anchor_signature"]


async def test_an_anchor_signed_by_a_revoked_key_is_refused_and_says_so(
    recorder: AuditRecorder, keys: KeyStore, pool: Any
) -> None:
    _, first, _ = await _trail(recorder, keys)
    await keys.rotate()
    await keys.revoke(first.anchor.key_id)
    report = await verify_anchors(Database(pool), keys, _external(first))
    assert _statuses(report) == ["anchor_revoked_key"]
    assert "revoked" in report.anchors[0].description


async def test_an_anchor_signed_by_a_retired_key_still_verifies(
    recorder: AuditRecorder, keys: KeyStore, pool: Any
) -> None:
    _, first, _ = await _trail(recorder, keys)
    await keys.rotate()
    await keys.retire(first.anchor.key_id)
    report = await verify_anchors(Database(pool), keys, _external(first))
    assert report.ok
    assert _statuses(report) == ["matched"]


async def test_an_anchor_by_an_unknown_key_is_refused(
    recorder: AuditRecorder, keys: KeyStore, pool: Any
) -> None:
    _, first, _ = await _trail(recorder, keys)
    unknown = dataclasses.replace(first, anchor=dataclasses.replace(first.anchor, key_id="k-x"))
    report = await verify_anchors(Database(pool), keys, _external(unknown))
    assert _statuses(report) == ["anchor_signature"]


async def test_a_malformed_anchor_is_reported(keys: KeyStore, pool: Any) -> None:
    report = await verify_anchors(
        Database(pool), keys, [ExternalAnchor(line=7, row_id=12, anchor=None)]
    )
    assert not report.ok
    ((check),) = report.anchors
    assert (check.line, check.row_id, check.head_id, check.status) == (
        7,
        12,
        None,
        "anchor_malformed",
    )


# Anchors and retention. Ageing a row rewrites its recorded_at and re-chains
# from there (chain_support.age), so the rows up to an anchor's head are aged
# before the anchor is taken; ageing later rows leaves the head's hash alone.


async def _aged_then_anchored(
    recorder: AuditRecorder, keys: KeyStore, dsn: str, rows: int
) -> tuple[list[int], AnchorRecord]:
    ids = [await _record(recorder, n) for n in range(rows)]
    age(dsn, ids, MIN_RETENTION_DAYS + 10)
    return ids, await _anchor(recorder, keys)


async def test_an_anchor_whose_head_was_purged_is_checked_against_the_checkpoint(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """Purged exactly through the head: the checkpoint's hash is compared with the anchor's."""
    _, written = await _aged_then_anchored(recorder, keys, migrated_dsn, 3)
    await _record(recorder, 3)
    result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert result.through_id == written.anchor.head_id
    report = await verify_anchors(Database(pool), keys, _external(written))
    assert report.ok, report
    assert _statuses(report) == ["checkpointed"]


async def test_a_wrong_hash_at_the_checkpoint_boundary_is_named(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """A signed anchor claiming another hash for the checkpoint's last row does not match it."""
    _, written = await _aged_then_anchored(recorder, keys, migrated_dsn, 3)
    result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert result.through_id == written.anchor.head_id
    unsigned = dataclasses.replace(written.anchor, head_hash=bytes(32), signature=b"")
    signed = await keys.sign(unsigned.message())
    claim = dataclasses.replace(
        written, anchor=dataclasses.replace(unsigned, signature=signed.signature)
    )
    report = await verify_anchors(Database(pool), keys, _external(claim))
    assert _statuses(report) == ["head_hash"]


async def test_anchors_survive_a_purge_of_their_own_rows(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """The anchor row and its head are both purged; the SIEM copy still verifies."""
    _, written = await _aged_then_anchored(recorder, keys, migrated_dsn, 3)
    later = [await _record(recorder, n) for n in range(3, 5)]
    age(migrated_dsn, [written.row_id, later[0]], MIN_RETENTION_DAYS + 10)
    result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert result.through_id == later[0]
    assert written.row_id not in {row.id for row in stored(migrated_dsn)}
    report = await verify_anchors(Database(pool), keys, _external(written))
    assert report.ok, report
    assert _statuses(report) == ["checkpointed"]


async def test_anchors_survive_successive_purges(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """A second purge removes the first checkpoint; the later one still covers the anchor."""
    _, written = await _aged_then_anchored(recorder, keys, migrated_dsn, 2)
    first = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert first.checkpoint_id is not None
    more = [await _record(recorder, n) for n in range(2, 4)]
    age(migrated_dsn, [written.row_id, first.checkpoint_id, more[0]], MIN_RETENTION_DAYS + 10)
    second = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    assert first.checkpoint_id not in {row.id for row in stored(migrated_dsn)}
    assert second.through_id == more[0]
    report = await verify_anchors(Database(pool), keys, _external(written))
    assert report.ok, report
    assert _statuses(report) == ["checkpointed"]


async def test_a_prefix_deleted_without_a_checkpoint_is_named(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    _, first, second = await _trail(recorder, keys)
    _sql(migrated_dsn, "DELETE FROM warden.audit_events WHERE id <= %s", (first.row_id,))
    report = await verify_anchors(Database(pool), keys, _external(first, second))
    assert report.chain.broken is not None and report.chain.broken.reason == "unanchored"
    assert _statuses(report) == ["head_missing", "matched"]


async def test_a_forged_checkpoint_does_not_cover_a_deleted_head(
    recorder: AuditRecorder, keys: KeyStore, migrated_dsn: str, pool: Any
) -> None:
    """Only a checkpoint whose signature verifies vouches for purged rows."""
    _, written = await _aged_then_anchored(recorder, keys, migrated_dsn, 3)
    await _record(recorder, 3)
    await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute(
            "UPDATE warden.audit_events SET details = jsonb_set(details,"
            " '{checkpoint,purged_rows}', '1') WHERE action = 'warden.audit.purge'"
        )
        rechain(conn)
    report = await verify_anchors(Database(pool), keys, _external(written))
    assert report.chain.broken is not None
    assert report.chain.broken.reason == "checkpoint_signature"
    assert _statuses(report) == ["head_missing"]


# Anchors read back from what warden actually emits.


async def test_anchors_read_from_an_ndjson_export_and_from_syslog_verify(
    recorder: AuditRecorder, keys: KeyStore, registry: ActionRegistry, pool: Any
) -> None:
    _, first, second = await _trail(recorder, keys)
    db = Database(pool)
    exported = [line async for line in ndjson_lines(iter_events(db, AuditQuery()))]
    settings = SyslogSettings(host="collector.example.com", port=6514, hostname="app.example.com")
    forwarded = [
        format_message(
            AuditRecord(
                id=row.id,
                occurred_at=row.occurred_at,
                action=row.action,
                outcome=row.outcome,
                actor=row.actor,
                details=dict(row.details),
                row_hash=row.row_hash,
            ),
            settings,
            registry,
        ).decode("utf-8")
        async for row in iter_events(db, AuditQuery())
    ]
    found = read_anchors(exported + forwarded)
    assert [(a.row_id, a.anchor) for a in found] == [
        (first.row_id, first.anchor),
        (second.row_id, second.anchor),
    ] * 2
    report = await verify_anchors(db, keys, found)
    assert report.ok, report
    assert _statuses(report) == ["matched"] * 4
