"""The chained recorder: links, server-side order, the details cap, and concurrency.

The ordering contract the syslog forwarder relies on: the chain lock is taken
before a row's id is drawn and held until its transaction ends, so row id
order equals commit order.
"""

from __future__ import annotations

import asyncio
import itertools
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from psycopg import sql

from warden.audit import (
    ActionRegistry,
    AuditChainConflict,
    AuditEvent,
    AuditRecorder,
    Severity,
)
from warden.audit.chain import CHAIN_LOCK_KEY, GENESIS_HASH, TRUNCATION_MARKER, row_hash
from warden.audit.store import ROW_COLUMNS, AuditRow, row_from_record
from warden.db import Database

pytestmark = pytest.mark.db


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    return registry


def _event(**kw: Any) -> AuditEvent:
    return AuditEvent(**{"action": "product.export", "outcome": "success", "actor": "user-1", **kw})


async def _stored(pool: Any) -> list[AuditRow]:
    async with pool.connection() as conn:
        cur = await conn.execute(
            sql.SQL("SELECT {} FROM warden.audit_events ORDER BY id").format(ROW_COLUMNS)
        )
        return [row_from_record(r) for r in await cur.fetchall()]


def _assert_one_unforked_chain(rows: list[AuditRow]) -> None:
    assert rows, "no rows recorded"
    assert rows[0].prev_hash == GENESIS_HASH
    for before, after in itertools.pairwise(rows):
        assert after.prev_hash == before.row_hash, f"link broken at row {after.id}"
    for row in rows:
        assert row.row_hash == row_hash(row), f"hash wrong at row {row.id}"


async def test_rows_are_chained_from_genesis(pool: Any, registry: ActionRegistry) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    for n in range(3):
        await recorder.record(_event(details={"n": n}, source_ip="2001:db8::5"))
    rows = await _stored(pool)
    assert len(rows) == 3
    _assert_one_unforked_chain(rows)


async def test_stored_hash_covers_awkward_details(pool: Any, registry: ActionRegistry) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    details: dict[str, Any] = {
        "big": 1e20,
        "tiny": 1.5e-7,
        "negzero": -0.0,
        "one": 1.0,
        "huge": 10**30,
        "text": 'Zoë \u2028 \\ "quoted"',
        "nested": {"b": [1, {"z": None, "a": True}], "a": []},
    }
    await recorder.record(_event(details=details))
    _assert_one_unforked_chain(await _stored(pool))


async def test_recorded_at_is_server_time_and_order_follows_id(
    pool: Any, registry: ActionRegistry
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    backdated = datetime(2020, 1, 1, tzinfo=UTC)
    first = await recorder.record(_event())
    second = await recorder.record(_event(occurred_at=backdated))
    rows = await _stored(pool)
    assert [r.id for r in rows] == [first, second]
    assert rows[1].occurred_at == backdated
    assert rows[1].recorded_at >= rows[0].recorded_at
    assert abs(datetime.now(UTC) - rows[1].recorded_at) < timedelta(minutes=5)
    _assert_one_unforked_chain(rows)


async def test_recorded_at_defaults_to_clock_timestamp(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        row = conn.execute(
            "SELECT column_default FROM information_schema.columns"
            " WHERE table_schema = 'warden' AND table_name = 'audit_events'"
            " AND column_name = 'recorded_at'"
        ).fetchone()
    assert row is not None and row[0] == "clock_timestamp()"


def _raw_insert(dsn: str, *, outcome: str = "success", prev_hash: bytes = b"\x09" * 32) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "INSERT INTO warden.audit_events (action, outcome, prev_hash, row_hash)"
            " VALUES ('product.export', %s, %s, %s)",
            (outcome, prev_hash, b"\x07" * 32),
        )


def test_outcome_is_constrained_to_success_or_failure(migrated_dsn: str) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        _raw_insert(migrated_dsn, outcome="maybe")
    _raw_insert(migrated_dsn, outcome="failure")


def test_chain_hashes_are_required_and_32_bytes(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn, pytest.raises(psycopg.errors.NotNullViolation):
        conn.execute(
            "INSERT INTO warden.audit_events (action, outcome, row_hash)"
            " VALUES ('product.export', 'success', %s)",
            (b"\x07" * 32,),
        )
    with pytest.raises(psycopg.errors.CheckViolation):
        _raw_insert(migrated_dsn, prev_hash=b"\x01" * 31)


def test_two_rows_can_never_claim_the_same_predecessor(migrated_dsn: str) -> None:
    _raw_insert(migrated_dsn)
    with pytest.raises(psycopg.errors.UniqueViolation):
        _raw_insert(migrated_dsn)


async def test_oversized_details_are_stored_as_the_marker(
    pool: Any, registry: ActionRegistry
) -> None:
    sink_events: list[AuditEvent] = []

    class Sink:
        def offer(self, event: AuditEvent) -> None:
            sink_events.append(event)

    recorder = AuditRecorder(Database(pool), registry, sinks=[Sink()], details_max_bytes=256)
    await recorder.record(_event(details={"note": "x" * 1000}))
    (row,) = await _stored(pool)
    assert set(row.details) == {TRUNCATION_MARKER}
    assert row.details[TRUNCATION_MARKER]["original_bytes"] > 1000
    # Sinks see what was stored, never the oversized original.
    assert sink_events[0].details == row.details
    _assert_one_unforked_chain([row])


async def test_the_default_cap_is_the_configured_default(
    pool: Any, registry: ActionRegistry
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    await recorder.record(_event(details={"note": "x" * 8000}))
    await recorder.record(_event(details={"note": "x" * 9000}))
    first, second = await _stored(pool)
    assert first.details == {"note": "x" * 8000}
    assert set(second.details) == {TRUNCATION_MARKER}


async def test_invalid_details_are_refused_before_anything_is_written(
    pool: Any, registry: ActionRegistry
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    with pytest.raises(ValueError, match="NUL"):
        await recorder.record(_event(details={"x": "a\x00b"}))
    assert await _stored(pool) == []


async def test_concurrent_writers_produce_one_unforked_chain(
    pool: Any, migrated_dsn: str, registry: ActionRegistry
) -> None:
    from psycopg_pool import AsyncConnectionPool

    writers = 12
    big: Any = AsyncConnectionPool(migrated_dsn, min_size=writers, max_size=writers, open=False)
    await big.open(wait=True)
    try:
        recorder = AuditRecorder(Database(big), registry)
        barrier = asyncio.Barrier(writers)

        async def write(n: int) -> int:
            async with big.connection() as conn:
                await conn.execute("SELECT 1")
                await barrier.wait()
                async with conn.transaction():
                    return await recorder.record(_event(details={"n": n}), conn=conn)

        ids = await asyncio.gather(*(write(n) for n in range(writers)))
    finally:
        await big.close()
    rows = await _stored(pool)
    assert sorted(ids) == [r.id for r in rows]
    _assert_one_unforked_chain(rows)


async def _wait_until_blocked_on_chain_lock(dsn: str, pid: int) -> None:
    """Poll until backend ``pid`` waits on the chain's advisory lock."""
    lock_key = CHAIN_LOCK_KEY
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as watcher:
        for _ in range(200):
            cur = await watcher.execute(
                "SELECT count(*) FROM pg_locks WHERE pid = %s AND locktype = 'advisory'"
                " AND NOT granted AND ((classid::bigint << 32) | objid::bigint) = %s",
                (pid, lock_key),
            )
            row = await cur.fetchone()
            if row and row[0]:
                return
            await asyncio.sleep(0.02)
    raise AssertionError("the second writer never waited on the chain lock")


async def test_a_later_writer_never_commits_before_an_earlier_one(
    migrated_dsn: str, pool: Any, registry: ActionRegistry
) -> None:
    """Row id order is commit order: the second inserter waits for the first's commit."""
    recorder = AuditRecorder(Database(pool), registry)
    commit_order: list[str] = []

    a_conn = await psycopg.AsyncConnection.connect(migrated_dsn)
    b_conn = await psycopg.AsyncConnection.connect(migrated_dsn)
    b_task: asyncio.Task[int] | None = None
    try:

        async def second_writer() -> int:
            async with b_conn.transaction():
                row_id = await recorder.record(_event(actor="b"), conn=b_conn)
            commit_order.append("b")
            return row_id

        async with a_conn.transaction():
            first_id = await recorder.record(_event(actor="a"), conn=a_conn)
            b_task = asyncio.create_task(second_writer())
            await _wait_until_blocked_on_chain_lock(migrated_dsn, b_conn.info.backend_pid)
            # B is parked on the lock: it has not committed, and has not drawn an id.
            assert not b_task.done()
            async with pool.connection() as probe:
                cur = await probe.execute(
                    "SELECT pg_sequence_last_value("
                    "pg_get_serial_sequence('warden.audit_events', 'id')::regclass)"
                )
                (last_value,) = await cur.fetchone() or (None,)
            assert last_value == first_id
            await asyncio.sleep(0.2)
            assert not b_task.done()
            commit_order.append("a")
        # A's transaction has now committed and released the lock.
        second_id = await asyncio.wait_for(b_task, timeout=10)
    finally:
        if b_task is not None and not b_task.done():
            b_task.cancel()
        await a_conn.close()
        await b_conn.close()
    assert commit_order == ["a", "b"]
    assert second_id > first_id
    _assert_one_unforked_chain(await _stored(pool))


async def test_a_stale_repeatable_read_snapshot_fails_closed_rather_than_forking(
    migrated_dsn: str, pool: Any, registry: ActionRegistry
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    await recorder.record(_event(actor="genesis"))
    async with await psycopg.AsyncConnection.connect(migrated_dsn) as conn:
        await conn.set_isolation_level(psycopg.IsolationLevel.REPEATABLE_READ)
        async with conn.transaction():
            await conn.execute("SELECT count(*) FROM warden.audit_events")  # takes the snapshot
            await recorder.record(_event(actor="concurrent"))  # commits after the snapshot
            with pytest.raises(AuditChainConflict):
                await recorder.record(_event(actor="stale"), conn=conn)
    rows = await _stored(pool)
    assert [r.actor for r in rows] == ["genesis", "concurrent"]
    _assert_one_unforked_chain(rows)


async def test_warden_owned_writes_read_the_committed_head_whatever_the_default_isolation(
    migrated_dsn: str, pool: Any, registry: ActionRegistry
) -> None:
    """A server default of REPEATABLE READ must not make warden's own writes conflict."""
    from psycopg_pool import AsyncConnectionPool

    rr: Any = AsyncConnectionPool(
        migrated_dsn,
        min_size=1,
        max_size=2,
        open=False,
        kwargs={"options": "-c default_transaction_isolation=repeatable\\ read"},
    )
    await rr.open(wait=True)
    try:
        rr_recorder = AuditRecorder(Database(rr), registry)
        holder = AuditRecorder(Database(pool), registry)
        async with await psycopg.AsyncConnection.connect(migrated_dsn) as a_conn:
            async with a_conn.transaction():
                await holder.record(_event(actor="a"), conn=a_conn)
                b_task = asyncio.create_task(rr_recorder.record(_event(actor="b")))
                await asyncio.sleep(0.3)
                assert not b_task.done()
            await asyncio.wait_for(b_task, timeout=10)
    finally:
        await rr.close()
    rows = await _stored(pool)
    assert [r.actor for r in rows] == ["a", "b"]
    _assert_one_unforked_chain(rows)
