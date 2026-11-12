"""The minimal audit recorder: one insert and its notification, inside one transaction."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import psycopg
import pytest
from psycopg import sql

from warden.audit import (
    ActionRegistry,
    AuditEvent,
    AuditRecorder,
    Severity,
    record_audit,
    set_recorder,
)
from warden.db import AUDIT_CHANNEL, Database

pytestmark = pytest.mark.db


class RecordingSink:
    def __init__(self) -> None:
        self.offered: list[AuditEvent] = []

    def offer(self, event: AuditEvent) -> None:
        self.offered.append(event)


class BrokenSink:
    def offer(self, event: AuditEvent) -> None:
        raise RuntimeError("collector down")


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    return registry


def _event(**kw: Any) -> AuditEvent:
    return AuditEvent(action="product.export", outcome="success", actor="user-1", **kw)


async def _rows(pool: Any) -> list[tuple[Any, ...]]:
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT action, outcome, actor, source_ip::text, details"
            " FROM warden.audit_events ORDER BY id"
        )
        return list(await cur.fetchall())


async def test_record_inserts_a_row(pool: Any, registry: ActionRegistry) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    await recorder.record(_event(source_ip="192.0.2.7", details={"rows": 3}))
    assert await _rows(pool) == [
        ("product.export", "success", "user-1", "192.0.2.7/32", {"rows": 3})
    ]


async def test_record_returns_the_row_id(pool: Any, registry: ActionRegistry) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    first = await recorder.record(_event())
    second = await recorder.record(_event())
    assert second > first


async def test_record_joins_the_callers_transaction_and_rolls_back_with_it(
    pool: Any, registry: ActionRegistry
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    async with pool.connection() as conn:
        with pytest.raises(RuntimeError):
            async with conn.transaction():
                await conn.execute("INSERT INTO warden.settings (key, value) VALUES ('k', '1')")
                await recorder.record(_event(), conn=conn)
                raise RuntimeError("product write failed")
    assert await _rows(pool) == []


async def test_record_commits_with_the_callers_transaction(
    pool: Any, registry: ActionRegistry
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    async with pool.connection() as conn, conn.transaction():
        await recorder.record(_event(), conn=conn)
    assert len(await _rows(pool)) == 1


async def test_unregistered_action_is_refused(pool: Any, registry: ActionRegistry) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    with pytest.raises(KeyError):
        await recorder.record(AuditEvent(action="product.unknown", outcome="success"))
    assert await _rows(pool) == []


@pytest.fixture
async def listener(migrated_dsn: str) -> AsyncIterator[psycopg.AsyncConnection[Any]]:
    conn = await psycopg.AsyncConnection.connect(migrated_dsn, autocommit=True)
    await conn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(AUDIT_CHANNEL)))
    try:
        yield conn
    finally:
        await conn.close()


async def _notifications(
    listener: psycopg.AsyncConnection[Any], timeout: float = 0.5
) -> list[tuple[str, str]]:
    return [(n.channel, n.payload) async for n in listener.notifies(timeout=timeout)]


async def test_a_committed_record_notifies_its_row_id(
    pool: Any, registry: ActionRegistry, listener: psycopg.AsyncConnection[Any]
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    row_id = await recorder.record(_event())
    assert await _notifications(listener) == [(AUDIT_CHANNEL, str(row_id))]


async def test_a_rolled_back_record_sends_no_notification(
    pool: Any, registry: ActionRegistry, listener: psycopg.AsyncConnection[Any]
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    async with pool.connection() as conn:
        with pytest.raises(RuntimeError):
            async with conn.transaction():
                await recorder.record(_event(), conn=conn)
                raise RuntimeError("product write failed")
    committed = await recorder.record(_event())
    # Only the committed row signals; the rolled-back one never does.
    assert await _notifications(listener) == [(AUDIT_CHANNEL, str(committed))]


async def test_the_notification_waits_for_the_callers_commit(
    pool: Any, registry: ActionRegistry, listener: psycopg.AsyncConnection[Any]
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    async with pool.connection() as conn:
        async with conn.transaction():
            row_id = await recorder.record(_event(), conn=conn)
            assert await _notifications(listener, timeout=0.3) == []
        assert await _notifications(listener) == [(AUDIT_CHANNEL, str(row_id))]


class CommitCheckingSink:
    """Records, at offer time, whether the event's row is visible to another session."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self.visible_rows: list[int] = []

    def offer(self, event: AuditEvent) -> None:
        with psycopg.connect(self._dsn) as conn:
            row = conn.execute("SELECT count(*) FROM warden.audit_events").fetchone()
        self.visible_rows.append(row[0] if row else 0)


async def test_sinks_are_offered_only_after_commit(
    pool: Any, registry: ActionRegistry, migrated_dsn: str
) -> None:
    sink = CommitCheckingSink(migrated_dsn)
    recorder = AuditRecorder(Database(pool), registry, sinks=[sink])
    await recorder.record(_event())
    assert sink.visible_rows == [1]


async def test_sinks_are_not_offered_for_a_callers_transaction(
    pool: Any, registry: ActionRegistry
) -> None:
    sink = RecordingSink()
    recorder = AuditRecorder(Database(pool), registry, sinks=[sink])
    async with pool.connection() as conn:
        async with conn.transaction():
            await recorder.record(_event(), conn=conn)
        with pytest.raises(RuntimeError):
            async with conn.transaction():
                await recorder.record(_event(), conn=conn)
                raise RuntimeError("product write failed")
    assert len(await _rows(pool)) == 1
    assert sink.offered == []


async def test_sinks_are_offered_each_recorded_event(pool: Any, registry: ActionRegistry) -> None:
    sink = RecordingSink()
    recorder = AuditRecorder(Database(pool), registry, sinks=[sink])
    event = _event()
    await recorder.record(event)
    assert sink.offered == [event]


async def test_a_failing_sink_never_fails_the_record(pool: Any, registry: ActionRegistry) -> None:
    good = RecordingSink()
    recorder = AuditRecorder(Database(pool), registry, sinks=[BrokenSink(), good])
    await recorder.record(_event())
    assert len(await _rows(pool)) == 1
    assert len(good.offered) == 1


async def test_module_function_uses_the_installed_recorder(
    pool: Any, registry: ActionRegistry
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    previous = set_recorder(recorder)
    try:
        await record_audit(_event())
    finally:
        set_recorder(previous)
    assert len(await _rows(pool)) == 1


async def test_module_function_without_a_recorder_fails() -> None:
    previous = set_recorder(None)
    try:
        with pytest.raises(RuntimeError):
            await record_audit(_event())
    finally:
        set_recorder(previous)
