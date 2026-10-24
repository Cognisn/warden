"""The minimal audit recorder: one insert, inside the caller's transaction."""

from __future__ import annotations

from typing import Any

import pytest

from warden.audit import (
    ActionRegistry,
    AuditEvent,
    AuditRecorder,
    Severity,
    record_audit,
    set_recorder,
)
from warden.db import Database

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
