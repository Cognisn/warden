"""The forwarder: one per deployment, tailing committed audit rows into syslog."""

from __future__ import annotations

import asyncio
import statistics
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import psycopg
import pytest

from syslogfwd.collector import StreamCollector
from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.syslog import (
    SyslogForwarder,
    SyslogSettings,
    Transport,
    TransportError,
    open_transport,
)
from warden.db import SYSLOG_CURSOR_SETTING, SYSLOG_FORWARDER_LOCK_KEY, Database

pytestmark = pytest.mark.db


# --- helpers -------------------------------------------------------------------


class FakeCollector:
    """A transport factory that records messages and can be told to fail."""

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.down = False
        self.opened = 0
        self.closed = 0

    @property
    def ids(self) -> list[int]:
        return [int(m.split(b" ")[5]) for m in self.messages]

    async def factory(self, settings: SyslogSettings) -> Transport:
        if self.down:
            raise TransportError("connection refused")
        self.opened += 1
        return _FakeTransport(self)


class _FakeTransport:
    def __init__(self, collector: FakeCollector) -> None:
        self.collector = collector
        self.open = True

    async def send(self, message: bytes) -> None:
        if self.collector.down or not self.open:
            raise TransportError("connection closed")
        self.collector.messages.append(message)

    async def close(self) -> None:
        if self.open:
            self.open = False
            self.collector.closed += 1


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    return registry


@pytest.fixture
def recorder(pool: Any, registry: ActionRegistry) -> AuditRecorder:
    return AuditRecorder(Database(pool), registry)


def _settings(**kw: Any) -> SyslogSettings:
    values: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 1,
        "transport": "tcp",
        "sd_id": "warden@99999",
        "hostname": "app-1.example.com",
        "grace_seconds": 1.0,
        "poll_seconds": 0.5,
        "standby_retry_seconds": 0.2,
        "backoff_initial_seconds": 0.05,
        "backoff_max_seconds": 0.2,
        "connect_timeout_seconds": 2,
        "send_timeout_seconds": 2,
    }
    values.update(kw)
    return SyslogSettings(**values)


ForwarderFactory = Callable[..., SyslogForwarder]


@pytest.fixture
async def forwarders(pool: Any, registry: ActionRegistry) -> AsyncIterator[ForwarderFactory]:
    started: list[SyslogForwarder] = []

    def make(collector: FakeCollector | None = None, **kw: Any) -> SyslogForwarder:
        factory = collector.factory if collector is not None else open_transport
        forwarder = SyslogForwarder(
            Database(pool), _settings(**kw), registry, transport_factory=factory
        )
        started.append(forwarder)
        return forwarder

    yield make
    for forwarder in started:
        await forwarder.stop()


def _event(actor: str = "user-1") -> AuditEvent:
    return AuditEvent(action="product.export", outcome="success", actor=actor)


async def eventually(
    check: Callable[[], bool | Awaitable[bool]], timeout: float = 10.0, interval: float = 0.05
) -> None:
    deadline = time.monotonic() + timeout
    while True:
        result = check()
        if not isinstance(result, bool):
            result = await result
        if result:
            return
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(interval)


async def _leader(forwarder: SyslogForwarder) -> bool:
    return forwarder.snapshot().role == "leader"


async def _stored_cursor(pool: Any) -> int | None:
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT (value #>> '{}')::bigint FROM warden.settings WHERE key = %s",
            (SYSLOG_CURSOR_SETTING,),
        )
        row = await cur.fetchone()
    return None if row is None else int(row[0])


async def _raw_insert(conn: psycopg.AsyncConnection[Any], *, notify: bool = True) -> int:
    """An audit row written outside the recorder, as a writer without the chain lock would."""
    cur = await conn.execute(
        "INSERT INTO warden.audit_events (action, outcome) VALUES ('product.export', 'success')"
        " RETURNING id"
    )
    row = await cur.fetchone()
    assert row is not None
    if notify:
        await conn.execute("SELECT pg_notify('warden_audit', %s)", (str(row[0]),))
    return int(row[0])


# --- forwarding committed rows ---------------------------------------------------


async def test_a_committed_row_is_forwarded_with_its_id_as_msgid(
    forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    row_id = await recorder.record(_event())
    await eventually(lambda: collector.ids == [row_id])
    assert b'[warden@99999 action="product.export" outcome="success"' in collector.messages[0]


async def test_rows_are_forwarded_in_id_order(
    forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    ids = [await recorder.record(_event(f"user-{n}")) for n in range(30)]
    await eventually(lambda: len(collector.ids) == 30)
    assert collector.ids == ids


async def test_first_start_begins_at_the_newest_row(
    pool: Any, forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    old = [await recorder.record(_event()) for _ in range(3)]
    collector = FakeCollector()
    forwarder = forwarders(collector)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    await eventually(lambda: _stored_cursor_is(pool, old[-1]))
    new = await recorder.record(_event())
    await eventually(lambda: collector.ids == [new])


async def _stored_cursor_is(pool: Any, value: int) -> bool:
    return await _stored_cursor(pool) == value


async def test_start_from_beginning_replays_the_table(
    forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    old = [await recorder.record(_event()) for _ in range(3)]
    collector = FakeCollector()
    forwarder = forwarders(collector, start_from="beginning")
    await forwarder.start()
    await eventually(lambda: collector.ids == old)


async def test_a_stored_cursor_is_resumed(
    pool: Any, forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = FakeCollector()
    first = forwarders(collector)
    await first.start()
    await eventually(lambda: _leader(first))
    a = await recorder.record(_event())
    await eventually(lambda: collector.ids == [a])
    await first.stop()
    b = await recorder.record(_event())  # committed while no forwarder runs
    second = forwarders(collector)
    await second.start()
    await eventually(lambda: collector.ids == [a, b])
    await eventually(lambda: _stored_cursor_is(pool, b))


async def test_a_rolled_back_audit_write_is_never_forwarded(
    pool: Any, forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector, grace_seconds=0.3)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    async with pool.connection() as conn:
        with pytest.raises(RuntimeError):
            async with conn.transaction():
                await recorder.record(_event("ghost"), conn=conn)
                raise RuntimeError("product write failed")
    kept = await recorder.record(_event("real"))
    await eventually(lambda: collector.ids == [kept])
    await asyncio.sleep(1.0)  # well past the grace period: the ghost never appears
    assert collector.ids == [kept]
    assert all(b"ghost" not in m for m in collector.messages)


async def test_a_late_committing_lower_id_inside_the_grace_period_is_sent(
    pool: Any, forwarders: ForwarderFactory, migrated_dsn: str
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector, grace_seconds=5.0)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    async with (
        await psycopg.AsyncConnection.connect(migrated_dsn) as slow,
        await psycopg.AsyncConnection.connect(migrated_dsn, autocommit=True) as fast,
    ):
        low = await _raw_insert(slow)  # takes the lower id and does not commit yet
        high = await _raw_insert(fast)  # commits first
        assert high > low
        await asyncio.sleep(1.0)
        assert collector.ids == []  # held back: the lower id may still commit
        await slow.commit()
    await eventually(lambda: collector.ids == [low, high])


async def test_a_gap_is_passed_once_the_grace_period_ends(
    pool: Any, forwarders: ForwarderFactory, migrated_dsn: str
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector, grace_seconds=0.5)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    async with (
        await psycopg.AsyncConnection.connect(migrated_dsn) as stuck,
        await psycopg.AsyncConnection.connect(migrated_dsn, autocommit=True) as fast,
    ):
        await _raw_insert(stuck)  # never commits within the test
        started = time.monotonic()
        high = await _raw_insert(fast)
        await eventually(lambda: collector.ids == [high], timeout=5)
        assert time.monotonic() - started >= 0.5
        await stuck.rollback()
    assert forwarder.snapshot().gaps_skipped == 1


async def test_the_safety_poll_finds_a_row_without_a_notification(
    forwarders: ForwarderFactory, migrated_dsn: str
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector, poll_seconds=0.3)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    async with await psycopg.AsyncConnection.connect(migrated_dsn, autocommit=True) as conn:
        row_id = await _raw_insert(conn, notify=False)
    await eventually(lambda: collector.ids == [row_id], timeout=5)


# --- the collector going away ----------------------------------------------------


async def test_the_cursor_advances_only_after_a_row_is_handed_over(
    pool: Any, forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    await eventually(lambda: _stored_cursor_is(pool, 0))
    collector.down = True
    ids = [await recorder.record(_event()) for _ in range(5)]
    await asyncio.sleep(1.0)
    assert await _stored_cursor(pool) == 0
    status = await forwarder.status()
    assert status.lag == 5
    assert status.last_error == "connection refused"
    assert status.connected is False
    collector.down = False
    await eventually(lambda: collector.ids == ids)
    await eventually(lambda: _stored_cursor_is(pool, ids[-1]))
    status = await forwarder.status()
    assert (status.cursor, status.lag, status.connected) == (ids[-1], 0, True)


async def test_rows_committed_while_the_collector_is_stopped_are_delivered_after_it_returns(
    pool: Any, forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = StreamCollector()
    port = await collector.start()
    forwarder = forwarders(port=port)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    before = await recorder.record(_event())
    await collector.wait_for_frames(1)

    # Baseline request latency, collector up.
    baseline = []
    for _ in range(20):
        started = time.perf_counter()
        await recorder.record(_event())
        baseline.append(time.perf_counter() - started)
    await collector.wait_for_frames(21)

    await collector.stop()
    await asyncio.sleep(0.3)
    during = []
    down_ids = []
    for _ in range(20):
        started = time.perf_counter()
        down_ids.append(await recorder.record(_event()))
        during.append(time.perf_counter() - started)
    await asyncio.sleep(0.5)
    assert (await forwarder.status()).lag >= 20

    await collector.start(port)
    frames = await collector.wait_for_frames(41, timeout=20)
    msgids = [int(f.split(b" ")[5]) for f in frames]
    assert msgids[0] == before
    assert msgids[-20:] == down_ids
    assert len(msgids) == len(set(msgids)) == 41
    # Recording never waits on the collector: latency with it stopped stays at baseline.
    assert statistics.median(during) < statistics.median(baseline) * 3 + 0.02


async def test_notifications_are_drained_while_the_collector_is_down(
    forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector, backoff_initial_seconds=5, backoff_max_seconds=5)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    collector.down = True
    before = forwarder.snapshot().notifications
    for _ in range(50):
        await recorder.record(_event())
    # The forwarder is backing off, yet it keeps reading notifications, so
    # Postgres' notification queue cannot grow behind it.
    await eventually(lambda: forwarder.snapshot().notifications >= before + 50)
    assert collector.messages == []


# --- one forwarder per deployment -----------------------------------------------


async def test_two_forwarders_send_no_duplicates(
    forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    first, second = FakeCollector(), FakeCollector()
    a, b = forwarders(first), forwarders(second)
    await asyncio.gather(a.start(), b.start())
    await eventually(lambda: {a.snapshot().role, b.snapshot().role} == {"leader", "standby"})
    ids = await asyncio.gather(*(recorder.record(_event(f"u{n}")) for n in range(40)))
    await eventually(lambda: len(first.ids) + len(second.ids) >= 40)
    await asyncio.sleep(0.5)
    combined = first.ids + second.ids
    assert sorted(combined) == sorted(ids)
    assert len(combined) == len(set(combined))
    assert not (first.ids and second.ids)


async def test_a_standby_takes_over_when_the_leader_stops(
    forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    first, second = FakeCollector(), FakeCollector()
    a = forwarders(first)
    await a.start()
    await eventually(lambda: _leader(a))
    b = forwarders(second)
    await b.start()
    await eventually(lambda: b.snapshot().role == "standby")
    x = await recorder.record(_event())
    await eventually(lambda: first.ids == [x])
    await a.stop()
    await eventually(lambda: _leader(b))
    y = await recorder.record(_event())
    await eventually(lambda: second.ids == [y])
    assert first.ids == [x]


async def test_the_forwarder_recovers_when_its_session_is_killed(
    pool: Any, forwarders: ForwarderFactory, recorder: AuditRecorder, migrated_dsn: str
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    async with await psycopg.AsyncConnection.connect(migrated_dsn, autocommit=True) as admin:
        await admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_locks"
            " WHERE locktype = 'advisory' AND granted"
            " AND ((classid::bigint << 32) | objid::bigint) = %s",
            (SYSLOG_FORWARDER_LOCK_KEY,),
        )
    row_id = await recorder.record(_event())
    await eventually(lambda: collector.ids == [row_id], timeout=15)
    assert forwarder.snapshot().role == "leader"


async def _advisory_locks(dsn: str) -> int:
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted"
        )
        row = await cur.fetchone()
    return int(row[0]) if row else 0


async def test_stop_releases_the_lock_and_closes_the_transport(
    forwarders: ForwarderFactory, recorder: AuditRecorder, migrated_dsn: str
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    await recorder.record(_event())
    await eventually(lambda: len(collector.ids) == 1)
    assert await _advisory_locks(migrated_dsn) == 1
    await forwarder.stop()
    await forwarder.stop()  # idempotent
    assert await _advisory_locks(migrated_dsn) == 0
    assert collector.opened == collector.closed == 1
    assert forwarder.snapshot().role == "stopped"


async def test_starting_twice_is_refused(forwarders: ForwarderFactory) -> None:
    forwarder = forwarders(FakeCollector())
    await forwarder.start()
    with pytest.raises(RuntimeError):
        await forwarder.start()


async def test_concurrent_reconfiguration_leaves_one_transport(
    forwarders: ForwarderFactory, recorder: AuditRecorder
) -> None:
    collector = FakeCollector()
    forwarder = forwarders(collector)
    await forwarder.start()
    await eventually(lambda: _leader(forwarder))
    await recorder.record(_event())
    await eventually(lambda: len(collector.ids) == 1)
    await asyncio.gather(*(forwarder.reconfigure(_settings(app_name=f"app{n}")) for n in range(5)))
    await recorder.record(_event())
    await eventually(lambda: len(collector.ids) == 2)
    assert collector.opened - collector.closed == 1
    assert forwarder.settings.app_name.startswith("app")
    await forwarder.stop()
    assert collector.opened == collector.closed


async def test_status_before_start(forwarders: ForwarderFactory) -> None:
    status = await forwarders(FakeCollector()).status()
    assert status.role == "stopped"
    assert status.cursor is None
    assert status.lag is None


async def test_the_stored_cursor_never_moves_backwards(pool: Any) -> None:
    from warden.audit.syslog.cursor import initialise_cursor, load_cursor, store_cursor

    async with pool.connection() as conn:
        assert await load_cursor(conn) is None
        assert await initialise_cursor(conn, 7) == 7
        assert await initialise_cursor(conn, 3) == 7  # an existing cursor wins
        await store_cursor(conn, 10)
        await store_cursor(conn, 5)  # a deposed leader's late write
        assert await load_cursor(conn) == 10
