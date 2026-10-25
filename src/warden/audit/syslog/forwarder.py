"""The syslog forwarder: sends committed audit rows to the collector.

The recorder NOTIFYs ``AUDIT_CHANNEL`` in the same transaction as each insert,
so a signal arrives only once a row has committed. The forwarder listens on
that channel, and on each signal (and on a periodic safety poll) reads rows
with ids above its cursor, in id order, from the table itself. A rolled-back
row never commits, so it is never read and never sent.

One forwarder runs per deployment: the replica holding the session advisory
lock ``SYSLOG_FORWARDER_LOCK_KEY`` forwards, and the others stand by and take
over when the holder's session ends. The cursor is advanced only after a row
is handed to the transport, so delivery is at-least-once; MSGID carries the
row id, so a collector can discard a resent copy.

Ids are assigned at insert, not at commit, and rolled-back inserts leave
permanent gaps. A gap below a committed row may be a transaction still in
flight, so the forwarder holds the cursor at a gap for ``grace_seconds``
before passing it. A lower id that commits inside the grace period is still
sent, in order; one that commits later is not.

The forwarder holds one connection from the product's pool for as long as it
leads (for the lock and the LISTEN) and borrows others briefly to read rows
and store the cursor; a standby borrows one only to try the lock. The leading
connection is closed rather than returned when leadership ends, so it can
never go back to the pool still holding the lock or listening.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal

from psycopg import AsyncConnection, sql
from pydantic import BaseModel, ConfigDict

from warden.audit.registry import ActionRegistry
from warden.audit.syslog.cursor import initialise_cursor, load_cursor, store_cursor
from warden.audit.syslog.formatter import AuditRecord, format_message
from warden.audit.syslog.settings import SyslogSettings
from warden.audit.syslog.transport import Transport, TransportError, open_transport
from warden.db import AUDIT_CHANNEL, AUDIT_EVENTS, SYSLOG_FORWARDER_LOCK_KEY, Database, table

__all__ = ["ForwarderSnapshot", "ForwarderStatus", "SyslogForwarder", "TransportFactory"]

logger = logging.getLogger(__name__)

TransportFactory = Callable[[SyslogSettings], Awaitable[Transport]]
Role = Literal["stopped", "standby", "leader"]

_ROWS = sql.SQL(
    "SELECT id, occurred_at, action, outcome, actor, resource_type, resource_id,"
    " host(source_ip), details, key_id, row_hash FROM {} WHERE id > %s ORDER BY id LIMIT %s"
).format(table(AUDIT_EVENTS))
_MAX_ID = sql.SQL("SELECT coalesce(max(id), 0) FROM {}").format(table(AUDIT_EVENTS))
_LAG = sql.SQL("SELECT count(*) FROM {} WHERE id > %s").format(table(AUDIT_EVENTS))
_TRY_LOCK = sql.SQL("SELECT pg_try_advisory_lock(%s)")
_LISTEN = sql.SQL("LISTEN {}").format(sql.Identifier(AUDIT_CHANNEL))

_STOP_TIMEOUT = 10.0


class ForwarderSnapshot(BaseModel):
    """This process's view of the forwarder, without touching the database."""

    model_config = ConfigDict(frozen=True)

    role: Role
    connected: bool
    sent: int
    gaps_skipped: int
    notifications: int
    last_error: str | None
    last_error_at: datetime | None
    last_sent_at: datetime | None


class ForwarderStatus(ForwarderSnapshot):
    """The snapshot plus the stored cursor and how many rows lie beyond it."""

    cursor: int | None
    lag: int | None
    """Committed rows not yet forwarded; ``None`` before the forwarder has ever run."""


class _LeadershipLost(Exception):
    pass


class SyslogForwarder:
    """Forwards committed audit rows to syslog. Start it at boot; stop it at shutdown."""

    def __init__(
        self,
        db: Database,
        settings: SyslogSettings,
        registry: ActionRegistry | None = None,
        *,
        transport_factory: TransportFactory = open_transport,
    ) -> None:
        self._db = db
        self._settings = settings
        self._registry = registry
        self._factory = transport_factory
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self._wake = asyncio.Event()
        self._transport: Transport | None = None
        self._transport_lock = asyncio.Lock()
        self._cursor = 0
        self._gaps: list[tuple[int, int, float]] = []
        self._backoff = settings.backoff_initial_seconds
        self._role: Role = "stopped"
        self._connected = False
        self._sent = 0
        self._gaps_skipped = 0
        self._notifications = 0
        self._last_error: str | None = None
        self._last_error_at: datetime | None = None
        self._last_sent_at: datetime | None = None

    # --- lifecycle --------------------------------------------------------------

    @property
    def settings(self) -> SyslogSettings:
        return self._settings

    async def start(self) -> None:
        """Begin competing for the forwarder lock and, once held, forwarding."""
        if self._task is not None:
            raise RuntimeError("the syslog forwarder is already started")
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="warden-syslog-forwarder")

    async def stop(self) -> None:
        """Stop forwarding, release the lock and close the transport. Idempotent."""
        task, self._task = self._task, None
        if task is not None:
            self._stopping.set()
            self._wake.set()
            try:
                async with asyncio.timeout(_STOP_TIMEOUT):
                    await asyncio.shield(task)
            except TimeoutError:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        async with self._transport_lock:
            await self._close_transport()
        self._role = "stopped"

    async def __aenter__(self) -> SyslogForwarder:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    async def reconfigure(self, settings: SyslogSettings) -> None:
        """Switch to new settings; the next send opens a transport with them.

        Waits for an in-flight send to finish, so concurrent calls never leave
        a second transport open.
        """
        async with self._transport_lock:
            self._settings = settings
            self._backoff = settings.backoff_initial_seconds
            await self._close_transport()
        self._wake.set()

    # --- status -----------------------------------------------------------------

    def snapshot(self) -> ForwarderSnapshot:
        return ForwarderSnapshot(
            role=self._role,
            connected=self._connected,
            sent=self._sent,
            gaps_skipped=self._gaps_skipped,
            notifications=self._notifications,
            last_error=self._last_error,
            last_error_at=self._last_error_at,
            last_sent_at=self._last_sent_at,
        )

    async def status(self) -> ForwarderStatus:
        """The snapshot plus the stored cursor and the lag behind it.

        Read from the database, so a standby reports the leader's progress.
        """
        async with self._db.transaction() as conn:
            cursor = await load_cursor(conn)
            lag = None
            if cursor is not None:
                row = await (await conn.execute(_LAG, (cursor,))).fetchone()
                lag = int(row[0]) if row else 0
        return ForwarderStatus(**self.snapshot().model_dump(), cursor=cursor, lag=lag)

    def _record_error(self, category: str) -> None:
        self._last_error = category
        self._last_error_at = datetime.now(UTC)

    # --- the main loop ----------------------------------------------------------

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                led = await self._compete()
            except Exception as exc:
                led = False
                self._record_error("database error")
                logger.warning("syslog forwarder database error: %s", type(exc).__name__)
            if self._stopping.is_set():
                break
            if not led:
                await self._pause(self._settings.standby_retry_seconds)
        self._role = "stopped"

    async def _pause(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(seconds):
                await self._stopping.wait()

    async def _compete(self) -> bool:
        """Try for the lock; lead until stopped or the session ends. True if it led."""
        async with self._db.connection() as conn:
            await conn.set_autocommit(True)
            row = await (await conn.execute(_TRY_LOCK, (SYSLOG_FORWARDER_LOCK_KEY,))).fetchone()
            if not (row and row[0]):
                await conn.set_autocommit(False)
                self._role = "standby"
                return False
            try:
                await self._lead(conn)
            finally:
                # Ending the session releases the lock and the LISTEN; the pool
                # discards a closed connection instead of lending it out again.
                self._role = "standby"
                await conn.close()
            return True

    async def _lead(self, conn: AsyncConnection[Any]) -> None:
        self._role = "leader"
        await conn.execute(_LISTEN)
        listener = asyncio.create_task(self._listen(conn), name="warden-syslog-listener")
        listener.add_done_callback(lambda _: self._wake.set())
        try:
            self._cursor = await self._initial_cursor()
            self._gaps.clear()
            while not self._stopping.is_set():
                if listener.done():
                    raise _LeadershipLost
                self._wake.clear()
                try:
                    hint = await self._forward_once(listener)
                except TransportError as exc:
                    await self._back_off(exc, listener)
                    continue
                await self._wait_for_work(hint)
        except _LeadershipLost:
            self._record_error("database error")
            logger.warning("syslog forwarder lost its database session")
        finally:
            listener.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listener

    async def _listen(self, conn: AsyncConnection[Any]) -> None:
        """Read every notification as it arrives, so Postgres' queue never backs up."""
        async for _notify in conn.notifies():
            self._notifications += 1
            self._wake.set()

    async def _initial_cursor(self) -> int:
        async with self._db.transaction() as conn:
            stored = await load_cursor(conn)
            if stored is not None:
                return stored
            start = 0
            if self._settings.start_from == "latest":
                row = await (await conn.execute(_MAX_ID)).fetchone()
                start = int(row[0]) if row else 0
            return await initialise_cursor(conn, start)

    async def _wait_for_work(self, hint: float | None) -> None:
        timeout = (
            self._settings.poll_seconds if hint is None else min(hint, self._settings.poll_seconds)
        )
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(timeout):
                await self._wake.wait()

    async def _back_off(self, exc: TransportError, listener: asyncio.Task[None]) -> None:
        """Wait out a failed send. Notifications keep being read meanwhile."""
        self._record_error(exc.category)
        logger.warning("syslog forwarder send failed: %s", exc.category)
        delay, self._backoff = (
            self._backoff,
            min(self._backoff * 2, self._settings.backoff_max_seconds),
        )
        deadline = time.monotonic() + delay
        while not self._stopping.is_set() and not listener.done():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self._wake.clear()
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(remaining):
                    await self._wake.wait()

    # --- one pass -----------------------------------------------------------------

    async def _forward_once(self, listener: asyncio.Task[None]) -> float | None:
        """Send what can be sent now. Returns how long until a held gap's grace ends."""
        async with self._db.transaction() as conn:
            cur = await conn.execute(_ROWS, (self._cursor, self._settings.batch_size))
            rows = await cur.fetchall()
        sendable, hint = self._plan([int(r[0]) for r in rows])
        start = self._cursor
        try:
            for row in rows[:sendable]:
                if listener.done() or self._stopping.is_set():
                    break
                await self._send(_record(row))
                self._cursor = int(row[0])
        finally:
            if self._cursor != start:
                async with self._db.transaction() as conn:
                    await store_cursor(conn, self._cursor)
        if sendable == len(rows) == self._settings.batch_size:
            self._wake.set()  # a full batch: there may be more behind it
        return hint

    def _plan(self, ids: list[int]) -> tuple[int, float | None]:
        """How many of ``ids`` may be sent now, given the gaps in front of them."""
        now = time.monotonic()
        grace = self._settings.grace_seconds
        expected = self._cursor + 1
        for index, row_id in enumerate(ids):
            if row_id > expected:
                first_seen = self._note_gap(expected, row_id - 1, now)
                age = now - first_seen
                if age < grace:
                    self._prune(expected)
                    return index, grace - age
                self._gaps_skipped += row_id - expected
                logger.info("syslog forwarder passed audit ids %d to %d", expected, row_id - 1)
            expected = row_id + 1
        self._prune(expected)
        return len(ids), None

    def _note_gap(self, start: int, end: int, now: float) -> float:
        """Record the gap ``start..end``; returns when any part of it was first seen."""
        overlapping = [g for g in self._gaps if g[0] <= end and g[1] >= start]
        first_seen = min((g[2] for g in overlapping), default=now)
        self._gaps = [g for g in self._gaps if g not in overlapping]
        self._gaps.append((start, end, first_seen))
        return first_seen

    def _prune(self, expected: int) -> None:
        self._gaps = [g for g in self._gaps if g[1] >= expected]

    async def _send(self, record: AuditRecord) -> None:
        async with self._transport_lock:
            message = format_message(record, self._settings, self._registry)
            if self._transport is None:
                try:
                    self._transport = await self._factory(self._settings)
                except TransportError:
                    self._connected = False
                    raise
            try:
                await self._transport.send(message)
            except TransportError:
                await self._close_transport()
                raise
            self._connected = True
            self._backoff = self._settings.backoff_initial_seconds
            self._sent += 1
            self._last_sent_at = datetime.now(UTC)

    async def _close_transport(self) -> None:
        transport, self._transport = self._transport, None
        self._connected = False
        if transport is not None:
            with contextlib.suppress(Exception):
                await transport.close()


def _record(row: tuple[Any, ...]) -> AuditRecord:
    return AuditRecord(
        id=int(row[0]),
        occurred_at=row[1],
        action=row[2],
        outcome=row[3],
        actor=row[4],
        resource_type=row[5],
        resource_id=row[6],
        source_ip=row[7],
        details=row[8] or {},
        key_id=row[9],
        row_hash=bytes(row[10]) if row[10] is not None else None,
    )
