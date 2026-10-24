"""The audit recorder: the only code that writes to ``warden.audit_events``.

A tripwire test fails if any other module inserts into the audit table.
Foundation ships a plain insert; the audit core arc adds hash chaining
behind the same ``record`` and ``record_audit`` signatures.

Each insert issues ``pg_notify`` on ``AUDIT_CHANNEL`` in the same
transaction. Postgres delivers a notification only when its transaction
commits, so the syslog forwarder, which listens on the channel and reads
committed rows, never sees an event whose transaction rolled back.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from psycopg import AsyncConnection, sql
from psycopg.types.json import Jsonb

from warden.audit.events import AuditEvent
from warden.audit.registry import ActionRegistry
from warden.audit.sink import AuditSink
from warden.db import AUDIT_CHANNEL, AUDIT_EVENTS, Database, table

__all__ = ["AuditRecorder", "get_recorder", "record_audit", "set_recorder"]

logger = logging.getLogger(__name__)

_INSERT = sql.SQL(
    "INSERT INTO {} (occurred_at, actor, action, resource_type, resource_id,"
    " outcome, source_ip, details) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
).format(table(AUDIT_EVENTS))

_NOTIFY = sql.SQL("SELECT pg_notify(%s, %s)")


class AuditRecorder:
    """Records events to the audit table and offers them to sinks."""

    def __init__(
        self, db: Database, registry: ActionRegistry, sinks: Iterable[AuditSink] = ()
    ) -> None:
        self._db = db
        self._registry = registry
        self._sinks = tuple(sinks)

    @property
    def registry(self) -> ActionRegistry:
        return self._registry

    async def record(self, event: AuditEvent, *, conn: AsyncConnection[Any] | None = None) -> int:
        """Record ``event`` and return its row id.

        With ``conn``, the row is written inside the caller's transaction and
        commits or rolls back with it. The action must be registered.

        Sinks are offered the event only when warden owns the transaction
        (no ``conn``), and only after it commits. warden cannot see when a
        caller's transaction commits, so a caller-owned record is never
        offered; the syslog forwarder picks it up from the table instead.
        """
        self._registry.get(event.action)
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                _INSERT,
                (
                    event.occurred_at,
                    event.actor,
                    event.action,
                    event.resource_type,
                    event.resource_id,
                    event.outcome,
                    event.source_ip,
                    Jsonb(event.details),
                ),
            )
            row = await cur.fetchone()
            if row is None:
                raise RuntimeError("audit insert returned no row")
            row_id = int(row[0])
            await tx.execute(_NOTIFY, (AUDIT_CHANNEL, str(row_id)))
        if conn is not None:
            return row_id
        for sink in self._sinks:
            try:
                sink.offer(event)
            except Exception:
                logger.exception(
                    "audit sink %s raised on offer for action %s", type(sink).__name__, event.action
                )
        return row_id


_recorder: AuditRecorder | None = None


def set_recorder(recorder: AuditRecorder | None) -> AuditRecorder | None:
    """Install the process-wide recorder ``record_audit`` uses; returns the previous one."""
    global _recorder
    previous, _recorder = _recorder, recorder
    return previous


def get_recorder() -> AuditRecorder:
    if _recorder is None:
        raise RuntimeError("no audit recorder is installed; call warden.audit.set_recorder")
    return _recorder


async def record_audit(event: AuditEvent, *, conn: AsyncConnection[Any] | None = None) -> int:
    """Record ``event`` through the installed recorder. See ``AuditRecorder.record``."""
    return await get_recorder().record(event, conn=conn)
