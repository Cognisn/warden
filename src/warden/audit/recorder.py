"""The audit recorder: the only code that writes to ``warden.audit_events``.

A tripwire test fails if any other module inserts into the audit table.

Every row is hash-chained to the one before it (see ``warden.audit.chain``).
Appending takes the chain lock, a transaction-scoped advisory lock, *before*
the row's id is drawn, and holds it until the transaction ends. So:

- the chain never forks: each writer reads the committed head under the lock;
- row id order is commit order: a later id cannot commit before an earlier
  one, which the syslog forwarder relies on when it reads rows by id.

The cost is that audit writes are serialised. A record made inside a
caller's transaction holds the lock until **the caller** commits or rolls
back, so every other audit write waits behind it: keep such transactions
short. warden's own writes hold the lock for a few statements only.

Each insert issues ``pg_notify`` on ``AUDIT_CHANNEL`` in the same
transaction. Postgres delivers a notification only when its transaction
commits, so the syslog forwarder, which listens on the channel and reads
committed rows, never sees an event whose transaction rolled back.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

import psycopg
from psycopg import AsyncConnection, sql
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from warden.audit.actions import ANCHOR_ACTION, PURGE_ACTION
from warden.audit.chain import CHAIN_LOCK_KEY, GENESIS_HASH, ChainRow, cap_details, row_hash
from warden.audit.events import AuditEvent
from warden.audit.registry import ActionRegistry
from warden.audit.sink import AuditSink
from warden.config import AuditConfig
from warden.db import AUDIT_CHANNEL, AUDIT_EVENTS, SCHEMA, Database, table

__all__ = [
    "AuditChainConflict",
    "AuditRecorder",
    "get_recorder",
    "record_audit",
    "set_recorder",
]

logger = logging.getLogger(__name__)

_AUDIT = table(AUDIT_EVENTS)
_NEVER_TRUNCATED = frozenset({PURGE_ACTION, ANCHOR_ACTION})
PREV_HASH_INDEX = "audit_events_prev_hash_unique"

_READ_COMMITTED = sql.SQL("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
_LOCK = sql.SQL("SELECT pg_advisory_xact_lock(%s)")
# A separate statement from the lock, so under READ COMMITTED its snapshot is
# taken after the lock is granted and sees the previous writer's commit.
_NEXT = sql.SQL(
    "SELECT nextval(pg_get_serial_sequence({}, 'id')), clock_timestamp(),"
    " (SELECT row_hash FROM {} ORDER BY id DESC LIMIT 1)"
).format(sql.Literal(f"{SCHEMA}.{AUDIT_EVENTS}"), _AUDIT)
_INSERT = sql.SQL(
    "INSERT INTO {} (id, recorded_at, occurred_at, actor, action, resource_type, resource_id,"
    " outcome, source_ip, details, prev_hash, row_hash) OVERRIDING SYSTEM VALUE"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
).format(_AUDIT)

_NOTIFY = sql.SQL("SELECT pg_notify(%s, %s)")


class AuditChainConflict(Exception):
    """The row would have forked the chain, so nothing was written.

    Raised when the transaction's snapshot predates the chain head, which
    happens only in a REPEATABLE READ or SERIALIZABLE transaction that took
    its snapshot before another audit write committed. Retry the transaction.
    """


class AuditRecorder:
    """Records events to the audit table and offers them to sinks."""

    def __init__(
        self,
        db: Database,
        registry: ActionRegistry,
        sinks: Iterable[AuditSink] = (),
        *,
        details_max_bytes: int = AuditConfig().details_max_bytes,
    ) -> None:
        self._db = db
        self._registry = registry
        self._sinks = tuple(sinks)
        self._details_max_bytes = details_max_bytes

    @property
    def registry(self) -> ActionRegistry:
        return self._registry

    @property
    def db(self) -> Database:
        return self._db

    async def record(self, event: AuditEvent, *, conn: AsyncConnection[Any] | None = None) -> int:
        """Record ``event`` and return its row id.

        With ``conn``, the row is written inside the caller's transaction and
        commits or rolls back with it; the chain lock is then held until the
        caller's transaction ends. The action must be registered. Details
        larger than ``details_max_bytes`` are replaced by the truncation
        marker (``warden.audit.chain.cap_details``), except a retention
        checkpoint's or an anchor's, which are never truncated.

        Sinks are offered the event only when warden owns the transaction
        (no ``conn``), and only after it commits. warden cannot see when a
        caller's transaction commits, so a caller-owned record is never
        offered; the syslog forwarder picks it up from the table instead.
        """
        self._registry.get(event.action)
        if event.action in _NEVER_TRUNCATED:
            # A truncated checkpoint or anchor could not vouch for the chain;
            # warden writes both itself.
            details = dict(event.details)
        else:
            details = cap_details(event.details, max_bytes=self._details_max_bytes)
        if details != event.details:
            event = event.model_copy(update={"details": details})
        begins = conn is None or conn.info.transaction_status == TransactionStatus.IDLE
        try:
            async with self._db.transaction(conn) as tx:
                row_id = await self._append(tx, event, details, begins=begins)
        except psycopg.errors.UniqueViolation as exc:
            if exc.diag.constraint_name != PREV_HASH_INDEX:
                raise
            raise AuditChainConflict(
                "the audit chain head moved after this transaction's snapshot; retry it"
            ) from None
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

    async def _append(
        self,
        tx: AsyncConnection[Any],
        event: AuditEvent,
        details: dict[str, Any],
        *,
        begins: bool,
    ) -> int:
        if begins:
            # A transaction warden begins reads the committed head whatever
            # the server's default isolation.
            await tx.execute(_READ_COMMITTED)
        await tx.execute(_LOCK, (CHAIN_LOCK_KEY,))
        cur = await tx.execute(_NEXT)
        head = await cur.fetchone()
        if head is None:
            raise RuntimeError("audit chain head query returned no row")
        row_id, recorded_at = int(head[0]), head[1]
        prev_hash = GENESIS_HASH if head[2] is None else bytes(head[2])
        chained = ChainRow(
            id=row_id,
            prev_hash=prev_hash,
            recorded_at=recorded_at,
            occurred_at=event.occurred_at,
            actor=event.actor,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            outcome=event.outcome,
            source_ip=event.source_ip,
            details=details,
            key_id=None,
        )
        await tx.execute(
            _INSERT,
            (
                row_id,
                recorded_at,
                event.occurred_at,
                event.actor,
                event.action,
                event.resource_type,
                event.resource_id,
                event.outcome,
                event.source_ip,
                Jsonb(details),
                prev_hash,
                row_hash(chained),
            ),
        )
        await tx.execute(_NOTIFY, (AUDIT_CHANNEL, str(row_id)))
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
