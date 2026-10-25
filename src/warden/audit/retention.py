"""Retention: purge an old prefix of the chain behind a signed checkpoint.

A purge is the one place warden deletes audit rows. It runs as follows:

1. Find the oldest prefix of the chain, by id, in which every row's
   ``recorded_at`` is older than the cutoff. A row younger than the cutoff is
   never deleted, even if an older row follows it after a clock step.
2. Verify that prefix. A broken prefix is refused, and the refusal audited,
   so a purge can never launder tampering by deleting the evidence.
3. In one transaction, append a checkpoint row (``PURGE_ACTION``, outcome
   ``success``) carrying the last purged row's hash, signed with warden's
   Ed25519 key, then delete the prefix. Appending takes the chain lock, so
   the delete runs under it and a second purge racing this one finds its
   prefix gone and is refused. The checkpoint is the purge's own audit record.

The database role that runs a purge needs ``DELETE`` on the audit table,
which the application's role never holds; see ``warden.audit.grants``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Protocol

from psycopg import AsyncConnection, sql

from warden.audit.actions import PURGE_ACTION, register_audit_actions
from warden.audit.checkpoint import Checkpoint, HistoricalVerifier
from warden.audit.events import AuditEvent
from warden.audit.recorder import AuditRecorder
from warden.audit.verify import verify_chain
from warden.db import AUDIT_EVENTS, table

__all__ = ["MIN_RETENTION_DAYS", "CheckpointSigner", "PurgeResult", "RetentionError", "purge"]

# Provisional, pending a decision (design open item 3): no configuration may
# keep audit rows for less than a year.
MIN_RETENTION_DAYS = 365

_AUDIT = table(AUDIT_EVENTS)

_PREFIX = sql.SQL(
    "WITH cutoff AS (SELECT clock_timestamp() - make_interval(days => %s) AS at)"
    " SELECT cutoff.at, (SELECT max(id) FROM {audit} WHERE id < coalesce("
    "(SELECT min(id) FROM {audit} WHERE recorded_at >= cutoff.at), 9223372036854775807))"
    " FROM cutoff"
).format(audit=_AUDIT)
_SEGMENT = sql.SQL(
    "SELECT (SELECT row_hash FROM {audit} WHERE id = %s), min(id), count(*)"
    " FROM {audit} WHERE id <= %s"
).format(audit=_AUDIT)
_DELETE = sql.SQL("DELETE FROM {} WHERE id <= %s").format(_AUDIT)


class RetentionError(Exception):
    """A purge was refused. The message carries row ids only."""


class _SignatureLike(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def signature(self) -> bytes: ...


class _KeyLike(Protocol):
    @property
    def key_id(self) -> str: ...


class CheckpointSigner(HistoricalVerifier, Protocol):
    """What a purge needs from the key store: ``KeyStore`` fits."""

    async def active_key(self) -> _KeyLike: ...

    async def sign(self, message: bytes) -> _SignatureLike: ...


@dataclass(frozen=True, slots=True)
class PurgeResult:
    purged_rows: int
    through_id: int | None
    checkpoint_id: int | None


async def purge(
    recorder: AuditRecorder,
    keys: CheckpointSigner,
    *,
    retention_days: int,
    actor: str | None = None,
) -> PurgeResult:
    """Delete audit rows older than ``retention_days`` behind a signed checkpoint."""
    if retention_days < MIN_RETENTION_DAYS:
        raise RetentionError(
            f"retention of {retention_days} days is below the minimum of {MIN_RETENTION_DAYS}"
        )
    register_audit_actions(recorder.registry)
    db = recorder.db

    async with db.connection() as conn:
        cur = await conn.execute(_PREFIX, (retention_days,))
        found = await cur.fetchone()
    if found is None or found[1] is None:
        return PurgeResult(purged_rows=0, through_id=None, checkpoint_id=None)
    cutoff: datetime = found[0]
    through_id = int(found[1])

    report = await verify_chain(db, keys, through_id=through_id)
    if report.broken is not None:
        await recorder.record(
            AuditEvent(
                action=PURGE_ACTION,
                outcome="failure",
                actor=actor,
                details={"reason": "chain_broken", "row_id": report.broken.row_id},
            )
        )
        raise RetentionError(
            f"refusing to purge: the audit chain is broken at row {report.broken.row_id}"
        )

    async with db.transaction() as tx:
        checkpoint_id, purged = await _purge_prefix(
            tx,
            recorder,
            keys,
            through_id=through_id,
            verified_hash=report.head_hash,
            cutoff=cutoff,
            retention_days=retention_days,
            actor=actor,
        )
    return PurgeResult(purged_rows=purged, through_id=through_id, checkpoint_id=checkpoint_id)


async def _purge_prefix(
    tx: AsyncConnection[Any],
    recorder: AuditRecorder,
    keys: CheckpointSigner,
    *,
    through_id: int,
    verified_hash: bytes | None,
    cutoff: datetime,
    retention_days: int,
    actor: str | None,
) -> tuple[int, int]:
    cur = await tx.execute(_SEGMENT, (through_id, through_id))
    segment = await cur.fetchone()
    if segment is None or segment[0] is None or bytes(segment[0]) != verified_hash:
        raise RetentionError(f"refusing to purge: row {through_id} changed after verification")
    first_id, count = int(segment[1]), int(segment[2])

    key = await keys.active_key()
    unsigned = Checkpoint(
        first_purged_id=first_id,
        through_id=through_id,
        through_hash=bytes(segment[0]),
        purged_rows=count,
        cutoff=cutoff.astimezone(UTC),
        retention_days=retention_days,
        key_id=key.key_id,
    )
    signed = await keys.sign(unsigned.message())
    if signed.key_id != key.key_id:
        raise RetentionError("refusing to purge: the signing key changed during the purge")
    checkpoint = replace(unsigned, signature=signed.signature)
    checkpoint_id = await recorder.record(
        AuditEvent(
            action=PURGE_ACTION,
            outcome="success",
            actor=actor,
            details=checkpoint.to_details(),
        ),
        conn=tx,
    )
    deleted = await tx.execute(_DELETE, (through_id,))
    if deleted.rowcount != count:
        raise RetentionError(f"refusing to purge: rows up to {through_id} changed during the purge")
    return checkpoint_id, count
