"""Verify the audit chain and report the first broken link.

Rows are read in id order from one REPEATABLE READ snapshot, so a purge or
an append running at the same time cannot make an intact chain look broken.
For each row the stored ``row_hash`` is recomputed and the ``prev_hash``
link checked. The first row must be either the genesis row or anchored by a
valid retention checkpoint. Every checkpoint row's signature is checked with
``verify_historical``, so a key retired by routine rotation still vouches for
what it signed, but a revoked key vouches for nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from psycopg import AsyncConnection, sql

from warden.audit.chain import GENESIS_HASH, row_hash
from warden.audit.checkpoint import (
    PURGE_ACTION,
    Checkpoint,
    HistoricalVerifier,
    MalformedCheckpoint,
)
from warden.audit.store import ROW_COLUMNS, AuditRow, row_from_record
from warden.db import AUDIT_EVENTS, SIGNING_KEYS, Database, table

__all__ = ["BreakReason", "BrokenLink", "VerificationReport", "verify_chain"]

BreakReason = Literal[
    "row_hash",
    "prev_hash",
    "unanchored",
    "checkpoint_malformed",
    "checkpoint_signature",
    "checkpoint_revoked_key",
]

_REASONS: dict[BreakReason, str] = {
    "row_hash": "the row's contents do not match its stored hash",
    "prev_hash": "the row does not link to the row before it",
    "unanchored": "the first row is neither the genesis row nor anchored by a valid checkpoint",
    "checkpoint_malformed": "the checkpoint is malformed",
    "checkpoint_signature": "the checkpoint's signature is not valid",
    "checkpoint_revoked_key": "the checkpoint was signed by a revoked key",
}

_SNAPSHOT = sql.SQL("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
_AUDIT = table(AUDIT_EVENTS)


@dataclass(frozen=True, slots=True)
class BrokenLink:
    row_id: int
    reason: BreakReason

    @property
    def description(self) -> str:
        return _REASONS[self.reason]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    rows: int
    first_id: int | None
    last_id: int | None
    head_hash: bytes | None
    checkpoints: int
    broken: BrokenLink | None

    @property
    def ok(self) -> bool:
        return self.broken is None


def _is_checkpoint(row: AuditRow) -> bool:
    """A successful purge row carries a checkpoint; a refused purge records only why."""
    return row.action == PURGE_ACTION and row.outcome == "success"


class _Checker:
    def __init__(self, conn: AsyncConnection[Any], keys: HistoricalVerifier) -> None:
        self._conn = conn
        self._keys = keys

    async def checkpoint_problem(self, row: AuditRow) -> BreakReason | None:
        try:
            checkpoint = Checkpoint.from_details(row.details)
        except MalformedCheckpoint:
            return "checkpoint_malformed"
        if checkpoint.through_id >= row.id:
            return "checkpoint_malformed"
        if await self._keys.verify_historical(
            checkpoint.message(), checkpoint.signature, checkpoint.key_id
        ):
            return None
        cur = await self._conn.execute(
            sql.SQL("SELECT revoked_at IS NOT NULL FROM {} WHERE key_id = %s").format(
                table(SIGNING_KEYS)
            ),
            (checkpoint.key_id,),
        )
        found = await cur.fetchone()
        return "checkpoint_revoked_key" if found and found[0] else "checkpoint_signature"

    async def anchor_problem(self, first: AuditRow, purges: list[AuditRow]) -> BreakReason | None:
        if first.prev_hash == GENESIS_HASH:
            return None
        problem: BreakReason = "unanchored"
        for candidate in purges:
            try:
                checkpoint = Checkpoint.from_details(candidate.details)
            except MalformedCheckpoint:
                continue
            if checkpoint.through_hash != first.prev_hash or checkpoint.through_id >= first.id:
                continue
            found = await self.checkpoint_problem(candidate)
            if found is None:
                return None
            problem = found
        return problem


async def verify_chain(
    db: Database,
    keys: HistoricalVerifier,
    *,
    through_id: int | None = None,
    batch_size: int = 1000,
) -> VerificationReport:
    """Verify the chain, from its first surviving row to ``through_id`` (or the head)."""
    upto = (
        sql.SQL("")
        if through_id is None
        else sql.SQL(" WHERE id <= {}").format(sql.Literal(through_id))
    )
    async with db.connection() as conn, conn.transaction():
        await conn.execute(_SNAPSHOT)
        checker = _Checker(conn, keys)
        cur = await conn.execute(
            sql.SQL(
                "SELECT {} FROM {} WHERE action = %s AND outcome = 'success' ORDER BY id"
            ).format(ROW_COLUMNS, _AUDIT),
            (PURGE_ACTION,),
        )
        purges = [row_from_record(r) for r in await cur.fetchall()]

        rows = checkpoints = 0
        first_id: int | None = None
        previous: AuditRow | None = None
        broken: BrokenLink | None = None
        async with conn.cursor(name="warden_audit_verify") as stream:
            stream.itersize = batch_size
            await stream.execute(
                sql.SQL("SELECT {} FROM {}{} ORDER BY id").format(ROW_COLUMNS, _AUDIT, upto)
            )
            async for record in stream:
                row = row_from_record(record)
                if row.row_hash != row_hash(row):
                    broken = BrokenLink(row.id, "row_hash")
                elif previous is None:
                    if reason := await checker.anchor_problem(row, purges):
                        broken = BrokenLink(row.id, reason)
                elif row.prev_hash != previous.row_hash:
                    broken = BrokenLink(row.id, "prev_hash")
                if broken is None and _is_checkpoint(row):
                    checkpoints += 1
                    if reason := await checker.checkpoint_problem(row):
                        broken = BrokenLink(row.id, reason)
                if broken is not None:
                    break
                rows += 1
                first_id = row.id if first_id is None else first_id
                previous = row
    return VerificationReport(
        rows=rows,
        first_id=first_id,
        last_id=None if previous is None else previous.id,
        head_hash=None if previous is None else previous.row_hash,
        checkpoints=checkpoints,
        broken=broken,
    )
