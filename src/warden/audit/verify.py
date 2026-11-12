"""Verify the audit chain and report the first broken link.

Rows are read in id order from one REPEATABLE READ snapshot, so a purge or
an append running at the same time cannot make an intact chain look broken.
For each row the stored ``row_hash`` is recomputed and the ``prev_hash``
link checked. The first row must be either the genesis row or anchored by a
valid retention checkpoint. Every checkpoint row's signature is checked with
``verify_historical``, so a key retired by routine rotation still vouches for
what it signed, but a revoked key vouches for nothing.

``verify_anchors`` also checks, in the same snapshot, anchors held outside
the database (``warden.audit.anchor``): each anchor's signature, and that the
row at its ``head_id`` still has its ``head_hash``, or, if that row was
purged, that a valid checkpoint covers it. That finds tail deletion and a
rewrite of the chain, which the chain alone cannot show.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from psycopg import AsyncConnection, sql

from warden.audit.anchor import ExternalAnchor
from warden.audit.chain import GENESIS_HASH, row_hash
from warden.audit.checkpoint import (
    PURGE_ACTION,
    Checkpoint,
    HistoricalVerifier,
    MalformedCheckpoint,
)
from warden.audit.store import ROW_COLUMNS, AuditRow, row_from_record
from warden.db import AUDIT_EVENTS, SIGNING_KEYS, Database, table

__all__ = [
    "AnchorCheck",
    "AnchorReport",
    "AnchorStatus",
    "BreakReason",
    "BrokenLink",
    "VerificationReport",
    "verify_anchors",
    "verify_chain",
]

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

    async def signature_problem(
        self, message: bytes, signature: bytes, key_id: str
    ) -> Literal["signature", "revoked_key"] | None:
        """None if a key not revoked signed ``message``; otherwise why not."""
        if await self._keys.verify_historical(message, signature, key_id):
            return None
        cur = await self._conn.execute(
            sql.SQL("SELECT revoked_at IS NOT NULL FROM {} WHERE key_id = %s").format(
                table(SIGNING_KEYS)
            ),
            (key_id,),
        )
        found = await cur.fetchone()
        return "revoked_key" if found and found[0] else "signature"

    async def checkpoint_problem(self, row: AuditRow) -> BreakReason | None:
        try:
            checkpoint = Checkpoint.from_details(row.details)
        except MalformedCheckpoint:
            return "checkpoint_malformed"
        if checkpoint.through_id >= row.id:
            return "checkpoint_malformed"
        problem = await self.signature_problem(
            checkpoint.message(), checkpoint.signature, checkpoint.key_id
        )
        if problem is None:
            return None
        return "checkpoint_revoked_key" if problem == "revoked_key" else "checkpoint_signature"

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
    async with db.connection() as conn, conn.transaction():
        await conn.execute(_SNAPSHOT)
        checker = _Checker(conn, keys)
        purges = await _purges(conn)
        return await _walk(conn, checker, purges, through_id=through_id, batch_size=batch_size)


async def _purges(conn: AsyncConnection[Any]) -> list[AuditRow]:
    cur = await conn.execute(
        sql.SQL("SELECT {} FROM {} WHERE action = %s AND outcome = 'success' ORDER BY id").format(
            ROW_COLUMNS, _AUDIT
        ),
        (PURGE_ACTION,),
    )
    return [row_from_record(r) for r in await cur.fetchall()]


async def _walk(
    conn: AsyncConnection[Any],
    checker: _Checker,
    purges: list[AuditRow],
    *,
    through_id: int | None,
    batch_size: int,
) -> VerificationReport:
    upto = (
        sql.SQL("")
        if through_id is None
        else sql.SQL(" WHERE id <= {}").format(sql.Literal(through_id))
    )
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


# Verification against anchors held outside the database.

AnchorStatus = Literal[
    "matched",
    "checkpointed",
    "anchor_malformed",
    "anchor_signature",
    "anchor_revoked_key",
    "head_missing",
    "head_hash",
]

_ANCHOR_STATUSES: dict[AnchorStatus, str] = {
    "matched": "the row at head_id matches the anchor",
    "checkpointed": "the row at head_id was purged behind a valid checkpoint",
    "anchor_malformed": "the anchor is malformed",
    "anchor_signature": "the anchor's signature is not valid",
    "anchor_revoked_key": "the anchor was signed by a revoked key",
    "head_missing": (
        "the row at head_id is missing: the tail was deleted,"
        " or rows were removed without a checkpoint"
    ),
    "head_hash": "the row at head_id does not match the anchor: the chain was rewritten",
}

_HEADS = sql.SQL("SELECT id, row_hash FROM {} WHERE id = ANY(%s)").format(_AUDIT)


@dataclass(frozen=True, slots=True)
class AnchorCheck:
    """The outcome for one external anchor. Carries identifiers only, never row contents."""

    line: int
    row_id: int | None
    head_id: int | None
    status: AnchorStatus

    @property
    def ok(self) -> bool:
        return self.status in ("matched", "checkpointed")

    @property
    def description(self) -> str:
        return _ANCHOR_STATUSES[self.status]


@dataclass(frozen=True, slots=True)
class AnchorReport:
    """The chain's own verification, and each external anchor checked against it."""

    chain: VerificationReport
    anchors: tuple[AnchorCheck, ...]

    @property
    def ok(self) -> bool:
        return self.chain.ok and all(check.ok for check in self.anchors)


async def verify_anchors(
    db: Database,
    keys: HistoricalVerifier,
    anchors: Iterable[ExternalAnchor],
    *,
    batch_size: int = 1000,
) -> AnchorReport:
    """Verify the chain, then check each external anchor against it, in one snapshot.

    For each anchor, in order:

    1. A malformed anchor is reported as such.
    2. Its signature must verify with ``verify_historical`` over the
       ``warden.audit.anchor.v1`` message: a retired key still counts, a
       revoked or unknown key does not.
    3. If the row at ``head_id`` exists, its ``row_hash`` must equal
       ``head_hash``.
    4. If it does not, the earliest valid checkpoint whose ``through_id`` is
       at or after ``head_id`` must cover it; when ``through_id`` is
       ``head_id`` itself, the checkpoint's ``through_hash`` must equal
       ``head_hash``. With no such checkpoint, the row is missing.
    """
    found = list(anchors)
    async with db.connection() as conn, conn.transaction():
        await conn.execute(_SNAPSHOT)
        checker = _Checker(conn, keys)
        purges = await _purges(conn)
        chain = await _walk(conn, checker, purges, through_id=None, batch_size=batch_size)
        heads = sorted({a.anchor.head_id for a in found if a.anchor is not None})
        cur = await conn.execute(_HEADS, (heads,))
        stored = {int(r[0]): bytes(r[1]) for r in await cur.fetchall()}
        covering = [
            Checkpoint.from_details(row.details)
            for row in purges
            if await checker.checkpoint_problem(row) is None
        ]
        checks = [await _check_anchor(checker, item, stored, covering) for item in found]
    return AnchorReport(chain=chain, anchors=tuple(checks))


async def _check_anchor(
    checker: _Checker,
    item: ExternalAnchor,
    stored: dict[int, bytes],
    covering: list[Checkpoint],
) -> AnchorCheck:
    claim = item.anchor
    if claim is None:
        return AnchorCheck(item.line, item.row_id, None, "anchor_malformed")

    def result(status: AnchorStatus) -> AnchorCheck:
        return AnchorCheck(item.line, item.row_id, claim.head_id, status)

    problem = await checker.signature_problem(claim.message(), claim.signature, claim.key_id)
    if problem is not None:
        return result("anchor_revoked_key" if problem == "revoked_key" else "anchor_signature")
    present = stored.get(claim.head_id)
    if present is not None:
        return result("matched" if present == claim.head_hash else "head_hash")
    checkpoint = next((c for c in covering if c.through_id >= claim.head_id), None)
    if checkpoint is None:
        return result("head_missing")
    if checkpoint.through_id == claim.head_id and checkpoint.through_hash != claim.head_hash:
        return result("head_hash")
    return result("checkpointed")
