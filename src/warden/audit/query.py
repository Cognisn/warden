"""Filtering audit rows by time range, action, actor, resource and outcome."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Self

from psycopg import sql
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from warden.audit.events import Outcome
from warden.audit.store import ROW_COLUMNS, AuditRow, row_from_record
from warden.db import AUDIT_EVENTS, Database, table

__all__ = ["MAX_PAGE_SIZE", "AuditPage", "AuditQuery", "iter_events", "list_events"]

MAX_PAGE_SIZE = 1000

_AUDIT = table(AUDIT_EVENTS)
_SNAPSHOT = sql.SQL("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")


class AuditQuery(BaseModel):
    """A filter over the audit trail. Every given field must match.

    ``since`` is inclusive and ``until`` exclusive, both on ``occurred_at``.
    ``actions`` matches any of the listed actions.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    since: AwareDatetime | None = None
    until: AwareDatetime | None = None
    actions: tuple[str, ...] = Field(default=(), max_length=50)
    actor: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: Outcome | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.since is not None and self.until is not None and self.since >= self.until:
            raise ValueError("since must be earlier than until")
        return self

    def where(self) -> sql.Composable:
        """The SQL condition for this filter (``TRUE`` if empty)."""
        clauses: list[sql.Composable] = []
        if self.since is not None:
            clauses.append(sql.SQL("occurred_at >= {}").format(sql.Literal(self.since)))
        if self.until is not None:
            clauses.append(sql.SQL("occurred_at < {}").format(sql.Literal(self.until)))
        if self.actions:
            clauses.append(sql.SQL("action = ANY({})").format(sql.Literal(list(self.actions))))
        for column in ("actor", "resource_type", "resource_id", "outcome"):
            value = getattr(self, column)
            if value is not None:
                clauses.append(
                    sql.SQL("{} = {}").format(sql.Identifier(column), sql.Literal(value))
                )
        return sql.SQL(" AND ").join(clauses) if clauses else sql.SQL("TRUE")


@dataclass(frozen=True, slots=True)
class AuditPage:
    """One page of matching rows, newest first.

    ``next_before_id`` is passed as ``before_id`` for the next (older) page,
    and is ``None`` on the last page.
    """

    rows: list[AuditRow]
    next_before_id: int | None


async def list_events(
    db: Database, query: AuditQuery, *, limit: int = 100, before_id: int | None = None
) -> AuditPage:
    """A page of matching rows, newest first, older than ``before_id`` if given."""
    if not 1 <= limit <= MAX_PAGE_SIZE:
        raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
    condition = query.where()
    if before_id is not None:
        condition = sql.SQL("{} AND id < {}").format(condition, sql.Literal(before_id))
    async with db.connection() as conn:
        cur = await conn.execute(
            sql.SQL("SELECT {} FROM {} WHERE {} ORDER BY id DESC LIMIT {}").format(
                ROW_COLUMNS, _AUDIT, condition, sql.Literal(limit + 1)
            )
        )
        rows = [row_from_record(r) for r in await cur.fetchall()]
    more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(rows=rows, next_before_id=rows[-1].id if more else None)


async def iter_events(
    db: Database, query: AuditQuery, *, batch_size: int = 500
) -> AsyncIterator[AuditRow]:
    """Every matching row in chain (id) order, from one consistent snapshot."""
    async with db.connection() as conn, conn.transaction():
        await conn.execute(_SNAPSHOT)
        async with conn.cursor(name="warden_audit_export") as cur:
            cur.itersize = batch_size
            await cur.execute(
                sql.SQL("SELECT {} FROM {} WHERE {} ORDER BY id").format(
                    ROW_COLUMNS, _AUDIT, query.where()
                )
            )
            async for record in cur:
                yield row_from_record(record)
