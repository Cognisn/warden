"""Test-only helpers that stand in for audit rows recorded long ago.

Ageing a row changes ``recorded_at``, which the hash covers, so these helpers
re-chain the whole trail afterwards. They connect as the superuser; warden
itself never edits audit rows.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import psycopg
from psycopg import sql

from warden.audit.chain import GENESIS_HASH, row_hash
from warden.audit.store import ROW_COLUMNS, AuditRow, row_from_record


def stored(dsn: str) -> list[AuditRow]:
    with psycopg.connect(dsn) as conn:
        query = sql.SQL("SELECT {} FROM warden.audit_events ORDER BY id").format(ROW_COLUMNS)
        return [row_from_record(r) for r in conn.execute(query).fetchall()]


def rechain(conn: psycopg.Connection[Any]) -> None:
    """Recompute every hash and link from the first surviving row's ``prev_hash``."""
    conn.execute("DROP INDEX IF EXISTS warden.audit_events_prev_hash_unique")
    query = sql.SQL("SELECT {} FROM warden.audit_events ORDER BY id").format(ROW_COLUMNS)
    rows = [row_from_record(r) for r in conn.execute(query).fetchall()]
    prev = rows[0].prev_hash if rows else GENESIS_HASH
    for row in rows:
        new_hash = row_hash(dataclasses.replace(row, prev_hash=prev))
        conn.execute(
            "UPDATE warden.audit_events SET prev_hash = %s, row_hash = %s WHERE id = %s",
            (prev, new_hash, row.id),
        )
        prev = new_hash
    conn.execute(
        "CREATE UNIQUE INDEX audit_events_prev_hash_unique ON warden.audit_events (prev_hash)"
    )


def age(dsn: str, ids: list[int] | None, days: int) -> None:
    """Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then re-chain."""
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "UPDATE warden.audit_events SET recorded_at = recorded_at - make_interval(days => %s)"
            " WHERE %s::bigint[] IS NULL OR id = ANY(%s)",
            (days, ids, ids),
        )
        rechain(conn)
