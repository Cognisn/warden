"""The audit chain migration: reversible, and refuses rows it cannot chain."""

from __future__ import annotations

import psycopg
import pytest

from warden.db import current_revision, downgrade, heads, migrate

pytestmark = pytest.mark.db

CHAIN = "3f7a2c9d1b6e"
BEFORE_CHAIN = "8d41b7c3a9f2"


def _columns(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = 'warden' AND table_name = 'audit_events'"
        ).fetchall()
    return {r[0] for r in rows}


def _constraints(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'warden.audit_events'::regclass"
            " UNION SELECT indexname FROM pg_indexes WHERE schemaname = 'warden'"
            " AND tablename = 'audit_events'"
        ).fetchall()
    return {r[0] for r in rows}


CHAIN_OBJECTS = {
    "audit_events_outcome",
    "audit_events_hash_lengths",
    "audit_events_prev_hash_unique",
    "audit_events_recorded_at",
}


def test_head_includes_the_chain_revision(migrated_dsn: str) -> None:
    assert current_revision(migrated_dsn) == heads()[0]
    assert "recorded_at" in _columns(migrated_dsn)
    assert _constraints(migrated_dsn) >= CHAIN_OBJECTS


def test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(
    migrated_dsn: str,
) -> None:
    downgrade(migrated_dsn, BEFORE_CHAIN)
    assert "recorded_at" not in _columns(migrated_dsn)
    assert not CHAIN_OBJECTS & _constraints(migrated_dsn)
    with psycopg.connect(migrated_dsn) as conn:
        # Nullable again, as at the baseline.
        conn.execute(
            "INSERT INTO warden.audit_events (action, outcome) VALUES ('product.x', 'other')"
        )
        conn.execute("DELETE FROM warden.audit_events")
    migrate(migrated_dsn)
    assert "recorded_at" in _columns(migrated_dsn)
    assert _constraints(migrated_dsn) >= CHAIN_OBJECTS


def test_upgrade_refuses_unchained_rows(dsn: str) -> None:
    migrate(dsn, BEFORE_CHAIN)
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "INSERT INTO warden.audit_events (action, outcome) VALUES ('product.x', 'success')"
        )
    with pytest.raises(RuntimeError, match="cannot be chained"):
        migrate(dsn)
    assert current_revision(dsn) == BEFORE_CHAIN
