"""The migration chain: one head, schema-confined, reversible, safe to race."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import psycopg
import pytest

from warden.db import IDENTITY_TABLES, SCHEMA, current_revision, downgrade, heads, migrate

pytestmark = pytest.mark.db

WORKER = Path(__file__).with_name("migrate_worker.py")
BASELINE = "5c2f9a1e7b04"
BASELINE_TABLES = {"alembic_version", "audit_events", "signing_keys", "settings"}
HEAD_TABLES = BASELINE_TABLES | IDENTITY_TABLES


def _tables(dsn: str, schema: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (schema,)
        ).fetchall()
    return {r[0] for r in rows}


def _objects_outside_warden(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT n.nspname || '.' || c.relname"
            " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', %s)"
            " AND n.nspname NOT LIKE 'pg\\_toast%%' AND n.nspname NOT LIKE 'pg\\_temp%%'",
            (SCHEMA,),
        ).fetchall()
    return {r[0] for r in rows}


def test_chain_has_a_single_head() -> None:
    assert len(heads()) == 1


def test_migrate_creates_the_schema_and_reaches_head(dsn: str) -> None:
    migrate(dsn)
    assert _tables(dsn, SCHEMA) == HEAD_TABLES
    assert current_revision(dsn) == heads()[0]


def test_version_table_lives_in_the_warden_schema(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        row = conn.execute("SELECT version_num FROM warden.alembic_version").fetchone()
    assert row is not None and row[0] == heads()[0]
    assert "alembic_version" not in _tables(migrated_dsn, "public")


def test_migrations_touch_nothing_outside_the_warden_schema(dsn: str) -> None:
    before = _objects_outside_warden(dsn)
    migrate(dsn)
    downgrade(dsn, "base")
    migrate(dsn)
    assert _objects_outside_warden(dsn) == before


def test_downgrade_to_base_and_upgrade_again(migrated_dsn: str) -> None:
    downgrade(migrated_dsn, "base")
    assert _tables(migrated_dsn, SCHEMA) == {"alembic_version"}
    assert current_revision(migrated_dsn) is None
    migrate(migrated_dsn)
    assert _tables(migrated_dsn, SCHEMA) == HEAD_TABLES
    assert current_revision(migrated_dsn) == heads()[0]


def test_migrate_is_idempotent(migrated_dsn: str) -> None:
    migrate(migrated_dsn)
    assert current_revision(migrated_dsn) == heads()[0]


def test_concurrent_migrations_from_separate_processes_all_succeed(dsn: str) -> None:
    """Replicas starting together must not race each other's DDL."""
    workers = 4
    start = time.time() + 10
    procs = [
        subprocess.Popen(
            [sys.executable, str(WORKER), dsn, repr(start)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(workers)
    ]
    results = [proc.communicate(timeout=120) for proc in procs]
    for proc, (out, err) in zip(procs, results, strict=True):
        ready = [line for line in out.splitlines() if line.startswith("ready ")]
        assert ready, f"worker never became ready: {err[-2000:]}"
        # The barrier only proves anything if every worker was waiting before the start.
        assert float(ready[0].split()[1]) < start, "worker missed the start barrier"
        assert proc.returncode == 0, err[-2000:]
    assert current_revision(dsn) == heads()[0]


def test_concurrent_migrations_within_one_process_all_succeed(dsn: str) -> None:
    """Threads in one process (a product's test suite, say) must not collide in Alembic."""
    workers = 4
    barrier = threading.Barrier(workers)
    errors: list[BaseException] = []

    def run() -> None:
        try:
            barrier.wait(timeout=30)
            migrate(dsn)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert current_revision(dsn) == heads()[0]


def test_libpq_and_sqlalchemy_url_forms_are_accepted(dsn: str) -> None:
    sqlalchemy_url = dsn.replace("postgresql://", "postgresql+psycopg://", 1)
    migrate(sqlalchemy_url)
    assert current_revision(dsn) == heads()[0]


def test_baseline_signing_key_constraints(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO warden.signing_keys (key_id, public_key) VALUES ('k', %s)", (b"short",)
            )
        conn.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO warden.signing_keys (key_id, algorithm, public_key)"
                " VALUES ('k', 'HS256', %s)",
                (b"\0" * 32,),
            )


def _columns(dsn: str, table: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = %s AND table_name = %s",
            (SCHEMA, table),
        ).fetchall()
    return {r[0] for r in rows}


def test_signing_keys_carry_a_revocation_time(migrated_dsn: str) -> None:
    assert "revoked_at" in _columns(migrated_dsn, "signing_keys")
    with psycopg.connect(migrated_dsn) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO warden.signing_keys (key_id, public_key, created_at, revoked_at)"
            " VALUES ('k', %s, now(), now() - interval '1 second')",
            (b"\0" * 32,),
        )


def test_a_revoked_key_must_also_be_retired(migrated_dsn: str) -> None:
    # verify() relies on retired_at alone being enough to refuse a revoked key.
    with psycopg.connect(migrated_dsn) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO warden.signing_keys (key_id, public_key, revoked_at)"
            " VALUES ('k', %s, now())",
            (b"\0" * 32,),
        )


def test_revocation_migration_downgrades_to_the_baseline(migrated_dsn: str) -> None:
    downgrade(migrated_dsn, BASELINE)
    assert current_revision(migrated_dsn) == BASELINE
    assert "revoked_at" not in _columns(migrated_dsn, "signing_keys")
    migrate(migrated_dsn)
    assert "revoked_at" in _columns(migrated_dsn, "signing_keys")
