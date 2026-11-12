"""Append-only grants: the application role can only insert and read audit rows.

The forwarder role reads audit rows and keeps its cursor in settings; the
purger role alone may delete audit rows, and only the retention purge does.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql

from chain_support import age, stored
from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.grants import grants_sql
from warden.audit.retention import MIN_RETENTION_DAYS, purge
from warden.db import Database
from warden.keys import KeyStore

pytestmark = pytest.mark.db

PASSWORD = "synthetic-test-password"


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


def _as(dsn: str, role: str) -> str:
    parts = urlsplit(dsn)
    host = parts.netloc.rpartition("@")[2]
    return urlunsplit(parts._replace(netloc=f"{role}:{PASSWORD}@{host}"))


@pytest.fixture
def roles(migrated_dsn: str) -> Iterator[dict[str, str]]:
    suffix = uuid.uuid4().hex[:8]
    names = {kind: f"warden_{kind}_{suffix}" for kind in ("app", "forwarder", "purger")}
    with psycopg.connect(migrated_dsn, autocommit=True) as conn:
        for name in names.values():
            conn.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(name), sql.Literal(PASSWORD)
                )
            )
        conn.execute(
            grants_sql(
                app_role=names["app"],
                forwarder_role=names["forwarder"],
                purger_role=names["purger"],
            )
        )
    yield names
    with psycopg.connect(migrated_dsn, autocommit=True) as conn:
        for name in names.values():
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


def _registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    return registry


async def _pool(dsn: str) -> Any:
    from psycopg_pool import AsyncConnectionPool

    pool: Any = AsyncConnectionPool(dsn, min_size=1, max_size=4, open=False)
    await pool.open(wait=True)
    return pool


def _refused(dsn: str, statement: str) -> bool:
    with psycopg.connect(dsn) as conn:
        try:
            conn.execute(statement)
        except psycopg.errors.InsufficientPrivilege:
            return True
    return False


async def test_the_application_role_records_and_reads(
    migrated_dsn: str, roles: dict[str, str]
) -> None:
    pool = await _pool(_as(migrated_dsn, roles["app"]))
    try:
        recorder = AuditRecorder(Database(pool), _registry())
        await recorder.record(AuditEvent(action="product.export", outcome="success"))
        async with pool.connection() as conn:
            cur = await conn.execute("SELECT count(*) FROM warden.audit_events")
            assert await cur.fetchone() == (1,)
    finally:
        await pool.close()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE warden.audit_events SET actor = 'x'",
        "DELETE FROM warden.audit_events",
        "TRUNCATE warden.audit_events",
        "UPDATE warden.alembic_version SET version_num = 'x'",
        "DELETE FROM warden.alembic_version",
    ],
)
def test_the_application_role_cannot_edit_or_delete_audit_rows(
    migrated_dsn: str, roles: dict[str, str], statement: str
) -> None:
    assert _refused(_as(migrated_dsn, roles["app"]), statement)


def test_the_application_role_keeps_its_other_tables(
    migrated_dsn: str, roles: dict[str, str]
) -> None:
    app = _as(migrated_dsn, roles["app"])
    with psycopg.connect(app) as conn:
        conn.execute("INSERT INTO warden.settings (key, value) VALUES ('k', '1')")
        conn.execute("UPDATE warden.settings SET value = '2' WHERE key = 'k'")
        conn.execute("DELETE FROM warden.settings WHERE key = 'k'")
        conn.execute("SELECT count(*) FROM warden.signing_keys")


def test_the_forwarder_reads_audit_rows_and_keeps_its_cursor(
    migrated_dsn: str, roles: dict[str, str]
) -> None:
    forwarder = _as(migrated_dsn, roles["forwarder"])
    with psycopg.connect(forwarder) as conn:
        conn.execute("SELECT * FROM warden.audit_events")
        conn.execute("INSERT INTO warden.settings (key, value) VALUES ('syslog.cursor', '0')")
        conn.execute("UPDATE warden.settings SET value = '5' WHERE key = 'syslog.cursor'")
        conn.execute("SELECT value FROM warden.settings")
    for statement in (
        "INSERT INTO warden.audit_events (action, outcome) VALUES ('x.y', 'success')",
        "UPDATE warden.audit_events SET actor = 'x'",
        "DELETE FROM warden.audit_events",
        "DELETE FROM warden.settings",
        "SELECT * FROM warden.signing_keys",
    ):
        assert _refused(forwarder, statement), statement


async def test_only_the_purger_role_can_purge(
    migrated_dsn: str, roles: dict[str, str], pool: Any
) -> None:
    secrets = MemorySecrets()
    await KeyStore(Database(pool), secrets).rotate()
    recorder = AuditRecorder(Database(pool), _registry())
    for _ in range(3):
        await recorder.record(AuditEvent(action="product.export", outcome="success"))
    age(migrated_dsn, None, MIN_RETENTION_DAYS + 10)

    app_pool = await _pool(_as(migrated_dsn, roles["app"]))
    purger_pool = await _pool(_as(migrated_dsn, roles["purger"]))
    try:
        app = AuditRecorder(Database(app_pool), _registry())
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await purge(
                app, KeyStore(Database(app_pool), secrets), retention_days=MIN_RETENTION_DAYS
            )
        assert len(stored(migrated_dsn)) == 3

        purger = AuditRecorder(Database(purger_pool), _registry())
        result = await purge(
            purger, KeyStore(Database(purger_pool), secrets), retention_days=MIN_RETENTION_DAYS
        )
        assert result.purged_rows == 3
        assert [r.id for r in stored(migrated_dsn)] == [result.checkpoint_id]
    finally:
        await app_pool.close()
        await purger_pool.close()
