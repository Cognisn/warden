"""SSO invitation sealing's migration: the sealed token replaces its hash, and a tested downgrade.

The integration session may re-chain the migration, so the tests find it and
its parent by the migration's file name rather than a revision id.
"""

from __future__ import annotations

import os

import psycopg
import pytest
from psycopg import sql

from warden.db import SCHEMA, current_revision, downgrade, heads, migrate

pytestmark = pytest.mark.db

TABLE = "sso_login_transactions"
SEALED = "invitation_sealed"
HASHED = "invitation_hash"
SEALED_LENGTH = 71


def _columns(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = %s AND table_name = %s",
            (SCHEMA, TABLE),
        ).fetchall()
    return {str(r[0]) for r in rows}


def _tables(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (SCHEMA,)
        ).fetchall()
    return {str(r[0]) for r in rows}


def _revisions() -> tuple[str, str]:
    """This migration and the revision below it, however the chain was re-ordered."""
    from alembic.script import ScriptDirectory

    from warden.db.migrate import _config

    script = ScriptDirectory.from_config(_config())
    for revision in script.walk_revisions():
        if revision.path.endswith("_sso_invitation_sealing.py"):
            parent = revision.down_revision
            assert isinstance(parent, str)
            return revision.revision, parent
    raise AssertionError("no SSO invitation sealing migration in the chain")


def _insert(conn: psycopg.Connection[tuple[object, ...]], column: str, value: object) -> bytes:
    state_hash = os.urandom(32)
    conn.execute(
        sql.SQL(
            "INSERT INTO warden.sso_login_transactions"
            " (state_hash, binding_hash, nonce, code_verifier, issuer, expires_at, {})"
            " VALUES (%s, %s, 'n', %s, 'https://idp.example.org', now() + interval '1 hour', %s)"
        ).format(sql.Identifier(column)),
        (state_hash, os.urandom(32), "v" * 43, value),
    )
    return state_hash


def _states(dsn: str) -> set[bytes]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute("SELECT state_hash FROM warden.sso_login_transactions").fetchall()
    return {bytes(r[0]) for r in rows}


def test_at_head_a_transaction_carries_a_sealed_invitation_and_no_hash(migrated_dsn: str) -> None:
    columns = _columns(migrated_dsn)
    assert SEALED in columns
    assert HASHED not in columns
    with psycopg.connect(migrated_dsn) as conn:
        _insert(conn, SEALED, None)
        _insert(conn, SEALED, os.urandom(SEALED_LENGTH))


@pytest.mark.parametrize(
    "value",
    [b"", b"\x01" * 32, b"\x01" * (SEALED_LENGTH - 1), b"\x01" * (SEALED_LENGTH + 1)],
    ids=["empty", "a-hash", "70", "72"],
)
def test_the_sealed_invitation_has_the_sealed_length(migrated_dsn: str, value: bytes) -> None:
    with psycopg.connect(migrated_dsn) as conn, pytest.raises(psycopg.errors.CheckViolation):
        _insert(conn, SEALED, value)


def test_downgrade_restores_the_hash_column_and_drops_sealed_rows(migrated_dsn: str) -> None:
    revision, parent = _revisions()
    # Later migrations may sit above this one; take them off first.
    downgrade(migrated_dsn, revision)
    tables, columns = _tables(migrated_dsn), _columns(migrated_dsn)
    with psycopg.connect(migrated_dsn) as conn:
        plain = _insert(conn, SEALED, None)
        _insert(conn, SEALED, os.urandom(SEALED_LENGTH))

    downgrade(migrated_dsn, parent)
    assert current_revision(migrated_dsn) == parent
    assert _tables(migrated_dsn) == tables
    assert _columns(migrated_dsn) == (columns - {SEALED}) | {HASHED}
    # A sealed invitation cannot become a hash without the browser's binding,
    # so its transaction is removed; a plain sign-in's is kept.
    assert _states(migrated_dsn) == {plain}
    with psycopg.connect(migrated_dsn) as conn:
        hashed = _insert(conn, HASHED, os.urandom(32))
    # Its own connection: the refused insert aborts its transaction.
    with psycopg.connect(migrated_dsn) as conn, pytest.raises(psycopg.errors.CheckViolation):
        _insert(conn, HASHED, os.urandom(31))
    assert _states(migrated_dsn) == {plain, hashed}

    migrate(migrated_dsn)
    assert current_revision(migrated_dsn) == heads()[0]
    assert _columns(migrated_dsn) == columns
    # Upgrading drops an in-flight acceptance that carried only a hash: the
    # token is not in the database, so it could never be opened.
    assert hashed not in _states(migrated_dsn)
    assert _states(migrated_dsn) == {plain}
