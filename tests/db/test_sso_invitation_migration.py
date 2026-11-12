"""SSO invitations' migration: the login transaction's invitation hash, and a tested downgrade.

The integration session may re-chain the migration, so the tests find it and
its parent by the migration's name rather than a revision id. A later
migration (SSO invitation sealing) replaces the hash with a sealed token, so
these tests check this migration at its own revision, not at head.
"""

from __future__ import annotations

import os

import psycopg
import pytest

from warden.db import SCHEMA, current_revision, downgrade, heads, migrate

pytestmark = pytest.mark.db

TABLE = "sso_login_transactions"
COLUMN = "invitation_hash"


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
        if revision.path.endswith("_sso_invitations.py"):
            parent = revision.down_revision
            assert isinstance(parent, str)
            return revision.revision, parent
    raise AssertionError("no SSO invitations migration in the chain")


def _insert(conn: psycopg.Connection[tuple[object, ...]], invitation_hash: object) -> None:
    conn.execute(
        "INSERT INTO warden.sso_login_transactions"
        " (state_hash, binding_hash, nonce, code_verifier, issuer, expires_at, invitation_hash)"
        " VALUES (%s, %s, 'n', %s, 'https://idp.example.org', now(), %s)",
        (os.urandom(32), os.urandom(32), "v" * 43, invitation_hash),
    )


def test_a_transaction_may_carry_an_invitation_hash(migrated_dsn: str) -> None:
    downgrade(migrated_dsn, _revisions()[0])
    assert COLUMN in _columns(migrated_dsn)
    with psycopg.connect(migrated_dsn) as conn:
        _insert(conn, None)
        _insert(conn, os.urandom(32))


@pytest.mark.parametrize("value", [b"", b"\x01" * 31, b"\x01" * 33], ids=["empty", "31", "33"])
def test_the_invitation_hash_is_a_sha256_digest(migrated_dsn: str, value: bytes) -> None:
    downgrade(migrated_dsn, _revisions()[0])
    with psycopg.connect(migrated_dsn) as conn, pytest.raises(psycopg.errors.CheckViolation):
        _insert(conn, value)


def test_downgrade_removes_only_the_invitation_hash(migrated_dsn: str) -> None:
    revision, parent = _revisions()
    # Later migrations may sit above this one; take them off first.
    downgrade(migrated_dsn, revision)
    tables, columns = _tables(migrated_dsn), _columns(migrated_dsn)
    assert COLUMN in columns
    downgrade(migrated_dsn, parent)
    assert current_revision(migrated_dsn) == parent
    assert _tables(migrated_dsn) == tables
    assert _columns(migrated_dsn) == columns - {COLUMN}
    migrate(migrated_dsn)
    assert current_revision(migrated_dsn) == heads()[0]
    downgrade(migrated_dsn, revision)
    assert _columns(migrated_dsn) == columns
