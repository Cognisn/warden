"""Identity lifecycle's migration: its tables, their constraints, and a tested downgrade."""

from __future__ import annotations

import uuid

import psycopg
import pytest

from warden.db import SCHEMA, current_revision, downgrade, heads, migrate
from warden.identity.apikeys import API_KEYS
from warden.identity.invitations import INVITATION_GRANTS
from warden.identity.single_use import SINGLE_USE_TOKENS

pytestmark = pytest.mark.db

# The integration session may re-chain the migration, so the downgrade test
# finds its parent by the migration's name rather than a revision id.
LIFECYCLE_TABLES = {SINGLE_USE_TOKENS, INVITATION_GRANTS, API_KEYS}

Conn = psycopg.Connection[tuple[object, ...]]


def _tables(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (SCHEMA,)
        ).fetchall()
    return {r[0] for r in rows}


def _lifecycle_parent() -> str:
    """The revision below the lifecycle migration, however the chain was re-ordered."""
    from alembic.script import ScriptDirectory

    from warden.db.migrate import _config

    script = ScriptDirectory.from_config(_config())
    for revision in script.walk_revisions():
        if revision.path.endswith("_identity_lifecycle.py"):
            parent = revision.down_revision
            assert isinstance(parent, str)
            return parent
    raise AssertionError("no identity lifecycle migration in the chain")


def _user(conn: Conn, email: str = "invitee@example.com") -> uuid.UUID:
    row = conn.execute(
        "INSERT INTO warden.users (email, status) VALUES (%s, 'invited') RETURNING id", (email,)
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def test_lifecycle_tables_exist_at_head(migrated_dsn: str) -> None:
    assert _tables(migrated_dsn) >= LIFECYCLE_TABLES


def test_downgrade_removes_only_the_lifecycle_tables(migrated_dsn: str) -> None:
    before = _tables(migrated_dsn)
    parent = _lifecycle_parent()
    downgrade(migrated_dsn, parent)
    assert current_revision(migrated_dsn) == parent
    assert _tables(migrated_dsn) == before - LIFECYCLE_TABLES
    migrate(migrated_dsn)
    assert _tables(migrated_dsn) == before
    assert current_revision(migrated_dsn) == heads()[0]


@pytest.mark.parametrize(
    ("columns", "values"),
    [
        ("purpose", "'login'"),
        ("token_hash", "'\\x00'::bytea"),
    ],
)
def test_single_use_token_constraints(migrated_dsn: str, columns: str, values: str) -> None:
    fields = {
        "token_hash": "decode(repeat('00', 32), 'hex')",
        "purpose": "'invitation'",
        "expires_at": "now() + interval '1 hour'",
        columns: values,
    }
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                f"INSERT INTO warden.single_use_tokens (user_id, {', '.join(fields)})"  # noqa: S608
                f" VALUES (%s, {', '.join(fields.values())})",
                (user,),
            )


def test_a_single_use_token_cannot_expire_before_it_is_created(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO warden.single_use_tokens (user_id, token_hash, purpose, expires_at)"
                " VALUES (%s, decode(repeat('00', 32), 'hex'), 'invitation', now())",
                (user,),
            )


def test_a_token_is_either_consumed_or_revoked_never_both(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO warden.single_use_tokens"
                " (user_id, token_hash, purpose, expires_at, consumed_at, revoked_at)"
                " VALUES (%s, decode(repeat('00', 32), 'hex'), 'invitation',"
                " now() + interval '1 hour', now(), now())",
                (user,),
            )


def test_deleting_a_user_removes_their_tokens_grants_and_keys(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        conn.execute(
            "INSERT INTO warden.single_use_tokens (user_id, token_hash, purpose, expires_at)"
            " VALUES (%s, decode(repeat('01', 32), 'hex'), 'invitation', now() + interval '1 h')",
            (user,),
        )
        conn.execute(
            "INSERT INTO warden.invitation_grants (user_id, role) VALUES (%s, 'viewer')", (user,)
        )
        conn.execute(
            "INSERT INTO warden.api_keys (user_id, name, key_hash, hint, scopes)"
            " VALUES (%s, 'ci', decode(repeat('02', 32), 'hex'), 'wdn_abcd', '{}')",
            (user,),
        )
        conn.execute("DELETE FROM warden.users WHERE id = %s", (user,))
        for name in LIFECYCLE_TABLES:
            row = conn.execute(
                f"SELECT count(*) FROM warden.{name} WHERE user_id = %s",  # noqa: S608
                (user,),
            ).fetchone()
            assert row == (0,), name


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("name", "''"),
        ("key_hash", "'\\x00'::bytea"),
        ("expires_at", "now() - interval '1 second'"),
    ],
)
def test_api_key_constraints(migrated_dsn: str, column: str, value: str) -> None:
    fields = {
        "name": "'ci'",
        "key_hash": "decode(repeat('03', 32), 'hex')",
        "hint": "'wdn_abcd'",
        "scopes": "'{}'",
        column: value,
    }
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                f"INSERT INTO warden.api_keys (user_id, {', '.join(fields)})"  # noqa: S608
                f" VALUES (%s, {', '.join(fields.values())})",
                (user,),
            )
