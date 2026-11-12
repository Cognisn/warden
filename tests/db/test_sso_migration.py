"""Single sign-on's migration: its tables, their constraints, and a tested downgrade.

The downgrade target is whatever this migration currently revises, read from
the chain, so the test survives the integration session re-chaining it.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from alembic.script import ScriptDirectory

from warden.db import SCHEMA, SSO_TABLES, current_revision, downgrade, migrate
from warden.db.migrate import _config

pytestmark = pytest.mark.db

SSO_REVISION = "e3a9c5d17f42"


def _tables(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (SCHEMA,)
        ).fetchall()
    return {r[0] for r in rows}


def _user(conn: psycopg.Connection[tuple[object, ...]], email: str) -> uuid.UUID:
    row = conn.execute(
        "INSERT INTO warden.users (email, status) VALUES (%s, 'active') RETURNING id", (email,)
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def test_sso_tables_exist_at_head(migrated_dsn: str) -> None:
    assert _tables(migrated_dsn) >= SSO_TABLES


def test_a_subject_is_pinned_to_one_user(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        alice = _user(conn, "alice@example.com")
        bob = _user(conn, "bob@example.com")
        conn.execute(
            "INSERT INTO warden.sso_identities (user_id, issuer, subject) VALUES (%s, %s, %s)",
            (alice, "https://idp.example.com", "s-1"),
        )
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(
                "INSERT INTO warden.sso_identities (user_id, issuer, subject) VALUES (%s, %s, %s)",
                (bob, "https://idp.example.com", "s-1"),
            )


def test_a_user_has_at_most_one_pin(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        alice = _user(conn, "alice@example.com")
        conn.execute(
            "INSERT INTO warden.sso_identities (user_id, issuer, subject) VALUES (%s, %s, %s)",
            (alice, "https://idp.example.com", "s-1"),
        )
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(
                "INSERT INTO warden.sso_identities (user_id, issuer, subject) VALUES (%s, %s, %s)",
                (alice, "https://idp.example.com", "s-2"),
            )


@pytest.mark.parametrize(
    ("table", "columns"),
    [
        ("sso_identities", {"subject": ""}),
        ("sso_identities", {"subject": "s" * 256}),
        ("sso_login_transactions", {"state_hash": b"short"}),
        ("sso_login_transactions", {"binding_hash": b"short"}),
        ("sso_handoff_codes", {"code_hash": b"short"}),
    ],
)
def test_constraints(migrated_dsn: str, table: str, columns: dict[str, object]) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "carol@example.com")
        defaults: dict[str, dict[str, object]] = {
            "sso_identities": {
                "user_id": user,
                "issuer": "https://idp.example.com",
                "subject": "s",
            },
            "sso_login_transactions": {
                "state_hash": b"\x01" * 32,
                "binding_hash": b"\x02" * 32,
                "nonce": "n",
                "code_verifier": "v" * 43,
                "issuer": "https://idp.example.com",
                "expires_at": "2099-01-01T00:00:00Z",
            },
            "sso_handoff_codes": {
                "code_hash": b"\x03" * 32,
                "binding_hash": b"\x04" * 32,
                "user_id": user,
                "expires_at": "2099-01-01T00:00:00Z",
            },
        }
        values = {**defaults[table], **columns}
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                f"INSERT INTO warden.{table} ({', '.join(values)})"  # noqa: S608 - test names
                f" VALUES ({', '.join(['%s'] * len(values))})",
                tuple(values.values()),
            )


def test_downgrade_removes_only_the_sso_tables(dsn: str) -> None:
    migrate(dsn)
    head = _tables(dsn)
    # Later migrations may add tables of their own; take them off first.
    downgrade(dsn, SSO_REVISION)
    before = _tables(dsn)
    previous = ScriptDirectory.from_config(_config()).get_revision(SSO_REVISION).down_revision
    assert isinstance(previous, str)
    downgrade(dsn, previous)
    assert current_revision(dsn) == previous
    assert _tables(dsn) == before - SSO_TABLES
    migrate(dsn)
    assert _tables(dsn) == head
