"""Identity core's migration: its tables, their constraints, and a tested downgrade."""

from __future__ import annotations

import uuid

import psycopg
import pytest

from warden.db import SCHEMA, current_revision, downgrade, heads, migrate
from warden.identity.schema import IDENTITY_TABLES

pytestmark = pytest.mark.db

IDENTITY_REVISION = "b7e14a2c9d30"


def _tables(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (SCHEMA,)
        ).fetchall()
    return {r[0] for r in rows}


def _user(conn: psycopg.Connection[tuple[object, ...]], email: str, **kw: str) -> uuid.UUID:
    columns = {"email": email, "status": "active", **kw}
    row = conn.execute(
        f"INSERT INTO warden.users ({', '.join(columns)})"  # noqa: S608 - test-controlled names
        f" VALUES ({', '.join(['%s'] * len(columns))}) RETURNING id",
        tuple(columns.values()),
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def test_identity_tables_exist_at_head(migrated_dsn: str) -> None:
    assert _tables(migrated_dsn) >= IDENTITY_TABLES


def test_email_is_unique_regardless_of_case(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        _user(conn, "alice@example.com")
        with pytest.raises(psycopg.errors.UniqueViolation):
            _user(conn, "Alice@Example.COM")


@pytest.mark.parametrize(
    "columns",
    [
        {"status": "enabled"},
        {"sign_in_method": "password_only"},
        {"email": ""},
        {"email": "a" * 321},
    ],
)
def test_user_constraints(migrated_dsn: str, columns: dict[str, str]) -> None:
    email = columns.pop("email", "bob@example.com")
    with psycopg.connect(migrated_dsn) as conn, pytest.raises(psycopg.errors.CheckViolation):
        _user(conn, email, **columns)


def test_sealed_totp_secret_length_is_checked(migrated_dsn: str) -> None:
    """A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret is not."""
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "carol@example.com")
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO warden.totp_credentials (user_id, secret_sealed, key_id)"
                " VALUES (%s, %s, 'k')",
                (user, b"\0" * 20),
            )


def test_a_used_step_requires_a_confirmed_enrolment(migrated_dsn: str) -> None:
    """An unconfirmed enrolment can never record a used step (#130 at the schema level)."""
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "dave@example.com")
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO warden.totp_credentials"
                " (user_id, secret_sealed, key_id, last_used_step) VALUES (%s, %s, 'k', 1)",
                (user, b"\0" * 48),
            )


def test_deleting_a_user_removes_their_identity_rows(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "erin@example.com")
        conn.execute(
            "INSERT INTO warden.role_assignments (user_id, role) VALUES (%s, 'viewer')", (user,)
        )
        conn.execute(
            "INSERT INTO warden.sessions (id, user_id, expires_at)"
            " VALUES (gen_random_uuid(), %s, now() + interval '1 hour')",
            (user,),
        )
        conn.execute("DELETE FROM warden.users WHERE id = %s", (user,))
        counts = conn.execute(
            "SELECT (SELECT count(*) FROM warden.role_assignments),"
            " (SELECT count(*) FROM warden.sessions)"
        ).fetchone()
    assert counts == (0, 0)


def test_identity_migration_downgrades_and_upgrades_again(migrated_dsn: str) -> None:
    downgrade(migrated_dsn, f"{IDENTITY_REVISION}-1")
    assert not (_tables(migrated_dsn) & IDENTITY_TABLES)
    assert {"audit_events", "signing_keys", "settings"} <= _tables(migrated_dsn)
    migrate(migrated_dsn)
    assert _tables(migrated_dsn) >= IDENTITY_TABLES
    assert current_revision(migrated_dsn) == heads()[0]
