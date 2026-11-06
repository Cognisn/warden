"""WebAuthn's migration: credentials, user handles and challenges, with a tested downgrade.

It also widens two checks for wave 11: ``passkey_only`` as a sign-in method,
and ``passkey_registration`` as a single-use token purpose. The integration
session may re-chain the migration, so the tests find it and its parent by
the migration's file name rather than a revision id.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import psycopg
import pytest

from warden.db import SCHEMA, WEBAUTHN_TABLES, current_revision, downgrade, heads, migrate

pytestmark = pytest.mark.db

Conn = psycopg.Connection[tuple[Any, ...]]


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
        if revision.path.endswith("_webauthn.py"):
            parent = revision.down_revision
            assert isinstance(parent, str)
            return revision.revision, parent
    raise AssertionError("no WebAuthn migration in the chain")


def _user(conn: Conn, method: str = "password_and_sso") -> uuid.UUID:
    row = conn.execute(
        "INSERT INTO warden.users (email, status, sign_in_method)"
        " VALUES (%s, 'active', %s) RETURNING id",
        (f"user-{uuid.uuid4().hex[:8]}@example.com", method),
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _credential(conn: Conn, user_id: uuid.UUID, **overrides: Any) -> uuid.UUID:
    values: dict[str, Any] = {
        "user_id": user_id,
        "credential_id": os.urandom(32),
        "public_key": os.urandom(77),
        "algorithm": -7,
        "sign_count": 0,
        "aaguid": uuid.UUID(int=0),
        "transports": ["usb"],
        "backup_eligible": False,
        "backup_state": False,
        "discoverable": False,
        "user_verified": False,
        "attestation_verified": False,
        "nickname": None,
    }
    values.update(overrides)
    columns = ", ".join(values)
    placeholders = ", ".join(["%s"] * len(values))
    row = conn.execute(
        f"INSERT INTO warden.webauthn_credentials ({columns}) VALUES ({placeholders})"  # noqa: S608
        " RETURNING id",
        tuple(values.values()),
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _challenge(conn: Conn, purpose: str, user_id: uuid.UUID | None) -> None:
    conn.execute(
        "INSERT INTO warden.webauthn_challenges"
        " (challenge_hash, purpose, user_id, user_verification_required, expires_at)"
        " VALUES (%s, %s, %s, false, now() + interval '5 minutes')",
        (os.urandom(32), purpose, user_id),
    )


def _token(conn: Conn, user_id: uuid.UUID, purpose: str) -> None:
    conn.execute(
        "INSERT INTO warden.single_use_tokens (token_hash, purpose, user_id, expires_at)"
        " VALUES (%s, %s, %s, now() + interval '1 hour')",
        (os.urandom(32), purpose, user_id),
    )


def _refused(dsn: str, statement: Any) -> None:
    """``statement(conn)`` raises a check or unique violation, on its own connection."""
    with psycopg.connect(dsn) as conn, pytest.raises(psycopg.errors.IntegrityError):
        statement(conn)


def test_at_head_the_webauthn_tables_exist(migrated_dsn: str) -> None:
    assert _tables(migrated_dsn) >= WEBAUTHN_TABLES


def test_a_credential_round_trips_and_its_id_is_unique(migrated_dsn: str) -> None:
    credential_id = os.urandom(64)
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        _credential(conn, user, credential_id=credential_id, nickname="Desk key")
        other = _user(conn)
    _refused(migrated_dsn, lambda c: _credential(c, other, credential_id=credential_id))


@pytest.mark.parametrize(
    "overrides",
    [
        {"credential_id": b""},
        {"credential_id": b"\x01" * 1024},
        {"public_key": b""},
        {"sign_count": -1},
        {"sign_count": 2**32},
        {"backup_eligible": False, "backup_state": True},
        {"nickname": ""},
        {"nickname": "n" * 65},
        {"transports": None},
    ],
    ids=[
        "empty-id",
        "id-1024",
        "empty-key",
        "negative-counter",
        "counter-over-32-bits",
        "backed-up-not-eligible",
        "empty-nickname",
        "nickname-65",
        "null-transports",
    ],
)
def test_credential_constraints(migrated_dsn: str, overrides: dict[str, Any]) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
    _refused(migrated_dsn, lambda c: _credential(c, user, **overrides))


def test_a_counter_at_the_32_bit_ceiling_is_stored(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        _credential(conn, _user(conn), sign_count=2**32 - 1)


def test_a_user_handle_is_64_bytes_and_unique(migrated_dsn: str) -> None:
    handle = os.urandom(64)
    with psycopg.connect(migrated_dsn) as conn:
        user, other = _user(conn), _user(conn)
        conn.execute(
            "INSERT INTO warden.webauthn_user_handles (user_id, handle) VALUES (%s, %s)",
            (user, handle),
        )
    insert = "INSERT INTO warden.webauthn_user_handles (user_id, handle) VALUES (%s, %s)"
    _refused(migrated_dsn, lambda c: c.execute(insert, (other, handle)))
    _refused(migrated_dsn, lambda c: c.execute(insert, (user, os.urandom(64))))
    for length in (16, 63, 65):
        _refused(migrated_dsn, lambda c, n=length: c.execute(insert, (other, os.urandom(n))))


def test_challenge_constraints(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        _challenge(conn, "registration", user)
        _challenge(conn, "authentication", user)
        # A discoverable sign-in does not know its user yet.
        _challenge(conn, "authentication", None)
    _refused(migrated_dsn, lambda c: _challenge(c, "registration", None))
    _refused(migrated_dsn, lambda c: _challenge(c, "enrol", user))
    _refused(
        migrated_dsn,
        lambda c: c.execute(
            "INSERT INTO warden.webauthn_challenges"
            " (challenge_hash, purpose, user_id, user_verification_required, expires_at)"
            " VALUES (%s, 'authentication', NULL, false, now() + interval '5 minutes')",
            (os.urandom(31),),
        ),
    )


def test_deleting_a_user_removes_their_webauthn_rows(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        _credential(conn, user)
        _challenge(conn, "registration", user)
        conn.execute(
            "INSERT INTO warden.webauthn_user_handles (user_id, handle) VALUES (%s, %s)",
            (user, os.urandom(64)),
        )
        conn.execute("DELETE FROM warden.users WHERE id = %s", (user,))
        for table in sorted(WEBAUTHN_TABLES):
            row = conn.execute(
                f"SELECT count(*) FROM warden.{table} WHERE user_id = %s",  # noqa: S608
                (user,),
            ).fetchone()
            assert row == (0,), table


def test_passkey_only_and_the_passkey_registration_token_are_allowed(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "passkey_only")
        _token(conn, user, "passkey_registration")
    _refused(migrated_dsn, lambda c: _user(c, "passkey"))
    _refused(migrated_dsn, lambda c: _token(c, user, "passkey"))


def test_downgrade_removes_the_tables_and_narrows_both_checks(migrated_dsn: str) -> None:
    revision, parent = _revisions()
    # Later migrations may sit above this one; take them off first.
    downgrade(migrated_dsn, revision)
    tables = _tables(migrated_dsn)
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        _credential(conn, user)
        _token(conn, user, "invitation")
        _token(conn, user, "passkey_registration")

    downgrade(migrated_dsn, parent)
    assert current_revision(migrated_dsn) == parent
    assert _tables(migrated_dsn) == tables - WEBAUTHN_TABLES
    with psycopg.connect(migrated_dsn) as conn:
        purposes = conn.execute("SELECT purpose FROM warden.single_use_tokens").fetchall()
    # A passkey registration link means nothing below this revision, so it is removed.
    assert purposes == [("invitation",)]
    _refused(migrated_dsn, lambda c: _user(c, "passkey_only"))
    _refused(migrated_dsn, lambda c: _token(c, user, "passkey_registration"))

    migrate(migrated_dsn)
    assert current_revision(migrated_dsn) == heads()[0]
    assert _tables(migrated_dsn) == tables
    with psycopg.connect(migrated_dsn) as conn:
        _user(conn, "passkey_only")


def test_downgrade_is_refused_while_a_passkey_only_user_exists(migrated_dsn: str) -> None:
    revision, parent = _revisions()
    downgrade(migrated_dsn, revision)
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "passkey_only")
    # Below this revision the user could not exist, and no other method is
    # theirs to take: an operator must change them first.
    with pytest.raises(Exception, match="passkey_only"):
        downgrade(migrated_dsn, parent)
    assert current_revision(migrated_dsn) == revision
    assert _tables(migrated_dsn) >= WEBAUTHN_TABLES

    with psycopg.connect(migrated_dsn) as conn:
        conn.execute(
            "UPDATE warden.users SET sign_in_method = 'password_and_sso' WHERE id = %s", (user,)
        )
    downgrade(migrated_dsn, parent)
    assert current_revision(migrated_dsn) == parent
