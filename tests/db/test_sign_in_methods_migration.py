"""The sign-in methods migration (rulings CS13 and CS16), with a tested downgrade.

Nothing about how anyone signs in changes on upgrade: ``password_and_sso``
users follow the default, which starts as ``password_and_sso``, and
``sso_only`` and ``passkey_only`` users keep their own setting. The
downgrade restores the 0.1.x shape. The integration session may re-chain the
migration, so the tests find it and its parent by file name.
"""

from __future__ import annotations

import uuid
from typing import Any

import psycopg
import pytest

from warden.db import SCHEMA, SIGN_IN_TABLES, current_revision, downgrade, heads, migrate

pytestmark = pytest.mark.db

Conn = psycopg.Connection[tuple[Any, ...]]


def _revisions() -> tuple[str, str]:
    from alembic.script import ScriptDirectory

    from warden.db.migrate import _config

    script = ScriptDirectory.from_config(_config())
    for revision in script.walk_revisions():
        if revision.path.endswith("_sign_in_methods.py"):
            parent = revision.down_revision
            assert isinstance(parent, str)
            return revision.revision, parent
    raise AssertionError("no sign-in methods migration in the chain")


def _tables(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (SCHEMA,)
        ).fetchall()
    return {str(r[0]) for r in rows}


def _user(conn: Conn, method: str | None, status: str = "active") -> uuid.UUID:
    row = conn.execute(
        "INSERT INTO warden.users (email, status, sign_in_method) VALUES (%s, %s, %s) RETURNING id",
        (f"user-{uuid.uuid4().hex[:8]}@example.com", status, method),
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _method(conn: Conn, user_id: uuid.UUID) -> str | None:
    row = conn.execute(
        "SELECT sign_in_method FROM warden.users WHERE id = %s", (user_id,)
    ).fetchone()
    assert row is not None
    return None if row[0] is None else str(row[0])


def _refused(dsn: str, statement: Any) -> None:
    with psycopg.connect(dsn) as conn, pytest.raises(psycopg.errors.IntegrityError):
        statement(conn)


def test_at_head_the_sign_in_tables_exist_with_the_initial_settings(migrated_dsn: str) -> None:
    assert _tables(migrated_dsn) >= SIGN_IN_TABLES
    with psycopg.connect(migrated_dsn) as conn:
        rows = conn.execute(
            "SELECT default_sign_in_method, allowed_second_factors FROM warden.sign_in_settings"
        ).fetchall()
    assert rows == [("password_and_sso", ["totp", "passkey"])]


def test_upgrade_keeps_every_user_signing_in_as_before(dsn: str) -> None:
    this, parent = _revisions()
    migrate(dsn, parent)
    with psycopg.connect(dsn) as conn:
        both = _user(conn, "password_and_sso")
        invited = _user(conn, "password_and_sso", status="invited")
        sso = _user(conn, "sso_only")
        passkey = _user(conn, "passkey_only")
        before = conn.execute("SELECT id, updated_at FROM warden.users ORDER BY id").fetchall()
    migrate(dsn, this)
    with psycopg.connect(dsn) as conn:
        assert _method(conn, both) is None
        assert _method(conn, invited) is None
        assert _method(conn, sso) == "sso_only"
        assert _method(conn, passkey) == "passkey_only"
        after = conn.execute("SELECT id, updated_at FROM warden.users ORDER BY id").fetchall()
        default = conn.execute(
            "SELECT default_sign_in_method FROM warden.sign_in_settings"
        ).fetchone()
    # Those following the default follow password_and_sso, as they had it.
    assert default == ("password_and_sso",)
    assert after == before


def test_a_user_may_hold_any_of_the_four_methods_or_none(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        for method in ("password", "password_and_sso", "sso_only", "passkey_only", None):
            assert _method(conn, _user(conn, method)) == method
        row = conn.execute(
            "INSERT INTO warden.users (email, status) VALUES ('d@example.com', 'active')"
            " RETURNING sign_in_method"
        ).fetchone()
    # No column default: a user created without a method follows the default.
    assert row == (None,)
    _refused(migrated_dsn, lambda c: _user(c, "magic_link"))


@pytest.mark.parametrize(
    "assignment",
    [
        "default_sign_in_method = 'magic_link'",
        "allowed_second_factors = ARRAY['sms']",
        "allowed_second_factors = ARRAY['totp', 'sms']",
        "allowed_second_factors = ARRAY[]::text[]",
        "allowed_second_factors = ARRAY['totp', 'passkey', 'totp']",
        "updated_by = ''",
    ],
)
def test_settings_constraints(migrated_dsn: str, assignment: str) -> None:
    _refused(
        migrated_dsn,
        lambda c: c.execute(f"UPDATE warden.sign_in_settings SET {assignment}"),  # noqa: S608
    )


def test_the_settings_hold_one_row(migrated_dsn: str) -> None:
    _refused(
        migrated_dsn, lambda c: c.execute("INSERT INTO warden.sign_in_settings DEFAULT VALUES")
    )
    _refused(
        migrated_dsn,
        lambda c: c.execute("INSERT INTO warden.sign_in_settings (singleton) VALUES (false)"),
    )


def test_each_allowed_factor_set_is_stored(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        for factors in (["totp"], ["passkey"], ["passkey", "totp"]):
            conn.execute(
                "UPDATE warden.sign_in_settings SET allowed_second_factors = %s", (factors,)
            )
            row = conn.execute(
                "SELECT allowed_second_factors FROM warden.sign_in_settings"
            ).fetchone()
            assert row == (factors,)


def _pending(conn: Conn, user_id: uuid.UUID, start: str, end: str, previous: str | None) -> None:
    conn.execute(
        "INSERT INTO warden.sign_in_method_changes"
        " (user_id, from_method, to_method, previous_setting) VALUES (%s, %s, %s, %s)",
        (user_id, start, end, previous),
    )


def test_pending_change_constraints(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "passkey_only")
        _pending(conn, user, "password_and_sso", "passkey_only", None)
        other = _user(conn, None)
    # At most one per user; a change moves; methods are the four.
    _refused(migrated_dsn, lambda c: _pending(c, user, "password", "sso_only", None))
    _refused(migrated_dsn, lambda c: _pending(c, other, "password", "password", None))
    _refused(migrated_dsn, lambda c: _pending(c, other, "magic_link", "password", None))
    _refused(migrated_dsn, lambda c: _pending(c, other, "password", "magic_link", None))
    _refused(migrated_dsn, lambda c: _pending(c, other, "password", "sso_only", "magic_link"))


def test_deleting_a_user_removes_their_pending_change(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn, "passkey_only")
        _pending(conn, user, "password_and_sso", "passkey_only", None)
        conn.execute("DELETE FROM warden.users WHERE id = %s", (user,))
        row = conn.execute("SELECT count(*) FROM warden.sign_in_method_changes").fetchone()
    assert row == (0,)


def test_downgrade_restores_the_0_1_shape(dsn: str) -> None:
    _, parent = _revisions()
    migrate(dsn)
    with psycopg.connect(dsn) as conn:
        following = _user(conn, None)
        password = _user(conn, "password")
        sso = _user(conn, "sso_only")
        passkey = _user(conn, "passkey_only")
        both = _user(conn, "password_and_sso")
        # Waiting for a passkey: password_and_sso is still in force.
        waiting = _user(conn, "passkey_only")
        _pending(conn, waiting, "password_and_sso", "passkey_only", None)
        # Waiting for a password while single sign-on is in force.
        to_password = _user(conn, "password")
        _pending(conn, to_password, "sso_only", "password", "sso_only")
    downgrade(dsn, parent)
    assert current_revision(dsn) == parent
    assert not _tables(dsn) & SIGN_IN_TABLES
    with psycopg.connect(dsn) as conn:
        assert _method(conn, following) == "password_and_sso"
        assert _method(conn, password) == "password_and_sso"
        assert _method(conn, sso) == "sso_only"
        assert _method(conn, passkey) == "passkey_only"
        assert _method(conn, both) == "password_and_sso"
        assert _method(conn, waiting) == "password_and_sso"
        assert _method(conn, to_password) == "sso_only"
        row = conn.execute(
            "INSERT INTO warden.users (email, status) VALUES ('e@example.com', 'active')"
            " RETURNING sign_in_method"
        ).fetchone()
    assert row == ("password_and_sso",)
    _refused(dsn, lambda c: _user(c, "password"))
    _refused(dsn, lambda c: _user(c, None))
    # And the chain upgrades again from there.
    migrate(dsn)
    assert current_revision(dsn) == heads()[0]
