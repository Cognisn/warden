"""Password policies' migration: the whole feature's schema, with a tested downgrade.

Rulings PW0 to PW14 of 10 November 2026. The integration session may
re-chain the migration, so the tests find it and its parent by the
migration's file name rather than a revision id.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from warden.db import (
    PASSWORD_POLICY_TABLES,
    SCHEMA,
    current_revision,
    downgrade,
    heads,
    migrate,
)

pytestmark = pytest.mark.db

Conn = psycopg.Connection[tuple[Any, ...]]


def _tables(dsn: str) -> set[str]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (SCHEMA,)
        ).fetchall()
    return {str(r[0]) for r in rows}


def _columns(dsn: str) -> dict[str, set[str]]:
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns"
            " WHERE table_schema = %s",
            (SCHEMA,),
        ).fetchall()
    found: dict[str, set[str]] = {}
    for name, column in rows:
        found.setdefault(str(name), set()).add(str(column))
    return found


def _revisions() -> tuple[str, str]:
    from alembic.script import ScriptDirectory

    from warden.db.migrate import _config

    script = ScriptDirectory.from_config(_config())
    for revision in script.walk_revisions():
        if revision.path.endswith("_password_policies.py"):
            parent = revision.down_revision
            assert isinstance(parent, str)
            return revision.revision, parent
    raise AssertionError("no password policy migration in the chain")


def _user(conn: Conn) -> uuid.UUID:
    row = conn.execute(
        "INSERT INTO warden.users (email, status) VALUES (%s, 'active') RETURNING id",
        (f"user-{uuid.uuid4().hex[:8]}@example.com",),
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _policy(conn: Conn, **overrides: Any) -> uuid.UUID:
    values: dict[str, Any] = {
        "name": f"policy-{uuid.uuid4().hex[:8]}",
        "priority": None,
        "is_default": False,
        "min_length": 12,
        "max_length": 1024,
        "tiers": Jsonb([]),
    }
    if not overrides.get("is_default") and "priority" not in overrides:
        values["priority"] = int.from_bytes(os.urandom(2)) % 9999 + 1
    values.update(overrides)
    columns = ", ".join(values)
    placeholders = ", ".join(["%s"] * len(values))
    row = conn.execute(
        f"INSERT INTO warden.password_policies ({columns}) VALUES ({placeholders})"  # noqa: S608
        " RETURNING id",
        tuple(values.values()),
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _watch_list(conn: Conn, kind: str = "manual") -> uuid.UUID:
    row = conn.execute(
        "INSERT INTO warden.watch_lists (name, reason, kind) VALUES (%s, %s, %s) RETURNING id",
        (f"list-{uuid.uuid4().hex[:8]}", "This password is not allowed here", kind),
    ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _refused(dsn: str, statement: Any) -> None:
    with psycopg.connect(dsn) as conn, pytest.raises(psycopg.errors.IntegrityError):
        statement(conn)


def test_at_head_the_password_policy_tables_exist(migrated_dsn: str) -> None:
    assert _tables(migrated_dsn) >= PASSWORD_POLICY_TABLES


def test_no_column_could_hold_a_password_or_its_makeup(migrated_dsn: str) -> None:
    # Ruling PW5: only a tier's name and the expiry are stored, never a
    # password's length or makeup; PW8: the fingerprint is stored sealed.
    columns = _columns(migrated_dsn)
    forbidden = ("password_length", "length_of", "class_count", "classes_used", "plaintext")
    for name in PASSWORD_POLICY_TABLES:
        for column in columns[name]:
            assert not any(word in column for word in forbidden), f"{name}.{column}"
            assert "prefix" not in column, f"{name}.{column}"
    assert columns["password_states"] >= {"fingerprint_sealed", "fingerprint_key_id"}
    assert "fingerprint" not in columns["password_states"]
    assert columns["watch_list_entries"] == {"list_id", "hash"}


def test_exactly_one_default_and_priorities_are_unique(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        _policy(conn, is_default=True)
        _policy(conn, priority=5)
    _refused(migrated_dsn, lambda c: _policy(c, is_default=True))
    _refused(migrated_dsn, lambda c: _policy(c, priority=5))
    # A default has no priority; any other policy has one.
    _refused(migrated_dsn, lambda c: _policy(c, priority=None))


def test_policy_names_are_unique_without_regard_to_case(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        _policy(conn, name="Administrators")
    _refused(migrated_dsn, lambda c: _policy(c, name="administrators"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"min_length": 0},
        {"min_length": 20, "max_length": 10},
        {"max_length": 1025},
        {"min_classes": 6},
        {"max_repeat": 0},
        {"history_count": 25},
        {"history_count": -1},
        {"min_age_hours": -1},
        {"warning_days": -1},
        {"hibp_on_unavailable": "ignore"},
        {"passphrase_min_length": 20},
        {"passphrase_min_words": 4},
        {"tiers": Jsonb({"not": "a list"})},
        {"version": 0},
    ],
)
def test_out_of_range_policy_values_are_refused(migrated_dsn: str, overrides: Any) -> None:
    _refused(migrated_dsn, lambda c: _policy(c, **overrides))


def test_a_passphrase_rule_takes_both_length_and_words(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        _policy(conn, passphrase_min_length=20, passphrase_min_words=4)


def test_role_mappings_pins_and_attachments_follow_their_policy(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        policy = _policy(conn)
        user = _user(conn)
        listed = _watch_list(conn)
        conn.execute(
            "INSERT INTO warden.password_policy_roles (role, policy_id) VALUES ('admin', %s)",
            (policy,),
        )
        conn.execute(
            "INSERT INTO warden.password_policy_pins (user_id, policy_id) VALUES (%s, %s)",
            (user, policy),
        )
        conn.execute(
            "INSERT INTO warden.password_policy_watch_lists (policy_id, list_id) VALUES (%s, %s)",
            (policy, listed),
        )
        conn.execute("DELETE FROM warden.password_policies WHERE id = %s", (policy,))
        for name in (
            "password_policy_roles",
            "password_policy_pins",
            "password_policy_watch_lists",
        ):
            count = conn.execute(f"SELECT count(*) FROM warden.{name}").fetchone()  # noqa: S608
            assert count == (0,), name


def test_a_role_maps_to_one_policy(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        first, second = _policy(conn), _policy(conn)
        conn.execute(
            "INSERT INTO warden.password_policy_roles (role, policy_id) VALUES ('viewer', %s)",
            (first,),
        )

    def again(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.password_policy_roles (role, policy_id) VALUES ('viewer', %s)",
            (second,),
        )

    _refused(migrated_dsn, again)


def test_password_state_holds_a_reason_and_a_sealed_fingerprint_only(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        conn.execute(
            "INSERT INTO warden.password_states (user_id, tier, password_set_at, expires_at,"
            " change_reason, fingerprint_sealed, fingerprint_key_id)"
            " VALUES (%s, 'standard', now(), now() + interval '90 days', 'expired', %s, 'k1')",
            (user, os.urandom(48)),
        )

    def bad_reason(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.password_states (user_id, change_reason) VALUES (%s, 'whim')",
            (_user(c),),
        )

    def fingerprint_without_key(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.password_states (user_id, fingerprint_sealed) VALUES (%s, %s)",
            (_user(c), os.urandom(48)),
        )

    def unsealed_sized_fingerprint(c: Conn) -> None:
        # A bare SHA-1 is 20 bytes; a sealed one carries a nonce and a tag.
        c.execute(
            "INSERT INTO warden.password_states (user_id, fingerprint_sealed, fingerprint_key_id)"
            " VALUES (%s, %s, 'k1')",
            (_user(c), os.urandom(20)),
        )

    def source_without_reason(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.password_states (user_id, watch_list_source) VALUES (%s, 'list')",
            (_user(c),),
        )

    for statement in (
        bad_reason,
        fingerprint_without_key,
        unsealed_sized_fingerprint,
        source_without_reason,
    ):
        _refused(migrated_dsn, statement)


def test_history_holds_argon2id_hashes_only(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        conn.execute(
            "INSERT INTO warden.password_history (user_id, password_hash) VALUES (%s, %s)",
            (user, "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g"),
        )

    def legacy(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.password_history (user_id, password_hash) VALUES (%s, %s)",
            (_user(c), "pbkdf2:sha256:1000$salt$" + "0" * 64),
        )

    _refused(migrated_dsn, legacy)


def test_watch_list_entries_are_twenty_byte_hashes_keyed_by_list(migrated_dsn: str) -> None:
    digest = os.urandom(20)
    with psycopg.connect(migrated_dsn) as conn:
        listed = _watch_list(conn, "imported")
        conn.execute(
            "INSERT INTO warden.watch_list_entries (list_id, hash) VALUES (%s, %s)",
            (listed, digest),
        )

    def duplicate(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.watch_list_entries (list_id, hash) VALUES (%s, %s)",
            (listed, digest),
        )

    def short(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.watch_list_entries (list_id, hash) VALUES (%s, %s)",
            (listed, os.urandom(19)),
        )

    def bad_kind(c: Conn) -> None:
        _watch_list(c, "builtin")

    for statement in (duplicate, short, bad_kind):
        _refused(migrated_dsn, statement)


def test_a_change_challenge_is_hashed_and_bounded(migrated_dsn: str) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        conn.execute(
            "INSERT INTO warden.password_change_challenges (token_hash, user_id, reason,"
            " expires_at) VALUES (%s, %s, 'watch_list', now() + interval '5 minutes')",
            (os.urandom(32), user),
        )

    def bad_reason(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.password_change_challenges (token_hash, user_id, reason,"
            " expires_at) VALUES (%s, %s, 'whim', now() + interval '5 minutes')",
            (os.urandom(32), _user(c)),
        )

    def short_hash(c: Conn) -> None:
        c.execute(
            "INSERT INTO warden.password_change_challenges (token_hash, user_id, reason,"
            " expires_at) VALUES (%s, %s, 'expired', now() + interval '5 minutes')",
            (os.urandom(16), _user(c)),
        )

    for statement in (bad_reason, short_hash):
        _refused(migrated_dsn, statement)


def test_downgrade_removes_the_tables_and_upgrade_restores_them(migrated_dsn: str) -> None:
    revision, parent = _revisions()
    assert current_revision(migrated_dsn) in heads()
    with psycopg.connect(migrated_dsn) as conn:
        user = _user(conn)
        policy = _policy(conn, is_default=True)
        conn.execute(
            "INSERT INTO warden.password_policy_pins (user_id, policy_id) VALUES (%s, %s)",
            (user, policy),
        )
        conn.execute(
            "INSERT INTO warden.password_history (user_id, password_hash) VALUES (%s, %s)",
            (user, "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g"),
        )
    downgrade(migrated_dsn, parent)
    assert current_revision(migrated_dsn) == parent
    assert not (_tables(migrated_dsn) & PASSWORD_POLICY_TABLES)
    migrate(migrated_dsn)
    assert current_revision(migrated_dsn) == revision
    assert _tables(migrated_dsn) >= PASSWORD_POLICY_TABLES
