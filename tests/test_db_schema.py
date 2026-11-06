"""Schema names other modules agree on: the audit channel, lock keys and setting keys."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from warden import db
from warden.db import schema

SRC = Path(__file__).resolve().parents[1] / "src" / "warden"

# ASCII "warden" in the top six bytes of every warden advisory lock key.
_PREFIX = 0x7761_7264_656E << 16

# The allocation table in ``warden.db.schema``: the low 16 bits of a key by
# the subsystem that owns it.
_RANGES = {
    "db and audit": range(0x0000, 0x0100),
    "identity": range(0x0100, 0x0200),
    "single sign-on": range(0x0200, 0x0300),
}


def _lock_keys() -> list[tuple[str, str, int]]:
    """Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``."""
    found = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            for target in targets:
                if isinstance(target, ast.Name) and target.id.endswith("_LOCK_KEY"):
                    literal = ast.literal_eval(value)
                    assert isinstance(literal, int), f"{path.name}: {target.id} is not an int"
                    found.append((str(path.relative_to(SRC)), target.id, literal))
    return found


def test_audit_channel_is_the_agreed_name() -> None:
    # The syslog forwarder LISTENs on this name; the recorder NOTIFYs on it.
    assert db.AUDIT_CHANNEL == "warden_audit"


def test_the_scan_finds_every_known_lock_key() -> None:
    # Keys may also be defined outside warden.db.schema (a later workstream
    # in its own range); the scan covers every module so a collision is caught.
    names = {name for _, name, _ in _lock_keys()}
    assert names >= {
        "MIGRATION_LOCK_KEY",
        "SYSLOG_FORWARDER_LOCK_KEY",
        "CHAIN_LOCK_KEY",
        "ADMINISTRATOR_LOCK_KEY",
        "SSO_SETTINGS_LOCK_KEY",
    }


def test_advisory_lock_keys_anywhere_in_warden_are_distinct() -> None:
    keys = _lock_keys()
    by_value: dict[int, list[str]] = {}
    for path, name, value in keys:
        by_value.setdefault(value, []).append(f"{path}:{name}")
    collisions = {hex(v): names for v, names in by_value.items() if len(names) > 1}
    assert not collisions, f"advisory lock keys collide: {collisions}"


@pytest.mark.parametrize(("path", "name", "value"), _lock_keys())
def test_each_lock_key_is_a_signed_bigint_in_an_allocated_range(
    path: str, name: str, value: int
) -> None:
    assert -(2**63) <= value < 2**63, name
    assert value & ~0xFFFF == _PREFIX, f"{name} lacks the warden prefix"
    low = value & 0xFFFF
    assert any(low in r for r in _RANGES.values()), f"{name} is outside the allocation table"


def test_the_known_keys_keep_their_values() -> None:
    # A changed key would stop excluding a replica still running the old value.
    assert schema.MIGRATION_LOCK_KEY == 0x7761_7264_656E_0001
    assert schema.SYSLOG_FORWARDER_LOCK_KEY == 0x7761_7264_656E_0002
    assert schema.CHAIN_LOCK_KEY == 0x7761_7264_656E_0003
    assert schema.ADMINISTRATOR_LOCK_KEY == 0x7761_7264_656E_0101
    assert schema.SSO_SETTINGS_LOCK_KEY == 0x7761_7264_656E_0201


def test_moved_names_are_importable_from_warden_db() -> None:
    assert db.CHAIN_LOCK_KEY == schema.CHAIN_LOCK_KEY
    assert db.ADMINISTRATOR_LOCK_KEY == schema.ADMINISTRATOR_LOCK_KEY
    assert db.POLICY_SETTING == "identity.session_policy"
    assert db.POLICY_CHANNEL == "warden_identity_policy"
    assert {
        "users",
        "totp_credentials",
        "recovery_codes",
        "mfa_challenges",
        "sessions",
        "refresh_tokens",
        "role_assignments",
        "sign_in_attempts",
    } == db.IDENTITY_TABLES


def test_lifecycle_and_sso_names_are_importable_from_warden_db() -> None:
    assert db.SINGLE_USE_TOKENS == "single_use_tokens"
    assert db.INVITATION_GRANTS == "invitation_grants"
    assert db.API_KEYS == "api_keys"
    assert {"single_use_tokens", "invitation_grants", "api_keys"} == db.LIFECYCLE_TABLES
    assert db.SSO_IDENTITIES == "sso_identities"
    assert db.SSO_LOGIN_TRANSACTIONS == "sso_login_transactions"
    assert db.SSO_HANDOFF_CODES == "sso_handoff_codes"
    assert {"sso_identities", "sso_login_transactions", "sso_handoff_codes"} == db.SSO_TABLES
    assert db.SSO_SETTING == "identity.sso"
    assert db.SSO_SETTINGS_LOCK_KEY == 0x7761_7264_656E_0201


def test_webauthn_names_are_importable_from_warden_db() -> None:
    assert db.WEBAUTHN_CREDENTIALS == "webauthn_credentials"
    assert db.WEBAUTHN_USER_HANDLES == "webauthn_user_handles"
    assert db.WEBAUTHN_CHALLENGES == "webauthn_challenges"
    assert {
        "webauthn_credentials",
        "webauthn_user_handles",
        "webauthn_challenges",
    } == db.WEBAUTHN_TABLES


def test_table_sets_are_disjoint() -> None:
    sets = [db.IDENTITY_TABLES, db.LIFECYCLE_TABLES, db.SSO_TABLES, db.WEBAUTHN_TABLES]
    assert sum(len(t) for t in sets) == len(frozenset().union(*sets))


def test_old_import_paths_resolve_to_the_schema_module_values() -> None:
    from warden.identity import apikeys, invitations, single_use
    from warden.identity.sso import schema as sso_schema
    from warden.identity.sso import settings as sso_settings

    assert apikeys.API_KEYS is schema.API_KEYS
    assert invitations.INVITATION_GRANTS is schema.INVITATION_GRANTS
    assert single_use.SINGLE_USE_TOKENS is schema.SINGLE_USE_TOKENS
    for name in sso_schema.__all__:
        assert getattr(sso_schema, name) is getattr(schema, name), name
    assert sso_settings.SSO_SETTINGS_LOCK_KEY is schema.SSO_SETTINGS_LOCK_KEY


def _schema_names() -> dict[str, str]:
    """String values ``warden.db.schema`` owns: table names and settings keys."""
    owned: dict[str, str] = {}
    for name in dir(schema):
        value = getattr(schema, name)
        if name.isupper() and isinstance(value, str) and name not in ("SCHEMA", "VERSION_TABLE"):
            owned[value] = name
    return owned


def test_no_module_defines_a_schema_name_of_its_own() -> None:
    # String constants are interned, so ``is`` cannot show that a module
    # imports a name rather than repeating its literal; scan the source.
    owned = _schema_names()
    strays = []
    for path in sorted(SRC.rglob("*.py")):
        relative = path.relative_to(SRC).as_posix()
        if relative == "db/schema.py" or relative.startswith("db/migrations/"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                value = node.value
                if isinstance(value, ast.Constant) and value.value in owned:
                    strays.append(f"{relative}:{node.lineno} repeats {owned[value.value]}")
    assert not strays, strays


def test_every_allocated_key_is_recorded_in_the_allocation_table() -> None:
    doc = schema.__doc__ or ""
    table_rows = [line for line in doc.splitlines() if line.startswith("| 0x...")]
    for path, name, value in _lock_keys():
        number = f"{value & 0xFFFF:04x}"
        assert any(number in row for row in table_rows), f"{path}:{name} ({number}) is not recorded"


def test_modules_use_the_schema_module_values() -> None:
    from warden.audit import chain
    from warden.identity import policy, roles

    assert chain.CHAIN_LOCK_KEY is schema.CHAIN_LOCK_KEY
    assert roles.ADMINISTRATOR_LOCK_KEY is schema.ADMINISTRATOR_LOCK_KEY
    assert policy.POLICY_SETTING is schema.POLICY_SETTING
    assert policy.POLICY_CHANNEL is schema.POLICY_CHANNEL


def test_the_allocation_table_is_published_in_the_schema_docstring() -> None:
    doc = schema.__doc__ or ""
    for owner in _RANGES:
        assert owner in doc, owner
    for prefix in ("0x...00xx", "0x...01xx", "0x...02xx"):
        assert prefix in doc, prefix


def test_syslog_cursor_setting_key() -> None:
    assert db.SYSLOG_CURSOR_SETTING == "syslog.cursor"
