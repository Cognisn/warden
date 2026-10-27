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
