"""warden passwords import and recheck against a real database (rulings PW7 and PW8).

The CLI runs in a worker thread (it starts its own event loop) against the
same migrated database the test's identity uses.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import uuid
from pathlib import Path
from typing import Any

import pytest
from identity_support import FAST_HASHER, MemorySecrets, audit_rows

from warden.audit import ActionRegistry
from warden.cli import main
from warden.config import parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry, User
from warden.identity.crypto import TOTP_KEY_SECRET, new_totp_key
from warden.identity.password_policy import (
    ChangeReason,
    PasswordRules,
    PolicySettings,
    WatchListKind,
)
from warden.keys import KeyStore

pytestmark = pytest.mark.db

FINGERPRINT_KEY = "warden.password-fingerprint-key"
HTTP = {
    "public_base_url": "https://app.example.com",
    "accept_invitation_link": "https://app.example.com/accept?t={token}",
    "reset_password_link": "https://app.example.com/reset?t={token}",
}
LISTED = "a synthetic password later listed"
FINE = "a synthetic password nobody lists"


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest().upper()  # noqa: S324


class FakeSettings:
    def __init__(self, tree: dict[str, Any]) -> None:
        self._tree = tree

    def get_section(self, prefix: str) -> dict[str, Any]:
        return copy.deepcopy(self._tree.get(prefix, {}))


def _settings(dsn: str) -> FakeSettings:
    return FakeSettings(
        {
            "warden": {
                "http": dict(HTTP),
                "db": {"dsn": dsn},
                "identity": {"require_mfa": False},
                "passwords": {"fingerprint_key_secret": FINGERPRINT_KEY},
            }
        }
    )


@pytest.fixture
def cli_secrets() -> MemorySecrets:
    secrets = MemorySecrets()
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    secrets.set(FINGERPRINT_KEY, new_totp_key())
    return secrets


@pytest.fixture
async def fp_identity(
    db: Database,
    permissions: PermissionRegistry,
    audit_registry: ActionRegistry,
    cli_secrets: MemorySecrets,
) -> Identity:
    keys = KeyStore(db, cli_secrets)
    await keys.rotate()
    config = parse_config(
        {
            "http": dict(HTTP),
            "identity": {"require_mfa": False},
            "passwords": {"fingerprint_key_secret": FINGERPRINT_KEY},
        }
    )
    return Identity(config, db, keys, permissions, secrets=cli_secrets, hasher=FAST_HASHER)


async def run_cli(
    argv: list[str],
    dsn: str,
    secrets: MemorySecrets,
    permissions: PermissionRegistry | None = None,
) -> int:
    code: int = await asyncio.to_thread(
        main, argv, settings=_settings(dsn), secrets=secrets, permissions=permissions
    )
    return code


async def _entries(db: Database, list_id: uuid.UUID) -> set[str]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT upper(encode(hash, 'hex')) FROM warden.watch_list_entries WHERE list_id = %s",
            (list_id,),
        )
        return {r[0] for r in await cur.fetchall()}


def _write(path: Path, lines: list[str]) -> Path:
    path.write_text("".join(f"{line}\r\n" for line in lines), encoding="ascii", newline="")
    return path


# Import


async def test_import_creates_streams_and_prints_counts(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    tmp_path: Path,
    db: Database,
    capsys: pytest.CaptureFixture[str],
) -> None:
    words = [f"synthetic-breached-{n}" for n in range(5)]
    path = _write(tmp_path / "pwned.txt", [f"{_sha1(w)}:{n + 1}" for n, w in enumerate(words)])
    argv = ["passwords", "import", "--list", "Breaches", "--file", str(path), "--create",
            "--reason", "This password has appeared in a breach", "--actor", "ops"]  # fmt: skip
    assert await run_cli(argv, migrated_dsn, cli_secrets) == 0
    (listed,) = await fp_identity.watch_lists.list()
    assert listed.name == "Breaches" and listed.kind is WatchListKind.IMPORTED
    assert await _entries(db, listed.id) == {_sha1(w) for w in words}
    out = capsys.readouterr().out
    assert out == (
        f"created watch list {listed.id}\n"
        f"imported 5 hashes into watch list {listed.id} from 5 lines (0 below the threshold)\n"
    )
    (row,) = await audit_rows(db, "warden.identity.watch_list.imported")
    assert row["actor"] == "ops" and row["outcome"] == "success"
    assert row["details"] == {"imported": 5, "below_threshold": 0, "lines": 5, "threshold": None}
    for word in words:
        assert _sha1(word) not in out and _sha1(word) not in repr(row)


async def test_import_with_a_threshold_keeps_only_frequent_hashes(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    tmp_path: Path,
    db: Database,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listed = await fp_identity.watch_lists.create(
        "Breaches", "r", WatchListKind.IMPORTED, actor="a"
    )
    lines = [f"{_sha1('rare')}:1", f"{_sha1('common')}:50", f"{_sha1('edge')}:10", ""]
    path = _write(tmp_path / "pwned.txt", lines)
    argv = ["passwords", "import", "--list", "Breaches", "--file", str(path), "--threshold", "10"]
    assert await run_cli(argv, migrated_dsn, cli_secrets) == 0
    assert await _entries(db, listed.id) == {_sha1("common"), _sha1("edge")}
    assert capsys.readouterr().out == (
        f"imported 2 hashes into watch list {listed.id} from 3 lines (1 below the threshold)\n"
    )
    assert (await fp_identity.watch_lists.get(listed.id)).import_threshold == 10


async def test_a_reimport_replaces_the_list_in_place(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    tmp_path: Path,
    db: Database,
) -> None:
    listed = await fp_identity.watch_lists.create(
        "Breaches", "r", WatchListKind.IMPORTED, actor="a"
    )
    first = _write(tmp_path / "one.txt", [f"{_sha1('old-1')}:2", f"{_sha1('old-2')}:2"])
    second = _write(tmp_path / "two.txt", [f"{_sha1('new-1')}:2"])
    for path in (first, second):
        argv = ["passwords", "import", "--list", "Breaches", "--file", str(path)]
        assert await run_cli(argv, migrated_dsn, cli_secrets) == 0
    assert await _entries(db, listed.id) == {_sha1("new-1")}
    after = await fp_identity.watch_lists.get(listed.id)
    assert after.id == listed.id and after.entry_count == 1


async def test_a_malformed_line_is_refused_with_its_number_and_the_list_is_unchanged(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    tmp_path: Path,
    db: Database,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listed = await fp_identity.watch_lists.create(
        "Breaches", "r", WatchListKind.IMPORTED, actor="a"
    )
    good = _write(tmp_path / "good.txt", [f"{_sha1('kept')}:2"])
    argv = ["passwords", "import", "--list", "Breaches", "--file", str(good)]
    assert await run_cli(argv, migrated_dsn, cli_secrets) == 0
    capsys.readouterr()
    # Enough valid lines before the bad one that some reach the database first.
    lines = [f"{_sha1(f'staged-{n}')}:2" for n in range(6000)]
    lines.append("not a hash line synthetic-secret-candidate")
    bad = _write(tmp_path / "bad.txt", lines)
    argv = ["passwords", "import", "--list", "Breaches", "--file", str(bad)]
    assert await run_cli(argv, migrated_dsn, cli_secrets) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "warden passwords import: a line is not in HIBP's downloader format (line 6001)\n"
    )
    assert "synthetic-secret-candidate" not in captured.err
    assert await _entries(db, listed.id) == {_sha1("kept")}
    assert (await fp_identity.watch_lists.get(listed.id)).entry_count == 1
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.watch_list_staging")
        assert (await cur.fetchone()) == (0,)
    failed = [r for r in await audit_rows(db, "warden.identity.watch_list.imported")]
    assert failed[-1]["outcome"] == "failure" and failed[-1]["details"] == {"line": 6001}


async def test_import_without_the_list_or_into_a_manual_list_is_refused(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write(tmp_path / "pwned.txt", [f"{_sha1('x')}:2"])
    argv = ["passwords", "import", "--list", "Missing", "--file", str(path)]
    assert await run_cli(argv, migrated_dsn, cli_secrets) == 1
    assert capsys.readouterr().err == (
        "warden passwords import: no watch list has that name;"
        " pass --create --reason to create it\n"
    )
    await fp_identity.watch_lists.create("Manual", "r", WatchListKind.MANUAL, actor="a")
    argv = ["passwords", "import", "--list", "Manual", "--file", str(path)]
    assert await run_cli(argv, migrated_dsn, cli_secrets) == 1
    assert capsys.readouterr().err == (
        "warden passwords import: only an imported watch list takes imports\n"
    )


# Recheck


async def _user(identity: Identity, password: str, roles: tuple[str, ...] = ()) -> User:
    user = await identity.users.create(
        f"user-{uuid.uuid4().hex[:8]}@example.com", actor="test", password=password
    )
    for role in roles:
        await identity.roles.assign(user.id, role, actor="test")
    sealed = identity.password_fingerprints.seal(user.id, password)
    await identity.password_states.store_fingerprint(user.id, sealed)
    return user


async def _banned(identity: Identity) -> Any:
    return await identity.watch_lists.create("Local", "Banned", WatchListKind.MANUAL, actor="a")


async def _policy(identity: Identity, *, end_sessions: bool, listed: Any = None) -> Any:
    # With ``listed`` given, the caller adds the entry itself: sign-in checks
    # the policy's watch lists (0.1.0b20), so a session must be made first.
    if listed is None:
        listed = await _banned(identity)
        await identity.watch_lists.add_entries(listed.id, [LISTED], actor="a")
    policy = await identity.password_policies.create(
        PolicySettings(
            name="Fingerprinted",
            rules=PasswordRules(min_length=12),
            include_builtin=False,
            watch_list_ids=(listed.id,),
            fingerprint_enabled=True,
            end_sessions_on_match=end_sessions,
        ),
        priority=1,
        actor="a",
    )
    await identity.password_policies.map_role("viewer", policy.id, actor="a")
    return policy


async def test_recheck_flags_a_match_ends_sessions_and_prints_counts_only(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    permissions: PermissionRegistry,
    db: Database,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identity = fp_identity
    listed = await _banned(identity)
    await _policy(identity, end_sessions=True, listed=listed)
    matching = await _user(identity, LISTED, ("viewer",))
    other = await _user(identity, FINE, ("viewer",))
    signed_in = await identity.sign_in(matching.email, LISTED)
    assert signed_in.tokens is not None
    await identity.watch_lists.add_entries(listed.id, [LISTED], actor="a")

    argv = ["passwords", "recheck", "--actor", "scheduler"]
    assert await run_cli(argv, migrated_dsn, cli_secrets, permissions) == 0

    out = capsys.readouterr().out
    assert out == (
        "rechecked 2 passwords: 1 matched, 1 newly required to change, 1 sessions ended,"
        " 0 resealed, 0 did not open, 0 range checks unavailable\n"
    )
    for fragment in (str(matching.id), matching.email, LISTED, _sha1(LISTED)):
        assert fragment not in out
    flagged = await identity.password_states.get(matching.id)
    assert flagged is not None and flagged.change_reason is ChangeReason.WATCH_LIST
    left = await identity.password_states.get(other.id)
    assert left is not None and left.change_reason is None
    with pytest.raises(Exception):  # noqa: B017
        await identity.refresh(signed_in.tokens.refresh_token)
    (done,) = await audit_rows(db, "warden.identity.password.recheck_completed")
    assert done["actor"] == "scheduler" and done["details"]["end_sessions"] == "policy"


async def test_recheck_override_keeps_sessions_and_policy_limits_the_run(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    permissions: PermissionRegistry,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identity = fp_identity
    listed = await _banned(identity)
    policy = await _policy(identity, end_sessions=True, listed=listed)
    matching = await _user(identity, LISTED, ("viewer",))
    default_user = await _user(identity, LISTED)  # the default policy has no fingerprint
    signed_in = await identity.sign_in(matching.email, LISTED)
    assert signed_in.tokens is not None
    await identity.watch_lists.add_entries(listed.id, [LISTED], actor="a")

    missing = ["passwords", "recheck", "--policy", "Nope"]
    assert await run_cli(missing, migrated_dsn, cli_secrets, permissions) == 1
    assert capsys.readouterr().err == (
        "warden passwords recheck: no password policy has that name\n"
    )
    argv = ["passwords", "recheck", "--policy", policy.name, "--end-sessions-override", "off"]
    assert await run_cli(argv, migrated_dsn, cli_secrets, permissions) == 0
    assert capsys.readouterr().out.startswith("rechecked 1 passwords: 1 matched, 1 newly")
    assert await identity.refresh(signed_in.tokens.refresh_token) is not None
    state = await identity.password_states.get(default_user.id)
    assert state is None or state.change_reason is None


async def test_recheck_without_the_products_roles_honours_every_mapped_role(
    fp_identity: Identity,
    migrated_dsn: str,
    cli_secrets: MemorySecrets,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A product that runs the stock command passes no registry: the roles that
    # have mappings are taken as declared.
    identity = fp_identity
    await _policy(identity, end_sessions=False)
    matching = await _user(identity, LISTED, ("viewer",))
    assert await run_cli(["passwords", "recheck"], migrated_dsn, cli_secrets) == 0
    assert capsys.readouterr().out.startswith("rechecked 1 passwords: 1 matched")
    state = await identity.password_states.get(matching.id)
    assert state is not None and state.change_reason is ChangeReason.WATCH_LIST
