"""Recheck (ruling PW8): sealed fingerprints compared with watch lists that changed later."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

import httpx
import pytest
from identity_support import FAST_HASHER, MemorySecrets, audit_rows

from warden.audit import ActionRegistry
from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry, User
from warden.identity.crypto import TOTP_KEY_SECRET, new_totp_key
from warden.identity.password_policy import (
    ChangeReason,
    PasswordRules,
    PolicySettings,
    WatchListKind,
    WatchListSource,
)
from warden.identity.password_policy.hibp import HibpRangeClient
from warden.keys import KeyStore

pytestmark = pytest.mark.db

FINGERPRINT_KEY = "warden.password-fingerprint-key"
LISTED = "a synthetic password later listed"
LEAKED = "a synthetic password later breached"
FINE = "a synthetic password nobody lists"


def _config(previous: str | None = None) -> WardenConfig:
    passwords = {"fingerprint_key_secret": FINGERPRINT_KEY}
    if previous is not None:
        passwords["fingerprint_previous_key_secret"] = previous
    return parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "identity": {"require_mfa": False},
            "passwords": passwords,
        }
    )


class Range:
    def __init__(self) -> None:
        self.prefixes: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        prefix = request.url.path.rsplit("/", 1)[1]
        self.prefixes.append(prefix)
        digest = hashlib.sha1(LEAKED.encode()).hexdigest().upper()  # noqa: S324
        if prefix == digest[:5]:
            return httpx.Response(200, text=f"{digest[5:]}:7")
        return httpx.Response(200, text=f"{'0' * 35}:0")


@pytest.fixture
def range_api() -> Range:
    return Range()


@pytest.fixture
async def fp_identity(
    db: Database,
    permissions: PermissionRegistry,
    audit_registry: ActionRegistry,
    range_api: Range,
) -> Identity:
    secrets = MemorySecrets()
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    secrets.set(FINGERPRINT_KEY, new_totp_key())
    keys = KeyStore(db, secrets)
    await keys.rotate()
    identity = Identity(_config(), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    identity.watch_lists.hibp = HibpRangeClient(
        identity.config.passwords, transport=httpx.MockTransport(range_api)
    )
    return identity


async def _user(identity: Identity, password: str, roles: tuple[str, ...] = ()) -> User:
    user = await identity.users.create(
        f"user-{uuid.uuid4().hex[:8]}@example.com",
        actor="test",
        password=password,
    )
    for role in roles:
        await identity.roles.assign(user.id, role, actor="test")
    sealed = identity.password_fingerprints.seal(user.id, password)
    await identity.password_states.store_fingerprint(user.id, sealed)
    return user


async def test_a_listed_fingerprint_flags_a_change_and_others_are_left(
    fp_identity: Identity, db: Database, range_api: Range
) -> None:
    identity = fp_identity
    listed = await identity.watch_lists.create("Local", "Banned", WatchListKind.MANUAL, actor="a")
    policy = await identity.password_policies.create(
        PolicySettings(
            name="Fingerprinted",
            rules=PasswordRules(min_length=12),
            include_builtin=False,
            watch_list_ids=(listed.id,),
            hibp_enabled=True,
            fingerprint_enabled=True,
            end_sessions_on_match=True,
        ),
        priority=1,
        actor="a",
    )
    await identity.password_policies.map_role("viewer", policy.id, actor="a")
    on_list = await _user(identity, LISTED, ("viewer",))
    breached = await _user(identity, LEAKED, ("viewer",))
    fine = await _user(identity, FINE, ("viewer",))
    unfingerprinted = await _user(identity, FINE + " too", ())  # default policy: no fingerprint
    signed_in = await identity.sign_in(on_list.email, LISTED)
    assert signed_in.tokens is not None
    await identity.watch_lists.add_entries(listed.id, [LISTED], actor="a")

    report = await identity.password_recheck.run(actor="scheduler")

    assert (report.checked, report.matched, report.flagged) == (3, 2, 2)
    assert report.sessions_ended == 1
    assert report.unopened == 0 and report.hibp_unavailable == 0
    state = await identity.password_states.get(on_list.id)
    assert state is not None and state.change_reason == ChangeReason.WATCH_LIST
    assert state.watch_list_source == WatchListSource.LIST and state.watch_list_id == listed.id
    state = await identity.password_states.get(breached.id)
    assert state is not None and state.watch_list_source == WatchListSource.HIBP
    assert (await identity.password_states.get(fine.id)).change_reason is None  # type: ignore[union-attr]
    assert await identity.password_states.get(unfingerprinted.id) is None or (
        (await identity.password_states.get(unfingerprinted.id)).change_reason is None  # type: ignore[union-attr]
    )
    # The flagged user's live session ended.
    with pytest.raises(Exception):  # noqa: B017
        await identity.refresh(signed_in.tokens.refresh_token)

    required = await audit_rows(db, "warden.identity.password.change_required")
    assert {r["resource_id"] for r in required} == {str(on_list.id), str(breached.id)}
    for row in required:
        assert row["details"]["reason"] == "watch_list"
        assert row["details"]["trigger"] == "recheck"
    (done,) = await audit_rows(db, "warden.identity.password.recheck_completed")
    assert done["actor"] == "scheduler"
    assert done["details"] == {
        "checked": 3,
        "matched": 2,
        "flagged": 2,
        "sessions_ended": 1,
        "resealed": 0,
        "unopened": 0,
        "hibp_unavailable": 0,
        # The locally listed password matched before the range API was needed.
        "hibp_lookups": 2,
        "policy_id": None,
        "end_sessions": "policy",
    }
    # A second run finds the same matches but flags no one again.
    again = await identity.password_recheck.run(actor="scheduler")
    assert (again.matched, again.flagged) == (2, 0)


async def test_one_run_asks_the_range_api_once_per_prefix(
    fp_identity: Identity, range_api: Range
) -> None:
    identity = fp_identity
    policy = await identity.password_policies.create(
        PolicySettings(
            name="Fingerprinted",
            rules=PasswordRules(min_length=12),
            include_builtin=False,
            hibp_enabled=True,
            fingerprint_enabled=True,
        ),
        priority=1,
        actor="a",
    )
    await identity.password_policies.map_role("viewer", policy.id, actor="a")
    # Two users share a password, so three fingerprints fall under two prefixes.
    for password in (FINE, FINE, LEAKED):
        await _user(identity, password, ("viewer",))
    report = await identity.password_recheck.run(actor="a")
    assert report.checked == 3 and report.matched == 1
    assert sorted(range_api.prefixes) == sorted(
        {hashlib.sha1(p.encode()).hexdigest().upper()[:5] for p in (FINE, LEAKED)}  # noqa: S324
    )
    assert report.hibp_lookups == 2


async def test_a_fingerprint_sealed_with_the_previous_key_is_resealed(
    db: Database, permissions: PermissionRegistry, range_api: Range
) -> None:
    secrets = MemorySecrets()
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    old = new_totp_key()
    secrets.set(FINGERPRINT_KEY, old)
    keys = KeyStore(db, secrets)
    await keys.rotate()
    before = Identity(_config(), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    policy = await before.password_policies.create(
        PolicySettings(
            name="Fingerprinted",
            rules=PasswordRules(min_length=12),
            include_builtin=False,
            fingerprint_enabled=True,
        ),
        priority=1,
        actor="a",
    )
    await before.password_policies.map_role("viewer", policy.id, actor="a")
    user = await _user(before, FINE, ("viewer",))
    sealed = await before.password_states.fingerprint(user.id)
    # Rotate: the new key is current, the old one previous.
    rotated = MemorySecrets()
    rotated.values = dict(secrets.values)
    rotated.set(FINGERPRINT_KEY, new_totp_key())
    rotated.set(FINGERPRINT_KEY + ".previous", old)
    config = _config(previous=FINGERPRINT_KEY + ".previous")
    after = Identity(config, db, keys, permissions, secrets=rotated, hasher=FAST_HASHER)
    report = await after.password_recheck.run(actor="a")
    assert (report.checked, report.resealed, report.unopened) == (1, 1, 0)
    resealed = await after.password_states.fingerprint(user.id)
    assert resealed is not None and sealed is not None
    assert resealed.key_id == after.password_fingerprints.current_key_id != sealed.key_id


async def test_without_a_fingerprint_key_recheck_checks_no_one(
    identity: Identity, make_user: Any, db: Database
) -> None:
    await make_user()
    report = await identity.password_recheck.run(actor="a")
    assert report.checked == 0 and report.matched == 0
    (done,) = await audit_rows(db, "warden.identity.password.recheck_completed")
    assert done["details"]["checked"] == 0


# Wave 17: one policy only, and an override that never ends sessions.


async def _two_policies(identity: Identity, *, entry: bool = True) -> tuple[Any, Any, Any]:
    listed = await identity.watch_lists.create("Local", "Banned", WatchListKind.MANUAL, actor="a")
    policies = []
    for priority, (name, role) in enumerate((("First", "viewer"), ("Second", "analyst")), 1):
        policy = await identity.password_policies.create(
            PolicySettings(
                name=name,
                rules=PasswordRules(min_length=12),
                include_builtin=False,
                watch_list_ids=(listed.id,),
                fingerprint_enabled=True,
                end_sessions_on_match=True,
            ),
            priority=priority,
            actor="a",
        )
        await identity.password_policies.map_role(role, policy.id, actor="a")
        policies.append(policy)
    if entry:
        await identity.watch_lists.add_entries(listed.id, [LISTED], actor="a")
    return listed, policies[0], policies[1]


async def test_a_run_can_be_limited_to_one_policy(fp_identity: Identity, db: Database) -> None:
    identity = fp_identity
    _, _, second = await _two_policies(identity)
    under_first = await _user(identity, LISTED, ("viewer",))
    under_second = await _user(identity, LISTED, ("analyst",))

    report = await identity.password_recheck.run(actor="a", policy_id=second.id)

    assert (report.checked, report.matched, report.flagged) == (1, 1, 1)
    flagged = await identity.password_states.get(under_second.id)
    assert flagged is not None and flagged.change_reason == ChangeReason.WATCH_LIST
    left = await identity.password_states.get(under_first.id)
    assert left is not None and left.change_reason is None
    (done,) = await audit_rows(db, "warden.identity.password.recheck_completed")
    assert done["details"]["policy_id"] == str(second.id)
    assert done["details"]["end_sessions"] == "policy"


async def test_the_override_keeps_sessions_the_policy_would_end(
    fp_identity: Identity, db: Database
) -> None:
    identity = fp_identity
    # Sign in before the entry is added: sign-in checks the policy's watch
    # lists (0.1.0b20), as the wave 16 test above does.
    listed, _, _ = await _two_policies(identity, entry=False)
    user = await _user(identity, LISTED, ("viewer",))
    signed_in = await identity.sign_in(user.email, LISTED)
    assert signed_in.tokens is not None
    await identity.watch_lists.add_entries(listed.id, [LISTED], actor="a")

    report = await identity.password_recheck.run(actor="a", end_sessions=False)

    assert (report.flagged, report.sessions_ended) == (1, 0)
    refreshed = await identity.refresh(signed_in.tokens.refresh_token)
    assert refreshed is not None
    (done,) = await audit_rows(db, "warden.identity.password.recheck_completed")
    assert done["details"]["end_sessions"] == "off"
    assert done["details"]["policy_id"] is None
