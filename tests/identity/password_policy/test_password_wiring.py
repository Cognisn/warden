"""Identity gains the password policy services at construction, with no I/O.

Wave 16 changed no behaviour; wave 17 puts the policies in force, so a
common password is now refused on the seeded default (ruling PW12)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from identity_support import FAST_HASHER, PASSWORD, MemorySecrets

from warden.config import parse_config
from warden.db import Database
from warden.identity import (
    Identity,
    PasswordChangeChallenges,
    PasswordHistory,
    PasswordPolicies,
    PasswordRecheck,
    PasswordRejected,
    PasswordStates,
    PermissionRegistry,
    SecretKeyError,
    WatchLists,
)
from warden.identity.crypto import TOTP_KEY_SECRET, new_totp_key
from warden.identity.password_policy import Fingerprints
from warden.keys import KeyStore

pytestmark = pytest.mark.db


def test_the_services_are_attributes_built_at_construction(identity: Identity) -> None:
    assert isinstance(identity.password_policies, PasswordPolicies)
    assert isinstance(identity.watch_lists, WatchLists)
    assert isinstance(identity.password_history, PasswordHistory)
    assert isinstance(identity.password_states, PasswordStates)
    assert isinstance(identity.password_challenges, PasswordChangeChallenges)
    assert isinstance(identity.password_fingerprints, Fingerprints)
    assert isinstance(identity.password_recheck, PasswordRecheck)
    # No fingerprint key configured: no policy may enable the fingerprint.
    assert not identity.password_fingerprints.available
    assert not identity.password_policies.fingerprint_available


async def test_construction_writes_nothing_and_the_seeded_default_refuses_a_common_password(
    identity: Identity, make_user: Any, db: Database
) -> None:
    async with db.connection() as conn:
        for name in ("password_policies", "password_states", "password_history"):
            cur = await conn.execute(f"SELECT count(*) FROM warden.{name}")  # noqa: S608
            assert await cur.fetchone() == (0,), name
    # Wave 17 puts the seeded default in force (ruling PW12).
    with pytest.raises(PasswordRejected) as refused:
        await make_user(password="password1234")
    assert [f.code for f in refused.value.failures] == ["watch_list"]


async def test_a_configured_fingerprint_key_must_be_in_the_secrets_store(
    db: Database, permissions: PermissionRegistry
) -> None:
    config = parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "passwords": {"fingerprint_key_secret": "warden.password-fingerprint-key"},
        }
    )
    secrets = MemorySecrets()
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    keys = KeyStore(db, secrets)
    with pytest.raises(SecretKeyError) as caught:
        Identity(config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    assert "warden.password-fingerprint-key" in str(caught.value)
    secrets.set("warden.password-fingerprint-key", new_totp_key())
    identity = Identity(config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    assert identity.password_fingerprints.available
    assert identity.password_policies.fingerprint_available


async def test_running_also_listens_for_password_policy_changes(identity: Identity) -> None:
    assert not identity.password_policies.listening
    async with identity.running():
        for _ in range(100):
            if identity.password_policies.listening:
                break
            await asyncio.sleep(0.05)
        assert identity.password_policies.listening
        assert identity.policy.listening
    assert not identity.password_policies.listening


async def test_prune_trims_history_and_expired_change_challenges(
    identity: Identity, make_user: Any, db: Database
) -> None:
    # Without a password: setting one would keep it in the history too.
    user = await make_user(password=None)
    for index in range(3):
        await identity.password_history.record(
            user.id, await FAST_HASHER.hash(f"{PASSWORD}{index}")
        )
    async with db.transaction() as tx:
        from warden.identity.password_policy import ChangeReason

        await identity.password_challenges.create(tx, user.id, ChangeReason.EXPIRED)
        await tx.execute(
            "UPDATE warden.password_change_challenges"
            " SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'"
        )
    report = await identity.prune()
    assert report.password_history == 3  # the seeded default keeps none
    assert report.password_change_challenges == 1
    assert report.total >= 4
