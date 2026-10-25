"""TOTP secrets are sealed at rest, bound to their user, and survive key rotation."""

from __future__ import annotations

import pytest
from identity_support import FAST_HASHER, PASSWORD, MemorySecrets, UserFactory, current_code

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, PermissionRegistry, TokenPair
from warden.identity.crypto import (
    TOTP_KEY_SECRET,
    TOTP_PREVIOUS_KEY_SECRET,
    SecretBox,
    SecretKeyError,
    new_totp_key,
)
from warden.keys import KeyStore

pytestmark = pytest.mark.db


async def _row(db: Database, user_id: object) -> tuple[bytes, str]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT secret_sealed, key_id FROM warden.totp_credentials WHERE user_id = %s",
            (user_id,),
        )
        row = await cur.fetchone()
    assert row is not None
    return bytes(row[0]), row[1]


async def test_the_stored_secret_is_sealed(
    identity: Identity, make_user: UserFactory, db: Database, secrets: MemorySecrets
) -> None:
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    sealed, key_id = await _row(db, user.id)
    assert enrolment.secret not in sealed
    assert key_id == SecretBox.from_secrets(secrets).current_key_id
    codes = await identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret), actor="t")
    assert codes is not None


def test_identity_refuses_to_start_without_a_totp_key(
    config: WardenConfig, db: Database, keys: KeyStore, permissions: PermissionRegistry
) -> None:
    with pytest.raises(SecretKeyError, match=TOTP_KEY_SECRET):
        Identity(config, db, keys, permissions, secrets=MemorySecrets(), hasher=FAST_HASHER)


async def test_a_secret_copied_to_another_user_does_not_open(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    alice, mallory = await make_user(), await make_user()
    alice_enrolment = await identity.mfa.begin_enrolment(alice.id, account=alice.email)
    await identity.mfa.begin_enrolment(mallory.id, account=mallory.email)
    sealed, key_id = await _row(db, alice.id)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.totp_credentials SET secret_sealed = %s, key_id = %s WHERE user_id = %s",
            (sealed, key_id, mallory.id),
        )
    code = current_code(alice_enrolment.secret)
    assert await identity.mfa.confirm_enrolment(mallory.id, code, actor="t") is None
    assert await identity.mfa.confirm_enrolment(alice.id, code, actor="t") is not None


async def test_rotation_keeps_enrolments_working_and_reseals(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    make_user: UserFactory,
    identity: Identity,
) -> None:
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    await identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret), actor="t")
    old_key = secrets.get(TOTP_KEY_SECRET)
    assert old_key is not None
    _, old_id = await _row(db, user.id)

    secrets.set(TOTP_PREVIOUS_KEY_SECRET, old_key)
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    rotated = Identity(config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    challenge = await rotated.sign_in(user.email, PASSWORD)
    assert challenge.challenge is not None
    result = await rotated.verify_totp(challenge.challenge.token, current_code(enrolment.secret, 1))
    assert isinstance(result, TokenPair)

    assert await rotated.mfa.reseal_all() == 1
    _, new_id = await _row(db, user.id)
    assert new_id != old_id
    assert await rotated.mfa.reseal_all() == 0

    del secrets.values[TOTP_PREVIOUS_KEY_SECRET]
    only_new = Identity(config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    assert await only_new.mfa.has_confirmed_totp(user.id)
    challenge = await only_new.sign_in(user.email, PASSWORD)
    assert challenge.challenge is not None
    with pytest.raises(AuthenticationRefused):  # the step was used above, so a replay fails
        await only_new.verify_totp(challenge.challenge.token, current_code(enrolment.secret, 1))
    async with db.connection() as conn:  # free the step so the new key can be shown to work
        await conn.execute("UPDATE warden.totp_credentials SET last_used_step = 0")
    challenge = await only_new.sign_in(user.email, PASSWORD)
    assert challenge.challenge is not None
    result = await only_new.verify_totp(challenge.challenge.token, current_code(enrolment.secret))
    assert isinstance(result, TokenPair)
