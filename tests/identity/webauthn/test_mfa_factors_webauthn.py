"""Allowed second factors with security keys and passkeys (ruling CS14).

The challenge offers only allowed factors; a user holding none is sent
through forced enrolment of an allowed one; a disallowed factor is not
enrolled; once an allowed factor is in place, the disallowed enrolment is
removed and audited. Recovery codes come with the first factor, whatever it
is, and stay usable.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from identity_support import (
    PASSWORD,
    UserFactory,
    audit_rows,
    current_code,
    direct_session,
    enrol_totp,
    fresh_totp_code,
)
from soft_authenticator import SoftwareAuthenticator

from warden.db import Database
from warden.identity import (
    AuthenticationRefused,
    Identity,
    Principal,
    SignInMethod,
    User,
)
from warden.identity.webauthn import WebAuthnError, WebAuthnRefusal

pytestmark = pytest.mark.db


async def _allow(identity: Identity, *factors: str) -> None:
    await identity.update_sign_in_settings(actor="admin-1", allowed_second_factors=list(factors))


async def _principal(
    identity: Identity, user: User, amr: tuple[str, ...] = ("pwd", "otp")
) -> Principal:
    pair = await direct_session(identity, user.id, amr)
    return await identity.authenticate(pair.access_token)


async def _with_key(identity: Identity, user: User, **kind: bool) -> SoftwareAuthenticator:
    """Register a key for the user while signed in (as a prior session would have)."""
    key = SoftwareAuthenticator(**kind)
    principal = await _principal(identity, user, ("hwk", "mfa"))
    options = await identity.begin_webauthn_registration(principal=principal)
    await identity.finish_webauthn_registration(
        key.register(options.public_key), principal=principal
    )
    return key


async def _keys(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.webauthn_credentials WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def _unused_codes(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.recovery_codes WHERE user_id = %s AND used_at IS NULL",
            (user_id,),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def _challenge(identity: Identity, user: User, purpose: str) -> tuple[str, tuple[str, ...]]:
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == purpose, result
    return result.challenge.token, result.challenge.methods


# The challenge


async def test_the_challenge_offers_only_allowed_factors(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    await _with_key(identity, user)
    assert (await _challenge(identity, user, "verify"))[1] == ("totp", "webauthn")
    await _allow(identity, "passkey")
    assert (await _challenge(identity, user, "verify"))[1] == ("webauthn",)
    await _allow(identity, "totp")
    assert (await _challenge(identity, user, "verify"))[1] == ("totp",)


async def test_a_disallowed_totp_does_not_complete_the_challenge(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    key = await _with_key(identity, user)
    await _allow(identity, "passkey")
    token, _ = await _challenge(identity, user, "verify")
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(token, await fresh_totp_code(identity, user.id))
    rows = await audit_rows(db, "warden.identity.mfa.verify")
    assert rows[-1]["details"] == {"reason": "factor_not_allowed", "method": "totp"}
    # Not an attempt: the same challenge still takes the allowed key.
    options = await identity.begin_webauthn_sign_in(token)
    pair = await identity.verify_webauthn(token, key.authenticate(options.public_key))
    assert (await identity.authenticate(pair.access_token)).amr == ("pwd", "hwk")


async def test_a_disallowed_key_does_not_complete_the_challenge(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    key = await _with_key(identity, user)
    token, _ = await _challenge(identity, user, "verify")
    options = await identity.begin_webauthn_sign_in(token)
    await _allow(identity, "totp")
    with pytest.raises(AuthenticationRefused):
        await identity.verify_webauthn(token, key.authenticate(options.public_key))
    with pytest.raises(AuthenticationRefused):
        await identity.begin_webauthn_sign_in(token)
    rows = await audit_rows(db, "warden.identity.mfa.verify")
    assert [r["details"] for r in rows[-2:]] == [
        {"reason": "factor_not_allowed", "method": "webauthn"},
        {"reason": "factor_not_allowed", "method": "webauthn"},
    ]


async def test_a_recovery_code_still_completes_the_challenge(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret))
    assert codes
    await _with_key(identity, user)
    await _allow(identity, "passkey")
    token, _ = await _challenge(identity, user, "verify")
    pair = await identity.use_recovery_code(token, codes[0])
    assert (await identity.authenticate(pair.access_token)).amr == ("pwd", "recovery_code")


# Forced enrolment of an allowed factor


async def test_a_user_with_only_a_removed_totp_enrols_a_key(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    await _allow(identity, "passkey")
    token, methods = await _challenge(identity, user, "enrol")
    assert methods == ("webauthn",)
    key = SoftwareAuthenticator()
    options = await identity.begin_webauthn_registration(challenge=token)
    enrolled = await identity.finish_webauthn_registration(
        key.register(options.public_key), challenge=token, source_ip="192.0.2.21"
    )
    assert enrolled.tokens is not None
    # Not the first factor: no new codes, and the old ones still work.
    assert enrolled.recovery_codes == []
    assert await _unused_codes(db, user.id) == 10
    # The disallowed TOTP is removed now that an allowed factor exists.
    assert not await identity.mfa.has_confirmed_totp(user.id)
    rows = await audit_rows(db, "warden.identity.mfa.disallowed_removed")
    assert rows == [
        {
            "action": "warden.identity.mfa.disallowed_removed",
            "outcome": "success",
            "actor": str(user.id),
            "resource_type": "user",
            "resource_id": str(user.id),
            "details": {"totp_removed": True, "webauthn_removed": 0, "allowed": ["passkey"]},
        }
    ]
    assert (await _challenge(identity, user, "verify"))[1] == ("webauthn",)


async def test_a_user_with_only_a_removed_key_enrols_totp(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await _with_key(identity, user)
    await _with_key(identity, user)
    await _allow(identity, "totp")
    token, methods = await _challenge(identity, user, "enrol")
    assert methods == ("totp",)
    enrolment = await identity.begin_enrolment(challenge=token)
    codes, answer = await identity.confirm_enrolment(
        current_code(enrolment.secret), challenge=token
    )
    assert codes == [] and answer is not None
    assert await _keys(db, user.id) == 0
    rows = await audit_rows(db, "warden.identity.mfa.disallowed_removed")
    assert rows[-1]["details"] == {
        "totp_removed": False,
        "webauthn_removed": 2,
        "allowed": ["totp"],
    }


async def test_a_never_enrolled_user_enrols_only_an_allowed_factor(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    await _allow(identity, "totp")
    user = await make_user()
    token, methods = await _challenge(identity, user, "enrol")
    assert methods == ("totp",)
    with pytest.raises(AuthenticationRefused):
        await identity.begin_webauthn_registration(challenge=token)
    rows = await audit_rows(db, "warden.identity.mfa.verify")
    assert rows[-1]["details"] == {"reason": "factor_not_allowed", "method": "enrolment"}
    # A key whose registration began while keys were allowed is not kept.
    await _allow(identity, "totp", "passkey")
    options = await identity.begin_webauthn_registration(challenge=token)
    await _allow(identity, "totp")
    key = SoftwareAuthenticator()
    with pytest.raises(AuthenticationRefused):
        await identity.finish_webauthn_registration(
            key.register(options.public_key), challenge=token
        )
    assert await _keys(db, user.id) == 0


async def test_the_first_factor_brings_recovery_codes_whatever_it_is(
    identity: Identity, make_user: UserFactory
) -> None:
    await _allow(identity, "passkey")
    user = await make_user()
    token, _ = await _challenge(identity, user, "enrol")
    options = await identity.begin_webauthn_registration(challenge=token)
    enrolled = await identity.finish_webauthn_registration(
        SoftwareAuthenticator().register(options.public_key), challenge=token
    )
    assert len(enrolled.recovery_codes) == 10
    await _allow(identity, "totp")
    other = await make_user()
    token, _ = await _challenge(identity, other, "enrol")
    enrolment = await identity.begin_enrolment(challenge=token)
    codes, _ = await identity.confirm_enrolment(current_code(enrolment.secret), challenge=token)
    assert len(codes) == 10


# Enrolment by a signed-in user


async def test_a_disallowed_key_is_not_registered_by_a_signed_in_user(
    identity: Identity, client: httpx.AsyncClient, db: Database, make_user: UserFactory
) -> None:
    await _allow(identity, "totp")
    user = await make_user()
    await enrol_totp(identity, user)
    principal = await _principal(identity, user)
    with pytest.raises(WebAuthnError) as caught:
        await identity.begin_webauthn_registration(principal=principal)
    assert caught.value.reason is WebAuthnRefusal.FACTOR_NOT_ALLOWED
    pair = await direct_session(identity, user.id)
    response = await client.post(
        "/auth/webauthn/registration", headers={"authorization": f"Bearer {pair.access_token}"}
    )
    assert response.status_code == 409
    assert response.json() == {
        "detail": "security keys and passkeys are not allowed as a second factor"
    }
    assert await _keys(db, user.id) == 0


async def test_an_allowed_factor_added_while_signed_in_removes_a_disallowed_one(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await _with_key(identity, user)
    await _allow(identity, "totp")
    principal = await _principal(identity, user, ("pwd", "hwk"))
    enrolment = await identity.begin_enrolment(principal=principal)
    codes, answer = await identity.confirm_enrolment(
        current_code(enrolment.secret), principal=principal
    )
    assert codes == [] and answer is None
    assert await _keys(db, user.id) == 0
    rows = await audit_rows(db, "warden.identity.mfa.disallowed_removed")
    assert rows[-1]["details"]["webauthn_removed"] == 1


async def test_a_passkey_only_user_keeps_their_passkeys(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """A passkey_only user's passkeys are how they sign in, not a second factor."""
    user = await make_user(password=None, sign_in_method=SignInMethod.PASSKEY_ONLY)
    await _with_key(identity, user, resident=True)
    await _allow(identity, "totp")
    principal = await _principal(identity, user, ("hwk", "mfa"))
    # Another passkey may still be registered.
    options = await identity.begin_webauthn_registration(principal=principal)
    await identity.finish_webauthn_registration(
        SoftwareAuthenticator(resident=True).register(options.public_key), principal=principal
    )
    enrolment = await identity.begin_enrolment(principal=principal)
    await identity.confirm_enrolment(current_code(enrolment.secret), principal=principal)
    assert await _keys(db, user.id) == 2
    assert await audit_rows(db, "warden.identity.mfa.disallowed_removed") == []
