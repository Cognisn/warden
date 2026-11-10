"""Password policies with security keys and passkeys (rulings PW9 and P4 to P7).

A security key as the second factor comes before the forced change, and
the change keeps the key's ``amr``; a forced enrolment completed with a key
answers the change with the key and the recovery codes; a passkey sign-in
is never blocked by the password's state.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import httpx
import pytest
from identity_support import PASSWORD, UserFactory
from passkey_support import (
    give_passkey,
    http_client,
    passkey_assertion,
    passkey_sign_in,
)
from soft_authenticator import SoftwareAuthenticator

from warden.identity import (
    ChangeReason,
    Identity,
    PasswordRules,
    User,
    WatchListMatch,
    WatchListSource,
)
from warden.identity.password_policy import Tier
from warden.identity.webauthn import WebAuthnPurpose

pytestmark = pytest.mark.db

NEW = "Lantern-Meadow-77?"


async def _sign_in(c: httpx.AsyncClient, user: User) -> dict[str, Any]:
    answer = await c.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    assert answer.status_code == 200, answer.text
    body: dict[str, Any] = answer.json()
    return body


async def _amr(identity: Identity, body: dict[str, Any]) -> tuple[str, ...]:
    return (await identity.authenticate(body["access_token"])).amr


async def test_a_security_key_comes_before_the_change_and_keeps_its_amr(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    key, _ = await give_passkey(
        identity, user, SoftwareAuthenticator(), purpose=WebAuthnPurpose.SECOND_FACTOR
    )
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http_client(identity) as c:
        first = await _sign_in(c, user)
        assert first["status"] == "mfa_required" and first["methods"] == ["webauthn"]
        options = await c.post(
            "/auth/webauthn/verify/options", json={"challenge": first["challenge"]}
        )
        credential = key.authenticate(options.json()["public_key"])
        verified = await c.post(
            "/auth/webauthn/verify",
            json={"challenge": first["challenge"], "credential": credential},
        )
        body = verified.json()
        assert body["status"] == "password_change_required", body
        assert body["reason"] == "administrator"
        done = await c.post(
            "/auth/password-change", json={"challenge": body["challenge"], "new_password": NEW}
        )
        assert done.status_code == 200, done.text
    assert await _amr(identity, done.json()) == ("pwd", "hwk")


async def test_a_forced_enrolment_with_a_key_answers_the_change_with_the_key(
    identity: Identity, make_user: UserFactory
) -> None:
    await identity.policy.update(actor="test", require_mfa=True)
    user = await make_user()
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    key = SoftwareAuthenticator()
    async with http_client(identity) as c:
        first = await _sign_in(c, user)
        assert first["status"] == "mfa_enrolment_required"
        begun = await c.post("/auth/webauthn/registration", json={"challenge": first["challenge"]})
        response = key.register(begun.json()["public_key"])
        confirmed = await c.post(
            "/auth/webauthn/registration/confirm",
            json={"challenge": first["challenge"], "credential": response},
        )
        body = confirmed.json()
        assert body["status"] == "password_change_required", body
        assert body["credential"]["id"] and len(body["recovery_codes"]) == 10
        assert "access_token" not in body
        done = await c.post(
            "/auth/password-change", json={"challenge": body["challenge"], "new_password": NEW}
        )
    assert await _amr(identity, done.json()) == ("pwd", "hwk")


@pytest.mark.parametrize("reason", list(ChangeReason))
async def test_a_passkey_sign_in_is_never_blocked_by_the_passwords_state(
    reason: ChangeReason, identity: Identity, make_user: UserFactory
) -> None:
    default = await identity.password_policies.default()
    await identity.password_policies.update(
        default.id,
        replace(
            default.settings,
            rules=PasswordRules(min_length=12, tiers=(Tier("standard", max_age_days=1),)),
            enforce_on_sign_in=True,
        ),
        expected_version=default.version,
        actor="test",
    )
    user = await make_user()
    key, _ = await give_passkey(identity, user)
    match = None
    if reason is ChangeReason.WATCH_LIST:
        match = WatchListMatch(WatchListSource.BUILTIN, None, "This password is too common")
    await identity.password_states.require_change(user.id, reason, match=match)
    async with http_client(identity) as c:
        answer = await passkey_sign_in(c, await passkey_assertion(c, key))
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["status"] == "signed_in"
    assert "password_expires_in_days" not in body
    assert await _amr(identity, body) == ("hwk", "mfa")
