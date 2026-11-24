"""A deployment without WebAuthn (wave 9 decision D17) boots and serves 0.1.0b8 as before.

A base URL on a loopback IP address, allowed since 0.1.0b1, has no
relying party id, so passkeys and security keys are unavailable until
``webauthn.rp_id`` is set. Identity must still build, and every published
route must behave exactly as before; the WebAuthn routes say WebAuthn is
not configured, or refuse uniformly where they face a sign-in.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from identity_support import (
    FAST_HASHER,
    PASSWORD,
    MemorySecrets,
    RecordingSender,
    current_code,
)

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry
from warden.keys import KeyStore

pytestmark = pytest.mark.db

BASE = "http://127.0.0.1:8000"
REFUSAL = b'{"detail":"authentication failed"}'


def _config(**identity: object) -> WardenConfig:
    return parse_config(
        {
            "http": {
                "public_base_url": BASE,
                "accept_invitation_link": f"{BASE}/accept?t={{token}}",
                "reset_password_link": f"{BASE}/reset?t={{token}}",
            },
            "identity": {**identity},
        }
    )


@pytest.fixture
def bare(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
) -> Identity:
    return Identity(
        _config(), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER, mail_sender=mail
    )


@pytest.fixture
async def http(bare: Identity) -> AsyncIterator[httpx.AsyncClient]:
    application = FastAPI()
    bare.install(application)
    application.include_router(bare.auth_router(), prefix="/auth")
    application.include_router(bare.admin_router(permission="users.manage"), prefix="/admin")
    transport = httpx.ASGITransport(app=application, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:
        yield c


async def test_it_boots_without_webauthn(bare: Identity) -> None:
    assert bare.config.webauthn.relying_party_id(bare.config.http) is None
    assert bare.webauthn is None
    report = await bare.prune()
    assert report.webauthn_challenges == 0


async def test_password_and_totp_sign_in_are_unchanged(
    http: httpx.AsyncClient, bare: Identity
) -> None:
    user = await bare.users.create("enid@example.com", actor="test", password=PASSWORD)
    body = {"email": user.email, "password": PASSWORD}
    # A second factor is always required (ruling CS14): TOTP, the only kind here.
    forced = (await http.post("/auth/sign-in", json=body)).json()
    assert forced["status"] == "mfa_enrolment_required"
    assert forced["methods"] == ["totp"]
    enrol = {"challenge": forced["challenge"]}
    secret = (await http.post("/auth/totp/enrolment", json=enrol)).json()["secret"]
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8))
    confirmed = await http.post(
        "/auth/totp/enrolment/confirm", json={**enrol, "code": current_code(raw)}
    )
    assert confirmed.json()["status"] == "signed_in"
    assert len(confirmed.json()["recovery_codes"]) == 10
    headers = {"authorization": f"Bearer {confirmed.json()['access_token']}"}
    challenged = (await http.post("/auth/sign-in", json=body)).json()
    assert challenged["status"] == "mfa_required"
    assert challenged["methods"] == ["totp"]
    verified = await http.post(
        "/auth/totp/verify",
        json={"challenge": challenged["challenge"], "code": current_code(raw, 1)},
    )
    assert verified.status_code == 200, verified.text

    # The WebAuthn routes: not configured for a signed-in user, the uniform
    # refusal under a sign-in challenge, and an empty list of keys.
    begun = await http.post("/auth/webauthn/registration", json={}, headers=headers)
    assert (begun.status_code, begun.json()) == (409, {"detail": "WebAuthn is not configured"})
    challenge = (await http.post("/auth/sign-in", json=body)).json()["challenge"]
    options = await http.post("/auth/webauthn/verify/options", json={"challenge": challenge})
    assert (options.status_code, options.content) == (401, REFUSAL)
    listed = await http.get("/auth/webauthn/credentials", headers=headers)
    assert listed.json() == {"credentials": []}


async def test_passkeys_alone_cannot_be_allowed_without_webauthn(
    bare: Identity, db: Database
) -> None:
    """A user without a factor could never enrol one (ruling CS14)."""
    from identity_support import audit_rows

    from warden.identity import SecondFactorKind, SignInMethodChangeRefused

    with pytest.raises(SignInMethodChangeRefused) as caught:
        await bare.update_sign_in_settings(actor="admin-1", allowed_second_factors=["passkey"])
    assert caught.value.reason == "webauthn"
    settings = await bare.sign_in_methods.read_now()
    assert settings.allowed_second_factors == {SecondFactorKind.TOTP, SecondFactorKind.PASSKEY}
    rows = await audit_rows(db, "warden.identity.sign_in_settings_changed")
    assert [(r["outcome"], r["details"]["reason"]) for r in rows] == [("failure", "webauthn")]
    # TOTP alone is fine, and forced enrolment then offers TOTP only.
    await bare.update_sign_in_settings(actor="admin-1", allowed_second_factors=["totp"])
    user = await bare.users.create("ivo@example.com", actor="test", password=PASSWORD)
    result = await bare.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.methods == ("totp",)


async def test_forced_enrolment_offers_totp_only_without_webauthn(bare: Identity) -> None:
    user = await bare.users.create("una@example.com", actor="test", password=PASSWORD)
    result = await bare.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "enrol"
    assert result.challenge.methods == ("totp",)
