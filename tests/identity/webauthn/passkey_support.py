"""Helpers shared by the passkey tests (imported as ``passkey_support``).

An application with the auth, lifecycle and administration routers, and
ways to give a user a passkey without going through the routes under test.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import httpx
from fastapi import FastAPI
from fido2.utils import websafe_decode
from soft_authenticator import SoftwareAuthenticator

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, SignInMethod, User
from warden.identity.webauthn import WebAuthnCredential, WebAuthnPurpose

REFUSAL = b'{"detail":"authentication failed"}'
CLIENT = ("192.0.2.10", 50000)


def passkey_config(base_url: str = "https://app.example.com", **identity: Any) -> WardenConfig:
    """The identity tests' configuration, with the passkey registration link."""
    return parse_config(
        {
            "http": {
                "public_base_url": base_url,
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
                "passkey_registration_link": "https://app.example.com/passkey?t={token}",
            },
            "identity": {"require_mfa": False, **identity},
        }
    )


def passkey_app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.lifecycle_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


def http_client(identity: Identity, client: tuple[str, int] = CLIENT) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=passkey_app(identity), client=client)
    return httpx.AsyncClient(transport=transport, base_url="https://app.example.com")


def passkey_authenticator(**kw: Any) -> SoftwareAuthenticator:
    """A user-verifying authenticator that makes discoverable credentials."""
    return SoftwareAuthenticator(**{"resident": True, "user_verifying": True, **kw})


async def give_passkey(
    identity: Identity,
    user: User,
    authenticator: SoftwareAuthenticator | None = None,
    *,
    purpose: WebAuthnPurpose = WebAuthnPurpose.PASSKEY,
    **tamper: Any,
) -> tuple[SoftwareAuthenticator, WebAuthnCredential]:
    """Register a credential for an active user straight through the ceremony."""
    key = authenticator or passkey_authenticator()
    assert identity.webauthn is not None
    options = await identity.webauthn.begin_registration(user.id, purpose)
    response = key.register(options.public_key, **tamper)
    registration = await identity.webauthn.finish_registration(user.id, response)
    return key, registration.credential


async def set_method(db: Database, user_id: uuid.UUID, method: SignInMethod) -> None:
    """Change the sign-in method behind the services' back (no rule applies)."""
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.users SET sign_in_method = %s WHERE id = %s", (method.value, user_id)
        )


async def set_status(db: Database, user_id: uuid.UUID, status: str) -> None:
    async with db.connection() as conn:
        await conn.execute("UPDATE warden.users SET status = %s WHERE id = %s", (status, user_id))


def assert_refused(answer: httpx.Response) -> None:
    """The uniform refusal, byte for byte."""
    assert answer.status_code == 401, answer.text
    assert answer.content == REFUSAL
    assert answer.headers["www-authenticate"] == "Bearer"
    assert answer.headers["cache-control"] == "no-store"
    assert answer.headers["content-type"] == "application/json"


async def passkey_options(http: httpx.AsyncClient, **headers: str) -> httpx.Response:
    return await http.post("/auth/passkey/options", json={}, headers=headers)


async def passkey_assertion(
    http: httpx.AsyncClient, key: SoftwareAuthenticator, **tamper: Any
) -> dict[str, Any]:
    options = await passkey_options(http)
    assert options.status_code == 200, options.text
    return key.authenticate(options.json()["public_key"], **tamper)


async def passkey_sign_in(http: httpx.AsyncClient, credential: object) -> httpx.Response:
    return await http.post("/auth/passkey/sign-in", json={"credential": credential})


async def expire_challenge_of(db: Database, response: dict[str, Any]) -> None:
    """Expire only the challenge a browser response answers, as if its lifetime had passed."""
    client_data = json.loads(websafe_decode(response["response"]["clientDataJSON"]))
    digest = hashlib.sha256(websafe_decode(client_data["challenge"])).digest()
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.webauthn_challenges SET created_at = now() - interval '2 hours',"
            " expires_at = now() - interval '1 hour' WHERE challenge_hash = %s",
            (digest,),
        )
