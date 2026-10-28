"""Live check: break-glass password sign-in with the identity provider stopped.

Marked ``integration`` (skipped by default). Run it after stopping the stub
provider (the sandbox's ``compose_down``), with the same variables as
``test_sso_live.py``:

    WARDEN_IT_SANDBOX      directory holding idp-certs/
    WARDEN_IT_IDP_PORT     the stub provider's port

It first proves nothing answers on that port, then that single sign-on fails
with the fixed message while a password sign-in still succeeds.
"""

from __future__ import annotations

import os
import socket
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows
from sso_support import CLIENT_SECRET_NAME, COMPLETION, sso_config

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity, UserStatus

NEW_PASSWORD = "a brand new passphrase"

pytestmark = [pytest.mark.integration, pytest.mark.db]

SANDBOX = os.environ.get("WARDEN_IT_SANDBOX")
PORT = os.environ.get("WARDEN_IT_IDP_PORT")

if not (SANDBOX and PORT):
    pytest.skip("live identity provider not configured", allow_module_level=True)

assert PORT
ISSUER = f"https://localhost:{PORT}/warden"


@pytest.fixture
def config() -> WardenConfig:
    return sso_config(issuer_url=ISSUER, client_id="warden-live-client")


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, "live-secret-dev-only")
    return secrets


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.lifecycle_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


def test_the_provider_is_stopped() -> None:
    assert PORT
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", int(PORT)), timeout=2):
        pass


async def test_password_sign_in_works_while_sso_fails(
    client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    test_the_provider_is_stopped()
    await make_user("alice@example.com")

    sso = await client.get("/auth/sso/start")
    assert sso.status_code == 302
    assert sso.headers["location"] == f"{COMPLETION}?error=sso_failed"
    rows = await audit_rows(db, "warden.identity.sso.sign_in")
    assert rows[-1]["details"]["reason"] == "discovery_unavailable"

    password = await client.post(
        "/auth/sign-in", json={"email": "alice@example.com", "password": PASSWORD}
    )
    assert password.status_code == 200
    assert password.json()["status"] == "signed_in"


@pytest.mark.parametrize("body_type", ["form", "json"])
async def test_an_invitation_completes_with_a_password_while_sso_fails(
    client: httpx.AsyncClient,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
    body_type: str,
) -> None:
    test_the_provider_is_stopped()
    invitation = await identity.invitations.create("frank@example.com", actor="admin")
    token = mail.token()

    if body_type == "json":
        sso = await client.post("/auth/sso/start", json={"invitation": token})
    else:
        sso = await client.post("/auth/sso/start", data={"invitation": token})
    assert sso.headers["location"] == f"{COMPLETION}?error=sso_failed"
    rows = await audit_rows(db, "warden.identity.sso.sign_in")
    assert rows[-1]["details"]["reason"] == "discovery_unavailable"

    # The invitation is untouched, and completes with a password instead.
    accepted = await client.post(
        "/auth/invitations/accept", json={"token": token, "password": NEW_PASSWORD}
    )
    assert accepted.status_code == 200, accepted.text
    password = await client.post(
        "/auth/sign-in", json={"email": "frank@example.com", "password": NEW_PASSWORD}
    )
    assert password.status_code == 200
    assert password.json()["status"] == "signed_in"
    user = await identity.users.get(invitation.user_id)
    assert user is not None and user.status == UserStatus.ACTIVE
