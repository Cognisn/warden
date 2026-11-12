"""Live check: single sign-on against a real OIDC provider (navikt mock-oauth2-server).

Marked ``integration`` (skipped by default). Start the stub provider from the
sandbox (``--profile idp``, after ``live/make_certs.py <sandbox>/idp-certs``)
and point the test at it:

    WARDEN_IT_SANDBOX      directory holding idp-certs/
    WARDEN_IT_IDP_PORT     the stub provider's port (stub_idp in ports.txt)

The provider's own login page is driven headlessly: the username becomes the
id_token's ``sub`` and the submitted claims are added to it, so a test can
present a forged subject or email exactly as a hostile provider account would.
Everything warden does, discovery, JWKS, the token exchange over TLS and
validation, runs against the real server.
"""

from __future__ import annotations

import json
import os
import re
import ssl
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import UserFactory, audit_rows
from sso_support import CLIENT_SECRET_NAME, callback, completion, handoff, sso_config, start

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn

pytestmark = [pytest.mark.integration, pytest.mark.db]

SANDBOX = os.environ.get("WARDEN_IT_SANDBOX")
PORT = os.environ.get("WARDEN_IT_IDP_PORT")

if not (SANDBOX and PORT):
    pytest.skip("live identity provider not configured", allow_module_level=True)

assert SANDBOX and PORT
ISSUER = f"https://localhost:{PORT}/warden"
CA_FILE = Path(SANDBOX) / "idp-certs" / "ca.pem"
CLIENT_ID = "warden-live-client"


def trusted() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(CA_FILE))


@pytest.fixture
def config() -> WardenConfig:
    return sso_config(issuer_url=ISSUER, client_id=CLIENT_ID, allowed_email_domains="example.com")


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, "live-secret-dev-only")
    return secrets


@pytest.fixture
async def browser_to_idp() -> AsyncIterator[httpx.AsyncClient]:
    """The user's browser as it talks to the provider."""
    async with httpx.AsyncClient(verify=trusted(), follow_redirects=False) as c:
        yield c


@pytest.fixture
async def sso(identity: Identity, secrets: Any) -> AsyncIterator[SingleSignOn]:
    http = ProviderHttp(httpx.AsyncClient(verify=trusted(), timeout=10, follow_redirects=False))
    identity.sso = SingleSignOn(
        identity.config,
        identity.db,
        identity.sessions,
        identity.policy,
        secrets,
        http=http,
        settings_max_age=0,
    )
    yield identity.sso
    await http.aclose()


@pytest.fixture
def app(identity: Identity, sso: SingleSignOn) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


async def provider_login(
    idp: httpx.AsyncClient, authorize_url: str, subject: str, claims: dict[str, Any]
) -> tuple[str, str]:
    """Sign in on the provider's login page; returns the (code, state) it redirects with."""
    page = await idp.get(authorize_url)
    assert page.status_code == 200, page.text[:200]
    action = re.search(r'<form[^>]*action="([^"]*)"', page.text)
    target = (
        httpx.URL(authorize_url).join(action.group(1))
        if action and action.group(1)
        else (httpx.URL(authorize_url))
    )
    landed = await idp.post(str(target), data={"username": subject, "claims": json.dumps(claims)})
    assert landed.status_code == 302, landed.text[:200]
    redirect = httpx.URL(landed.headers["location"])
    assert str(redirect.copy_with(query=None)) == "https://app.example.com/auth/sso/callback"
    return redirect.params["code"], redirect.params["state"]


async def round_trip(
    client: httpx.AsyncClient, idp: httpx.AsyncClient, subject: str, email: str
) -> dict[str, str]:
    started = await start(client)
    code, state = await provider_login(
        idp, started.response.headers["location"], subject, {"email": email, "email_verified": True}
    )
    assert state == started.state
    return completion(await callback(client, code, state))


async def reasons(db: Database) -> list[str]:
    return [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sso.sign_in")]


async def test_live_round_trip_and_refusals(
    client: httpx.AsyncClient,
    browser_to_idp: httpx.AsyncClient,
    identity: Identity,
    make_user: UserFactory,
    db: Database,
    sso: SingleSignOn,
) -> None:
    alice = await make_user("alice@example.com")
    await make_user("bob@example.com")
    await make_user("carol@example.org")

    report = await sso.test_configuration(actor="admin")
    assert report.ok, report

    # Sign in: the first sign-in pins the provider's subject.
    landed = await round_trip(client, browser_to_idp, "s-alice", "alice@example.com")
    response = await handoff(client, landed["code"])
    assert response.status_code == 200, response.text
    principal = await identity.authenticate(response.json()["access_token"])
    assert principal.user_id == alice.id
    assert principal.amr == ("sso",)

    # Signing in again matches by subject.
    landed = await round_trip(client, browser_to_idp, "s-alice", "Alice@Example.com")
    assert (await handoff(client, landed["code"])).status_code == 200

    # A forged subject for Alice's email is refused.
    assert await round_trip(client, browser_to_idp, "s-forged", "alice@example.com") == {
        "error": "sso_failed"
    }
    assert (await reasons(db))[-1] == "subject_mismatch"

    # Alice's subject presenting another user's email is refused.
    assert await round_trip(client, browser_to_idp, "s-alice", "bob@example.com") == {
        "error": "sso_failed"
    }
    assert (await reasons(db))[-1] == "email_mismatch"

    # A user outside the allowed domains is refused, pre-provisioned or not.
    assert await round_trip(client, browser_to_idp, "s-carol", "carol@example.org") == {
        "error": "sso_failed"
    }
    assert (await reasons(db))[-1] == "domain_not_allowed"
