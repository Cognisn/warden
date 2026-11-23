"""The single sign-on guard on the administration routes (ruling CS17).

Turning single sign-on off or clearing it is a 409 while anyone signs in with
it alone, answering the reason and the users to move first.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, FakeIdp
from fastapi import FastAPI, HTTPException, Request
from identity_support import UserFactory
from sso_support import CLIENT_SECRET_NAME, sso_config

from warden.config import WardenConfig
from warden.identity import Identity, SignInMethod
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn

pytestmark = pytest.mark.db

ADMIN = {"x-admin": "yes"}


@pytest.fixture
def config() -> WardenConfig:
    # Off in the configuration; every test turns it on at run time, so a reset has
    # somewhere to go back to that is not usable.
    return sso_config(enabled=False)


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    return secrets


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def sso(identity: Identity, idp: FakeIdp, secrets: Any) -> SingleSignOn:
    identity.sso = SingleSignOn(
        identity.config,
        identity.db,
        identity.sessions,
        identity.policy,
        secrets,
        http=ProviderHttp(idp.client()),
        settings_max_age=0,
    )
    identity.sso.use_sign_in_methods(identity.sign_in_methods)
    return identity.sso


@pytest.fixture(autouse=True)
async def turned_on(sso: SingleSignOn) -> None:
    await sso.settings.update(actor="seed", enabled=True)


async def authorise(request: Request) -> str:
    if request.headers.get("x-admin") != "yes":
        raise HTTPException(status_code=403, detail="forbidden")
    return "admin-1"


@pytest.fixture
def app(identity: Identity, sso: SingleSignOn) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.sso_settings_router(authorise=authorise), prefix="/admin")
    return application


async def test_turning_sso_off_names_the_reason_and_the_users_to_move(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    bob = await make_user("bob@example.com", password=None, sign_in_method=SignInMethod.SSO_ONLY)
    await make_user("alice@example.com")
    answer = await client.put("/admin/sso/settings", json={"enabled": False}, headers=ADMIN)
    assert answer.status_code == 409
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert body["reason"] == "sso_still_required"
    assert body["default_sso_only"] is False
    assert body["users"] == [{"id": str(bob.id), "email": "bob@example.com"}]
    assert "bob@example.com" not in body["detail"]
    assert set(body) == {"detail", "reason", "default_sso_only", "users"}
    # Nothing changed.
    shown = await client.get("/admin/sso/settings", headers=ADMIN)
    assert shown.json()["enabled"] is True


async def test_an_sso_only_default_is_named_by_the_guard(
    client: httpx.AsyncClient, identity: Identity
) -> None:
    await identity.update_sign_in_settings(actor="admin-1", default_sign_in_method="sso_only")
    answer = await client.put("/admin/sso/settings", json={"enabled": False}, headers=ADMIN)
    assert answer.status_code == 409
    body = answer.json()
    assert body["default_sso_only"] is True
    assert body["users"] == []


async def test_the_guard_does_not_refuse_a_change_that_keeps_sso_usable(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await make_user("bob@example.com", password=None, sign_in_method=SignInMethod.SSO_ONLY)
    answer = await client.put(
        "/admin/sso/settings", json={"allowed_email_domains": ["example.com"]}, headers=ADMIN
    )
    assert answer.status_code == 200


async def test_an_invalid_setting_is_still_a_400(client: httpx.AsyncClient) -> None:
    answer = await client.put("/admin/sso/settings", json={"issuer_url": "x"}, headers=ADMIN)
    assert answer.status_code == 400
    assert "reason" not in answer.json()


async def test_a_reset_that_would_turn_sso_off_is_refused_the_same_way(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    bob = await make_user("bob@example.com", password=None, sign_in_method=SignInMethod.SSO_ONLY)
    answer = await client.post("/admin/sso/settings/reset", headers=ADMIN)
    assert answer.status_code == 409, answer.text
    assert answer.json()["reason"] == "sso_still_required"
    assert answer.json()["users"] == [{"id": str(bob.id), "email": "bob@example.com"}]
