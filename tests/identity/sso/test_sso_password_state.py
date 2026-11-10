"""Single sign-on is never blocked by the password's state (ruling PW9).

A user whose password must change (for any reason) still signs in through
the identity provider, against the local fake provider.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, FakeIdp
from fastapi import FastAPI
from identity_support import UserFactory
from sso_support import CLIENT_SECRET_NAME, sign_in, sso_config

from warden.config import WardenConfig
from warden.identity import ChangeReason, Identity, WatchListMatch, WatchListSource
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn

pytestmark = pytest.mark.db


@pytest.fixture
def config() -> WardenConfig:
    return sso_config(allowed_email_domains="example.com")


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    return secrets


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def app(identity: Identity, idp: FakeIdp, secrets: Any) -> FastAPI:
    identity.sso = SingleSignOn(
        identity.config,
        identity.db,
        identity.sessions,
        identity.policy,
        secrets,
        http=ProviderHttp(idp.client()),
        settings_max_age=0,
    )
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


@pytest.mark.parametrize("reason", list(ChangeReason))
async def test_sso_signs_in_whatever_the_passwords_state(
    reason: ChangeReason,
    client: httpx.AsyncClient,
    identity: Identity,
    idp: FakeIdp,
    make_user: UserFactory,
) -> None:
    user = await make_user("alice@example.com")
    match = None
    if reason is ChangeReason.WATCH_LIST:
        match = WatchListMatch(WatchListSource.BUILTIN, None, "This password is too common")
    await identity.password_states.require_change(user.id, reason, match=match)
    response = await sign_in(client, idp, email="alice@example.com")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "signed_in"
    assert "password_expires_in_days" not in body
    state = await identity.password_states.get(user.id)
    assert state is not None and state.change_reason is reason
