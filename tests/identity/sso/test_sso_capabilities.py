"""Single sign-on in the capabilities agrees with ``GET <auth>/sso/start``.

Single sign-on can be turned on and off at run time (``PUT <admin>/sso/settings``),
so the capability follows the same settings read sign-in makes, through the
same cache; the tests use no cache, so a change shows at once.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, FakeIdp
from fastapi import FastAPI
from sso_support import CLIENT_SECRET_NAME, COMPLETION, sso_config

from warden.config import WardenConfig
from warden.identity import Identity
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn

pytestmark = pytest.mark.db


@pytest.fixture
def config(request: Any) -> WardenConfig:
    """Enabled in configuration unless a test asks otherwise (``indirect``)."""
    return sso_config(enabled=getattr(request, "param", True))


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
    return identity.sso


@pytest.fixture
def app(identity: Identity, sso: SingleSignOn) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


async def started(client: httpx.AsyncClient) -> bool:
    """Whether ``/sso/start`` sent the browser to the provider (not to the failure)."""
    response = await client.get("/auth/sso/start")
    assert response.status_code == 302, response.text
    return not response.headers["location"].startswith(COMPLETION)


async def offered(client: httpx.AsyncClient) -> bool:
    body = (await client.get("/auth/capabilities")).json()
    value = body["single_sign_on"]
    assert isinstance(value, bool)
    return value


@pytest.mark.parametrize("enabled", [True, False])
async def test_single_sign_on_agrees_with_the_start_route(
    identity: Identity, client: httpx.AsyncClient, enabled: bool
) -> None:
    if not enabled:
        await identity.sso.settings.update(actor="admin", enabled=False)
    began = await started(client)
    assert began is enabled
    assert (await identity.capabilities()).single_sign_on is began
    assert await offered(client) is began


async def test_a_run_time_change_moves_the_answer_and_the_route_together(
    identity: Identity, client: httpx.AsyncClient
) -> None:
    assert await started(client)
    assert (await identity.capabilities()).single_sign_on
    await identity.sso.settings.update(actor="admin", enabled=False)
    assert not await started(client)
    assert not (await identity.capabilities()).single_sign_on
    assert not await offered(client)
    await identity.sso.settings.update(actor="admin", enabled=True)
    assert await started(client)
    assert await offered(client)


@pytest.mark.parametrize("config", [False], indirect=True)
async def test_disabled_in_configuration_it_is_not_offered_until_enabled(
    identity: Identity, client: httpx.AsyncClient
) -> None:
    assert not await started(client)
    assert not (await identity.capabilities()).single_sign_on
    assert not await offered(client)
    await identity.sso.settings.update(actor="admin", enabled=True)
    assert await started(client)
    assert (await identity.capabilities()).single_sign_on
