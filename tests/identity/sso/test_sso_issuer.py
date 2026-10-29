"""The configured issuer is used verbatim: a trailing slash is part of it.

Discovery and id_token ``iss`` checks compare the provider's issuer with the
configured one by exact string equality, so an issuer ending in "/" signs
in, and one differing from the configuration only by that slash is refused.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, ISSUER, FakeIdp
from fastapi import FastAPI
from identity_support import UserFactory, audit_rows
from sso_support import CLIENT_SECRET_NAME, completion, sign_in, sso_config

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity, User
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn

pytestmark = pytest.mark.db

SLASHED = ISSUER + "/"
ALICE = "alice@example.com"


@pytest.fixture
def configured_issuer() -> str:
    return SLASHED


@pytest.fixture
def provider_issuer() -> str:
    return SLASHED


@pytest.fixture
def config(configured_issuer: str) -> WardenConfig:
    return sso_config(issuer_url=configured_issuer, allowed_email_domains="example.com")


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    return secrets


@pytest.fixture
def idp(provider_issuer: str) -> FakeIdp:
    return FakeIdp(issuer=provider_issuer)


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


@pytest.fixture
async def alice(make_user: UserFactory) -> User:
    return await make_user(ALICE)


async def _pins(db: Database) -> list[tuple[str, str]]:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT issuer, subject FROM warden.sso_identities")
        return [(str(r[0]), str(r[1])) for r in await cur.fetchall()]


async def _refusals(db: Database) -> list[str]:
    return [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sso.sign_in")]


def test_the_configuration_keeps_the_slash(config: WardenConfig) -> None:
    assert config.sso.issuer_url == SLASHED


async def test_a_run_time_issuer_keeps_the_slash(sso: SingleSignOn) -> None:
    await sso.settings.update(actor="admin", issuer_url="https://other.example.com/")
    assert (await sso.settings.current()).issuer_url == "https://other.example.com/"


async def test_single_sign_on_reads_the_configured_secret_name(
    identity: Identity, idp: FakeIdp, secrets: Any
) -> None:
    config = sso_config(issuer_url=SLASHED, client_secret="product/sso-secret")
    sso = SingleSignOn(
        config,
        identity.db,
        identity.sessions,
        identity.policy,
        secrets,
        http=ProviderHttp(idp.client()),
    )
    assert sso.client_secret_name == "product/sso-secret"
    assert not sso.client_secret_set()
    secrets.set("product/sso-secret", CLIENT_SECRET)
    assert sso.client_secret_set()


async def test_an_issuer_ending_in_a_slash_passes_discovery(sso: SingleSignOn) -> None:
    report = await sso.test_configuration(actor="admin", source_ip=None)
    assert report.ok, report


async def test_an_issuer_ending_in_a_slash_signs_in(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, alice: User, db: Database
) -> None:
    response = await sign_in(client, idp, sub="s-alice", email=ALICE)
    assert response.status_code == 200, response.text
    principal = await identity.authenticate(response.json()["access_token"])
    assert principal.user_id == alice.id
    # The pin records the issuer exactly as configured and advertised.
    assert await _pins(db) == [(SLASHED, "s-alice")]


async def test_an_id_token_iss_without_the_slash_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    # Discovery agrees (both slashed); only the id_token's iss lacks the slash.
    response = await sign_in(client, idp, sub="s-alice", email=ALICE, iss=ISSUER)
    assert response.status_code == 401
    assert await _refusals(db) == ["id_token_invalid:issuer"]
    assert await _pins(db) == []


@pytest.mark.parametrize(
    ("configured_issuer", "provider_issuer"),
    [(SLASHED, ISSUER), (ISSUER, SLASHED)],
    ids=["configured-slash", "provider-slash"],
)
async def test_an_issuer_differing_only_by_the_slash_is_refused(
    client: httpx.AsyncClient, alice: User, db: Database, sso: SingleSignOn
) -> None:
    response = await client.get("/auth/sso/start")
    landed = completion(response)
    assert "code" not in landed
    assert await _refusals(db) == ["issuer_mismatch"]
    report = await sso.test_configuration(actor="admin", source_ip=None)
    assert not report.ok
