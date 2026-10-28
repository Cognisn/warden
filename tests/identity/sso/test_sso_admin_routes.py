"""Single sign-on administration routes: settings, the write-only client secret,
the configuration test (which signs nobody in), presets and unpinning."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, FakeIdp
from fastapi import FastAPI, HTTPException, Request
from identity_support import UserFactory, audit_rows
from sso_support import CLIENT_SECRET_NAME, sign_in, sso_config

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn

pytestmark = pytest.mark.db


@pytest.fixture
def config() -> WardenConfig:
    return sso_config()


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


async def authorise(request: Request) -> str:
    if request.headers.get("x-admin") != "yes":
        raise HTTPException(status_code=403, detail="forbidden")
    return "admin-1"


@pytest.fixture
def app(identity: Identity, sso: SingleSignOn) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    application.include_router(identity.sso_settings_router(authorise=authorise), prefix="/admin")
    return application


ADMIN = {"x-admin": "yes"}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/admin/sso/settings"),
        ("PUT", "/admin/sso/settings"),
        ("POST", "/admin/sso/settings/reset"),
        ("PUT", "/admin/sso/client-secret"),
        ("POST", "/admin/sso/test"),
        ("DELETE", "/admin/sso/users/00000000-0000-0000-0000-000000000000/pin"),
    ],
)
async def test_every_route_needs_the_product_authorisation(
    client: httpx.AsyncClient, method: str, path: str
) -> None:
    response = await client.request(method, path, json={})
    assert response.status_code == 403


async def test_settings_show_the_derived_callback_and_never_the_secret(
    client: httpx.AsyncClient, secrets: Any
) -> None:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    response = await client.get("/admin/sso/settings", headers=ADMIN)
    assert response.status_code == 200
    body = response.json()
    assert body["callback_url"] == "https://app.example.com/auth/sso/callback"
    assert body["client_secret_set"] is True
    assert body["enabled"] is True
    assert body["provider_preset"] == "generic"
    assert {p["preset"] for p in body["presets"]} == {"entra", "google", "okta", "generic"}
    assert CLIENT_SECRET not in response.text
    assert response.headers["cache-control"] == "no-store"


async def test_settings_can_be_changed_and_reset(client: httpx.AsyncClient) -> None:
    changed = await client.put(
        "/admin/sso/settings", headers=ADMIN, json={"provider_preset": "entra"}
    )
    assert changed.status_code == 200
    assert changed.json()["provider_preset"] == "entra"
    reset = await client.post("/admin/sso/settings/reset", headers=ADMIN)
    assert reset.json()["provider_preset"] == "generic"


async def test_an_invalid_change_names_the_field(client: httpx.AsyncClient) -> None:
    response = await client.put(
        "/admin/sso/settings", headers=ADMIN, json={"issuer_url": "http://idp.example.com"}
    )
    assert response.status_code == 400
    assert "issuer_url" in response.json()["detail"]
    assert "idp.example.com" not in response.text
    bad_body = await client.put("/admin/sso/settings", headers=ADMIN, content=b"[]")
    assert bad_body.status_code == 400


async def test_the_client_secret_is_write_only(
    client: httpx.AsyncClient, secrets: Any, db: Database
) -> None:
    response = await client.put(
        "/admin/sso/client-secret", headers=ADMIN, json={"client_secret": "s3cret-dev-only"}
    )
    assert response.status_code == 204
    assert response.content == b""
    assert secrets.get(CLIENT_SECRET_NAME) == "s3cret-dev-only"
    shown = await client.get("/admin/sso/settings", headers=ADMIN)
    assert "s3cret-dev-only" not in shown.text
    rows = await audit_rows(db, "warden.identity.sso.client_secret_set")
    assert rows[0]["actor"] == "admin-1"
    assert "s3cret-dev-only" not in str(rows)


@pytest.mark.parametrize("body", [{}, {"client_secret": ""}, {"client_secret": "a\nb"}])
async def test_a_bad_client_secret_is_refused(
    client: httpx.AsyncClient, body: dict[str, Any]
) -> None:
    response = await client.put("/admin/sso/client-secret", headers=ADMIN, json=body)
    assert response.status_code == 400


async def test_the_configuration_test_signs_nobody_in(
    client: httpx.AsyncClient, idp: FakeIdp, secrets: Any, db: Database
) -> None:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    response = await client.post("/admin/sso/test", headers=ADMIN)
    assert response.status_code == 200
    report = response.json()
    assert report["ok"] is True
    assert {c["name"] for c in report["checks"]} == {
        "settings",
        "client_secret",
        "discovery",
        "algorithms",
        "jwks",
    }
    assert idp.count("/token") == 0
    assert idp.count("/authorize") == 0
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.sessions")
        row = await cur.fetchone()
    assert row is not None and row[0] == 0
    rows = await audit_rows(db, "warden.identity.sso.configuration_tested")
    assert rows[0]["outcome"] == "success"


async def test_the_configuration_test_reports_what_failed(
    client: httpx.AsyncClient, idp: FakeIdp, db: Database
) -> None:
    idp.discovery_overrides["issuer"] = "https://idp.example.com/other"
    report = (await client.post("/admin/sso/test", headers=ADMIN)).json()
    assert report["ok"] is False
    failed = {c["name"]: c["reason"] for c in report["checks"] if not c["ok"]}
    assert failed == {"client_secret": "missing", "discovery": "issuer_mismatch"}
    rows = await audit_rows(db, "warden.identity.sso.configuration_tested")
    assert rows[0]["details"] == {"failed": ["client_secret", "discovery"]}


async def test_unpinning_a_user(
    client: httpx.AsyncClient, idp: FakeIdp, secrets: Any, make_user: UserFactory
) -> None:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    user = await make_user("alice@example.com")
    assert (await sign_in(client, idp, sub="s-a", email="alice@example.com")).status_code == 200
    path = f"/admin/sso/users/{user.id}/pin"
    assert (await client.delete(path, headers=ADMIN)).status_code == 204
    assert (await client.delete(path, headers=ADMIN)).status_code == 404
    assert (
        await client.delete("/admin/sso/users/not-a-uuid/pin", headers=ADMIN)
    ).status_code == 404


async def test_disabling_through_the_route_ends_sso_sessions(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    secrets: Any,
    make_user: UserFactory,
    identity: Identity,
) -> None:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    await make_user("alice@example.com")
    body = (await sign_in(client, idp, sub="s-a", email="alice@example.com")).json()
    response = await client.put("/admin/sso/settings", headers=ADMIN, json={"enabled": False})
    assert response.status_code == 200
    refused = await client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert refused.status_code == 401
