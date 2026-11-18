"""The single sign-on administration routes record the client address on every row (GitHub #3)."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, FakeIdp
from fastapi import FastAPI, HTTPException, Request
from identity_support import UserFactory
from sso_support import CLIENT_SECRET_NAME, sign_in, sso_config

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn

pytestmark = pytest.mark.db

# The conftest's client connects from this documentation address.
ADDRESS = "192.0.2.10"
ADMIN = {"x-admin": "yes"}


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


async def _recorded(
    db: Database, call: Awaitable[httpx.Response], *expected: str, status: int
) -> None:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT coalesce(max(id), 0) FROM warden.audit_events")
        row = await cur.fetchone()
    assert row is not None
    response = await call
    assert response.status_code == status, response.text
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT action, host(source_ip) FROM warden.audit_events WHERE id > %s ORDER BY id",
            (row[0],),
        )
        rows = [(r[0], r[1]) for r in await cur.fetchall()]
    for action in expected:
        assert f"warden.identity.sso.{action}" in [a for a, _ in rows], (action, rows)
    assert all(address == ADDRESS for _, address in rows), rows


async def test_changing_resetting_and_disabling_record_the_address(
    client: httpx.AsyncClient, db: Database
) -> None:
    await _recorded(
        db,
        client.put("/admin/sso/settings", headers=ADMIN, json={"provider_preset": "entra"}),
        "settings_changed",
        status=200,
    )
    await _recorded(
        db,
        client.put("/admin/sso/settings", headers=ADMIN, json={"enabled": False}),
        "settings_changed",
        "disabled",
        status=200,
    )
    await _recorded(
        db, client.post("/admin/sso/settings/reset", headers=ADMIN), "settings_changed", status=200
    )


async def test_unpinning_records_the_address(
    client: httpx.AsyncClient, idp: FakeIdp, secrets: Any, make_user: UserFactory, db: Database
) -> None:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    user = await make_user("alice@example.com")
    assert (await sign_in(client, idp, sub="s-a", email="alice@example.com")).status_code == 200
    await _recorded(
        db,
        client.delete(f"/admin/sso/users/{user.id}/pin", headers=ADMIN),
        "subject_unpinned",
        status=204,
    )


@pytest.mark.parametrize("field", ["source_ip", "actor"])
async def test_a_reserved_name_in_the_body_is_an_unknown_setting(
    client: httpx.AsyncClient, field: str
) -> None:
    """The route passes ``actor`` and ``source_ip`` itself; a body cannot supply them."""
    response = await client.put("/admin/sso/settings", headers=ADMIN, json={field: "198.51.100.1"})
    assert response.status_code == 400
    assert response.json() == {"detail": f"unknown settings: {field}"}
