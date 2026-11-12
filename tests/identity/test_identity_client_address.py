"""Identity's client address comes from the trusted-proxy resolver.

Behind a reverse proxy every connection's peer is the proxy. Identity must
key the sign-in throttle and record audit events by the real client address,
believing ``X-Forwarded-For`` only from ``audit.trusted_proxies``; otherwise
the throttle collapses to per-identifier and anyone can lock a user out.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from identity_support import FAST_HASHER, PASSWORD, MemorySecrets, UserFactory

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry
from warden.keys import KeyStore

pytestmark = pytest.mark.db

LIMIT = 3
PROXY = "10.0.0.5"
UNTRUSTED_PEER = "192.0.2.40"
REFUSAL = b'{"detail":"authentication failed"}'


@pytest.fixture
def config() -> WardenConfig:
    return parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "audit": {"trusted_proxies": ["10.0.0.0/8"]},
            "identity": {"require_mfa": False},
        }
    )


@pytest.fixture
def app(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> FastAPI:
    identity = Identity(
        config,
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        sign_in_attempt_limit=LIMIT,
    )
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    return application


@pytest.fixture
async def via_proxy(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=(PROXY, 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


@pytest.fixture
async def untrusted(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=(UNTRUSTED_PEER, 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


async def _source_ips(db: Database) -> list[str | None]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT host(source_ip) FROM warden.audit_events"
            " WHERE action LIKE '%%sign_in' ORDER BY id"
        )
        return [row[0] for row in await cur.fetchall()]


def _wrong(email: str) -> dict[str, str]:
    return {"email": email, "password": "wrong password"}


async def test_a_spoofed_header_from_an_untrusted_peer_is_ignored_in_the_audit_record(
    untrusted: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    await make_user("spoof@example.com")
    await untrusted.post(
        "/auth/sign-in",
        json=_wrong("spoof@example.com"),
        headers={"x-forwarded-for": "203.0.113.66"},
    )
    assert await _source_ips(db) == [UNTRUSTED_PEER]


async def test_a_spoofed_header_from_an_untrusted_peer_is_ignored_in_the_throttle_key(
    untrusted: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await make_user("victim@example.com")
    for n in range(LIMIT):
        await untrusted.post(
            "/auth/sign-in",
            json=_wrong("victim@example.com"),
            headers={"x-forwarded-for": f"203.0.113.{n + 1}"},
        )
    refused = await untrusted.post(
        "/auth/sign-in",
        json={"email": "victim@example.com", "password": PASSWORD},
        headers={"x-forwarded-for": "203.0.113.99"},
    )
    assert refused.status_code == 401 and refused.content == REFUSAL


async def test_the_rightmost_untrusted_entry_from_a_trusted_proxy_is_recorded(
    via_proxy: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    await make_user("chain@example.com")
    await via_proxy.post(
        "/auth/sign-in",
        json=_wrong("chain@example.com"),
        headers={"x-forwarded-for": "198.51.100.7, 203.0.113.9, 10.0.0.9"},
    )
    assert await _source_ips(db) == ["203.0.113.9"]


async def test_two_clients_behind_one_proxy_are_throttled_separately(
    via_proxy: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await make_user("shared@example.com")
    for _ in range(LIMIT):
        await via_proxy.post(
            "/auth/sign-in",
            json=_wrong("shared@example.com"),
            headers={"x-forwarded-for": "203.0.113.1"},
        )
    attacker = await via_proxy.post(
        "/auth/sign-in",
        json={"email": "shared@example.com", "password": PASSWORD},
        headers={"x-forwarded-for": "203.0.113.1"},
    )
    assert attacker.status_code == 401 and attacker.content == REFUSAL
    owner = await via_proxy.post(
        "/auth/sign-in",
        json={"email": "shared@example.com", "password": PASSWORD},
        headers={"x-forwarded-for": "203.0.113.2"},
    )
    assert owner.status_code == 200
