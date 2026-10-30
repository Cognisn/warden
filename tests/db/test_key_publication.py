"""Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design D14).

``jwks.json`` carries the keys that sign and verify live credentials;
``jwks-historical.json`` adds retired keys, for verifying audit checkpoints.
A revoked key is in neither, and no private material is ever published.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from warden.db import Database
from warden.jwks import keys_router
from warden.keys import KeyStore, PublicKey

pytestmark = pytest.mark.db

LIVE = "/keys/jwks.json"
HISTORICAL = "/keys/jwks-historical.json"
JWK_MEMBERS = {"kty", "crv", "x", "kid", "alg", "use"}


class FakeSecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


@pytest.fixture
def secrets() -> FakeSecrets:
    return FakeSecrets()


@pytest.fixture
def store(pool: Any, secrets: FakeSecrets) -> KeyStore:
    return KeyStore(Database(pool), secrets)


@pytest.fixture
async def client(store: KeyStore) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(keys_router(keys=store), prefix="/keys")
    transport = httpx.ASGITransport(app=app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


async def _kids(client: httpx.AsyncClient, path: str) -> list[str]:
    response = await client.get(path)
    assert response.status_code == 200
    return [jwk["kid"] for jwk in response.json()["keys"]]


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


async def _three_keys(store: KeyStore) -> tuple[PublicKey, PublicKey, PublicKey]:
    """A retired key, a revoked key and the live key, oldest first."""
    retired = await store.rotate()
    revoked = await store.rotate()
    live = await store.rotate()
    await store.retire(retired.key_id)
    await store.revoke(revoked.key_id)
    return retired, revoked, live


@pytest.mark.parametrize("path", [LIVE, HISTORICAL])
async def test_each_key_is_an_rfc_8037_okp_jwk(
    client: httpx.AsyncClient, store: KeyStore, path: str
) -> None:
    key = await store.rotate()
    response = await client.get(path)
    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["keys"]
    [jwk] = body["keys"]
    assert jwk == {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "kid": key.key_id,
        "x": jwk["x"],
    }
    assert "=" not in jwk["x"]
    assert _unb64(jwk["x"]) == key.public_key


@pytest.mark.parametrize("path", [LIVE, HISTORICAL])
async def test_a_set_is_served_publicly_with_a_short_cache_lifetime(
    client: httpx.AsyncClient, store: KeyStore, path: str
) -> None:
    await store.rotate()
    response = await client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/jwk-set+json"
    assert response.headers["cache-control"] == "public, max-age=300"


@pytest.mark.parametrize("path", [LIVE, HISTORICAL])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_a_set_is_read_only(client: httpx.AsyncClient, path: str, method: str) -> None:
    response = await client.request(method, path)
    assert response.status_code == 405


async def test_with_no_keys_both_sets_are_empty(client: httpx.AsyncClient) -> None:
    for path in (LIVE, HISTORICAL):
        response = await client.get(path)
        assert response.status_code == 200
        assert response.json() == {"keys": []}


async def test_a_revoked_key_is_never_published(client: httpx.AsyncClient, store: KeyStore) -> None:
    _, revoked, _ = await _three_keys(store)
    assert revoked.key_id not in await _kids(client, LIVE)
    assert revoked.key_id not in await _kids(client, HISTORICAL)


async def test_a_retired_key_is_published_only_for_historical_verification(
    client: httpx.AsyncClient, store: KeyStore
) -> None:
    retired, _, live = await _three_keys(store)
    assert await _kids(client, LIVE) == [live.key_id]
    assert await _kids(client, HISTORICAL) == [live.key_id, retired.key_id]


async def test_a_rotated_key_is_published_at_once(
    client: httpx.AsyncClient, store: KeyStore
) -> None:
    first = await store.rotate()
    assert await _kids(client, LIVE) == [first.key_id]
    second = await store.rotate()
    assert await _kids(client, LIVE) == [second.key_id, first.key_id]


@pytest.mark.parametrize("path", [LIVE, HISTORICAL])
async def test_no_private_key_material_is_ever_published(
    client: httpx.AsyncClient, store: KeyStore, secrets: FakeSecrets, path: str
) -> None:
    await _three_keys(store)
    response = await client.get(path)
    assert response.status_code == 200
    for jwk in response.json()["keys"]:
        assert set(jwk) == JWK_MEMBERS
    assert secrets.values
    for seed in secrets.values.values():
        assert seed not in response.text


async def test_serving_a_set_records_no_audit_event(
    client: httpx.AsyncClient, store: KeyStore, pool: Any
) -> None:
    await store.rotate()
    for path in (LIVE, HISTORICAL, LIVE):
        assert (await client.get(path)).status_code == 200
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.audit_events")
        row = await cur.fetchone()
    assert row == (0,)
