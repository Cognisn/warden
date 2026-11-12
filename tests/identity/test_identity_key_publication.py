"""An access token warden issues verifies, outside warden, against its published keys."""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import jwt
import pytest
from fastapi import FastAPI
from identity_support import PASSWORD, UserFactory

from warden.identity import Identity
from warden.jwks import keys_router
from warden.keys import KeyStore

pytestmark = pytest.mark.db

ISSUER = "https://app.example.com"


@pytest.fixture
async def keys_client(keys: KeyStore) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(keys_router(keys=keys), prefix="/keys")
    transport = httpx.ASGITransport(app=app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url=ISSUER) as c:
        yield c


async def _access_token(identity: Identity, make_user: UserFactory) -> str:
    user = await make_user()
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is not None
    return result.tokens.access_token


async def _published_key(client: httpx.AsyncClient, token: str) -> jwt.PyJWK:
    kid = jwt.get_unverified_header(token)["kid"]
    response = await client.get("/keys/jwks.json")
    assert response.status_code == 200
    [match] = [k for k in response.json()["keys"] if k["kid"] == kid]
    return jwt.PyJWK(match)


def _decode(token: str, key: jwt.PyJWK) -> dict[str, Any]:
    claims: dict[str, Any] = jwt.decode(
        token, key=key, algorithms=["EdDSA"], issuer=ISSUER, options={"require": ["exp", "iat"]}
    )
    return claims


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


async def test_an_access_token_verifies_against_the_published_set(
    identity: Identity, make_user: UserFactory, keys_client: httpx.AsyncClient
) -> None:
    token = await _access_token(identity, make_user)
    key = await _published_key(keys_client, token)
    claims = _decode(token, key)
    assert claims["iss"] == ISSUER


async def test_a_tampered_access_token_does_not_verify(
    identity: Identity, make_user: UserFactory, keys_client: httpx.AsyncClient
) -> None:
    token = await _access_token(identity, make_user)
    key = await _published_key(keys_client, token)
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    forged = _b64(json.dumps(dict(claims, sub="00000000-0000-0000-0000-000000000000")).encode())
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    for bad in (f"{header}.{forged}.{signature}", f"{header}.{payload}.{flipped}"):
        with pytest.raises(jwt.InvalidSignatureError):
            _decode(bad, key)
