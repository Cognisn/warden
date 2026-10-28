"""Helpers shared by single sign-on tests (imported as ``sso_support``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from fake_idp import CLIENT_ID, ISSUER, FakeIdp

from warden.config import WardenConfig, parse_config

CLIENT_SECRET_NAME = "warden.sso.client-secret"
COMPLETION = "https://app.example.com/signed-in"


def sso_config(*, completion: str | None = COMPLETION, **sso: Any) -> WardenConfig:
    http: dict[str, Any] = {
        "public_base_url": "https://app.example.com",
        "accept_invitation_link": "https://app.example.com/accept?t={token}",
        "reset_password_link": "https://app.example.com/reset?t={token}",
    }
    if completion is not None:
        http["sso_completion_link"] = completion
    section: dict[str, Any] = {
        "enabled": True,
        "issuer_url": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET_NAME,
        **sso,
    }
    return parse_config({"http": http, "identity": {"require_mfa": False}, "sso": section})


# Driving a browser through the flow


@dataclass
class Started:
    params: dict[str, str]
    response: httpx.Response

    @property
    def state(self) -> str:
        return self.params["state"]

    @property
    def nonce(self) -> str:
        return self.params["nonce"]


async def start(client: httpx.AsyncClient) -> Started:
    response = await client.get("/auth/sso/start")
    assert response.status_code == 302, response.text
    location = httpx.URL(response.headers["location"])
    return Started({k: v for k, v in location.params.items()}, response)


def provider_code(idp: FakeIdp, started: Started, **claims: Any) -> str:
    """What the provider does after the user signs in there: issue a code."""
    claims.setdefault("nonce", started.nonce)
    return idp.issue_code(idp.claims(**claims), challenge=started.params["code_challenge"])


async def callback(client: httpx.AsyncClient, code: str, state: str) -> httpx.Response:
    return await client.get("/auth/sso/callback", params={"code": code, "state": state})


def completion(response: httpx.Response) -> dict[str, str]:
    """The query the browser lands on the product's completion screen with."""
    assert response.status_code == 302, response.text
    location = httpx.URL(response.headers["location"])
    assert str(location.copy_with(query=None)) == COMPLETION
    return dict(location.params.items())


async def handoff(client: httpx.AsyncClient, code: str) -> httpx.Response:
    return await client.post("/auth/sso/handoff", json={"code": code})


async def sign_in(client: httpx.AsyncClient, idp: FakeIdp, **claims: Any) -> httpx.Response:
    """The whole round trip; returns the handoff response, or the callback's on failure."""
    started = await start(client)
    landed = completion(
        await callback(client, provider_code(idp, started, **claims), started.state)
    )
    if "code" not in landed:
        return httpx.Response(401, json=landed)
    return await handoff(client, landed["code"])
