"""Helpers for the password policy and watch list administration route tests."""

from __future__ import annotations

from typing import Any

import httpx
from identity_support import sign_in_tokens

from warden.identity import Identity, User


async def bearer(identity: Identity, user: User) -> dict[str, str]:
    tokens = await sign_in_tokens(identity, user.email)
    return {"authorization": f"Bearer {tokens.access_token}"}


def policy_body(name: str = "Strict", priority: int | None = 1, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"name": name, "min_length": 14, "min_classes": 2}
    if priority is not None:
        body["priority"] = priority
    body.update(overrides)
    return body


async def create_policy(
    client: httpx.AsyncClient, headers: dict[str, str], **kw: Any
) -> dict[str, Any]:
    response = await client.post(
        "/admin/password-policies", json=policy_body(**kw), headers=headers
    )
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()["policy"]
    return created
