"""Helpers for the password enforcement tests (imported as ``password_support``)."""

from __future__ import annotations

import itertools
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import Any

import httpx
from fastapi import FastAPI
from identity_support import PASSWORD

from warden.identity import Identity, PasswordPolicy, PasswordRules, PolicySettings, User

STRONG = "Kestrel-Harbour-42!"
"""Passes every rule of ``STRICT`` and is on no list."""
OTHER_STRONG = "Lantern-Meadow-77?"
EMAIL = "hq.nightjar@example.com"
DISPLAY_NAME = "Harriet Quill"

STRICT = PasswordRules(
    min_length=12, max_length=40, min_classes=3, max_repeat=3, forbid_user_details=True
)
"""Every rule configured, so each can fail on its own."""

# One candidate per rule, failing that rule alone under ``STRICT`` for ``EMAIL`` and
# ``DISPLAY_NAME``.
FAILING: dict[str, str] = {
    "min_length": "Ab1!xyzq",
    "max_length": "Ab1!" + "xyzwvutsrqponm" * 3,
    "min_classes": "lowercaseonlywords",
    "max_repeat": "Abc1!!!!defgh",
    "no_email": "Nightjar7!Zebra",
    "no_display_name": "Quill7!Zebrafish",
}

COMMON = "password1234"
"""On the built-in common-password list, and long enough for the seeded default."""

_priorities = itertools.count(1)


def settings(name: str | None = None, rules: PasswordRules = STRICT, **kw: Any) -> PolicySettings:
    return PolicySettings(name=name or f"policy-{uuid.uuid4().hex[:8]}", rules=rules, **kw)


async def set_default(identity: Identity, **kw: Any) -> PasswordPolicy:
    """Replace the default policy's settings (keeping its name)."""
    current = await identity.password_policies.default()
    new = replace(current.settings, **kw)
    return await identity.password_policies.update(
        current.id, new, expected_version=current.version, actor="test"
    )


async def pin_policy(identity: Identity, user: User, **kw: Any) -> PasswordPolicy:
    """A new policy pinned on ``user``."""
    policy = await identity.password_policies.create(
        settings(**kw), priority=next(_priorities) % 9000 + 1, actor="test"
    )
    await identity.password_policies.pin(user.id, policy.id, actor="test")
    return policy


def lifecycle_app(identity: Identity) -> FastAPI:
    app = FastAPI()
    identity.install(app)
    app.include_router(identity.auth_router(), prefix="/auth")
    app.include_router(identity.lifecycle_router(), prefix="/auth")
    return app


@asynccontextmanager
async def http(identity: Identity, address: str = "192.0.2.10") -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=lifecycle_app(identity), client=(address, 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


async def sign_in(c: httpx.AsyncClient, email: str, password: str = PASSWORD) -> dict[str, Any]:
    response = await c.post("/auth/sign-in", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def bearer(c: httpx.AsyncClient, email: str, password: str = PASSWORD) -> dict[str, str]:
    body = await sign_in(c, email, password)
    assert body["status"] == "signed_in", body
    return {"authorization": f"Bearer {body['access_token']}"}


def codes(response: httpx.Response) -> list[str]:
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["detail"] == "password not accepted"
    return [f["code"] for f in body["failures"]]


class Clock:
    """A settable clock for ``Identity(clock=...)``: real time plus an offset."""

    def __init__(self, now: Callable[[], float]) -> None:
        self._now = now
        self.offset = 0.0

    def __call__(self) -> float:
        return self._now() + self.offset

    def advance(self, *, days: float = 0, hours: float = 0) -> None:
        self.offset += days * 86400 + hours * 3600
