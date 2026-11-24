"""Helpers shared by the sample console's tests (imported as ``console_support``)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import httpx

PASSWORD = "correct horse battery staple"
# The console's address in the tests, and so the WebAuthn origin a browser reports.
ORIGIN = "http://localhost:8040"
# Wave 9's software authenticator lives beside the WebAuthn tests.
WEBAUTHN_TESTS = Path(__file__).resolve().parents[1] / "identity" / "webauthn"
IDENTITY_TESTS = Path(__file__).resolve().parents[1] / "identity"


async def make_user(console: Any, email: str, *roles: str) -> Any:
    user = await console.identity.users.create(email, actor="test", password=PASSWORD)
    for role in roles:
        await console.identity.roles.assign(user.id, role, actor="test")
    return user


def identity_support() -> Any:
    """The identity tests' helpers (``tests/identity/identity_support.py``)."""
    if str(IDENTITY_TESTS) not in sys.path:
        sys.path.insert(0, str(IDENTITY_TESTS))
    import identity_support as module

    return module


async def http_sign_in(
    client: httpx.AsyncClient, email: str, password: str = PASSWORD
) -> httpx.Response:
    """``POST /auth/sign-in`` carried through the second factor: the final response."""
    response: httpx.Response = await identity_support().http_sign_in(client, email, password)
    return response


async def key_session(console: Any, email: str) -> str:
    """An access token for a user holding no second factor, as if signed in with a key."""
    user = await console.identity.users.get_by_email(email)
    pair = await identity_support().direct_session(console.identity, user.id, ("pwd", "hwk"))
    return str(pair.access_token)


async def sign_in(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> str:
    """A password sign-in carried through its second factor (always required since 0.2.0)."""
    answer = await identity_support().http_sign_in(client, email, password)
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["status"] == "signed_in"
    return str(body["access_token"])


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def assert_strict_csp(response: httpx.Response) -> None:
    policy = response.headers.get("content-security-policy")
    assert policy, f"no Content Security Policy on {response.request.url}"
    directives = {
        part.split()[0]: part.split()[1:] for part in (p.strip() for p in policy.split(";")) if part
    }
    assert directives["default-src"] == ["'none'"]
    assert directives["script-src"] == ["'self'"]
    assert directives["style-src"] == ["'self'"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert directives["object-src"] == ["'none'"]
    assert "unsafe" not in policy
    assert response.headers.get("x-content-type-options") == "nosniff"


def console_config(**sections: Any) -> Any:
    from warden.config import parse_config

    data: dict[str, Any] = {
        "http": {
            "public_base_url": ORIGIN,
            "accept_invitation_link": "/accept?t={token}",
            "reset_password_link": "/reset?t={token}",
            "sso_completion_link": "/signed-in",
            "passkey_registration_link": "/passkey?t={token}",
        },
        "identity": {},
        "mail": {"from_address": "console@example.com"},
        "syslog": {"enabled": True, "host": "127.0.0.1", "port": 9, "transport": "udp"},
    }
    for name, values in sections.items():
        data[name] = {**data.get(name, {}), **values}
    return parse_config(data)


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


def soft_authenticator() -> Any:
    """Wave 9's software authenticator module (``tests/identity/webauthn``)."""
    if str(WEBAUTHN_TESTS) not in sys.path:
        sys.path.insert(0, str(WEBAUTHN_TESTS))
    import soft_authenticator as module

    return module


def authenticator(**options: Any) -> Any:
    """A software authenticator that makes passkeys: discoverable, verifying the user."""
    module = soft_authenticator()
    return module.SoftwareAuthenticator(**{"resident": True, "user_verifying": True, **options})
