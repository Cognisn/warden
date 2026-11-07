"""The sample console's passkey and security key screens against a real Postgres.

Each test walks what a screen does, through warden's routes as the console
mounts them, with wave 9's software authenticator standing in for the
browser and the key: registration with a nickname, listing, renaming and
removing; the second factor and forced enrolment with a key; signing in with
a passkey alone; the administrator's ``passkey_only`` method, reset and
registration link followed from the outbox; and a ``passkey_only``
invitation accepted with a passkey.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from console_support import (
    ORIGIN,
    PASSWORD,
    assert_strict_csp,
    authenticator,
    bearer,
    make_user,
    sign_in,
)

pytestmark = pytest.mark.db

STATIC = Path(__file__).resolve().parents[2] / "examples" / "console" / "static"
SCRIPTS = STATIC / "js"
REFUSAL = b'{"detail":"authentication failed"}'


@asynccontextmanager
async def browser(console: Any) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=console.app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as c:
        yield c


def link_token(text: str, path: str) -> str:
    link = next(word for word in text.split() if f"{path}?t=" in word)
    return parse_qs(urlsplit(link.rstrip(".")).query)["t"][0]


async def outbox_message(client: httpx.AsyncClient, to: str, kind: str) -> dict[str, Any]:
    messages = (await client.get("/api/outbox")).json()["messages"]
    return next(m for m in messages if m["to"] == to and m["kind"] == kind)


async def register_key(
    client: httpx.AsyncClient, token: str, key: Any, nickname: str | None = None
) -> httpx.Response:
    """The account screen's "Register" button, signed in."""
    options = await client.post("/auth/webauthn/registration", json={}, headers=bearer(token))
    assert options.status_code == 200, options.text
    credential = key.register(options.json()["public_key"], origin=ORIGIN)
    return await client.post(
        "/auth/webauthn/registration/confirm",
        json={"credential": credential, "nickname": nickname},
        headers=bearer(token),
    )


async def passkey_sign_in(client: httpx.AsyncClient, key: Any) -> httpx.Response:
    """The sign-in screen's "Sign in with a passkey" button (or its autofill)."""
    options = await client.post("/auth/passkey/options")
    assert options.status_code == 200, options.text
    public_key = options.json()["public_key"]
    assert "allowCredentials" not in public_key or not public_key["allowCredentials"]
    credential = key.authenticate(public_key, origin=ORIGIN)
    return await client.post("/auth/passkey/sign-in", json={"credential": credential})


async def amr(client: httpx.AsyncClient, token: str) -> list[str]:
    me = await client.get("/api/me", headers=bearer(token))
    assert me.status_code == 200, me.text
    return list(me.json()["amr"])


# The pages and the routes the screens call


def test_the_console_has_a_page_at_the_registration_links_path(console: Any) -> None:
    from examples.console.app import PAGES

    link = console.identity.config.http.passkey_registration_link
    assert link is not None
    assert urlsplit(link).path in PAGES


async def test_the_registration_link_page_is_served_with_the_policy(
    client: httpx.AsyncClient,
) -> None:
    for page in ("/passkey?t=x", "/accept?t=x", "/"):
        answer = await client.get(page)
        assert answer.status_code == 200, page
        assert answer.headers["content-type"].startswith("text/html")
        assert_strict_csp(answer)
    script = await client.get("/static/js/webauthn.js")
    assert script.status_code == 200
    assert script.headers["content-type"].startswith("text/javascript")
    assert_strict_csp(script)


def warden_calls() -> set[tuple[str, str]]:
    """Every (method, path) a screen sends to a warden router, path parameters as ``{}``."""
    found: set[tuple[str, str]] = set()
    pattern = re.compile(r'call\("([A-Z]+)", `\$\{(auth|admin|audit|keys)\}([^`?]*)')
    for script in SCRIPTS.glob("*.js"):
        for method, prefix, rest in pattern.findall(script.read_text(encoding="utf-8")):
            # A trailing ``${query}`` straight after a path segment is a query string.
            rest = re.sub(r"(?<=[^/])\$\{[^}]*\}$", "", rest)
            path = re.sub(r"\$\{[^}]*\}", "{}", rest)
            found.add((method, f"/{prefix}{path}"))
    return found


def test_the_screens_call_the_passkey_routes() -> None:
    calls = warden_calls()
    for expected in (
        ("POST", "/auth/passkey/options"),
        ("POST", "/auth/passkey/sign-in"),
        ("POST", "/auth/webauthn/verify/options"),
        ("POST", "/auth/webauthn/verify"),
        ("POST", "/auth/webauthn/registration"),
        ("POST", "/auth/webauthn/registration/confirm"),
        ("GET", "/auth/webauthn/credentials"),
        ("PATCH", "/auth/webauthn/credentials/{}"),
        ("DELETE", "/auth/webauthn/credentials/{}"),
        ("POST", "/auth/invitations/accept/passkey/options"),
        ("POST", "/auth/invitations/accept/passkey"),
        ("POST", "/auth/passkey-registration/options"),
        ("POST", "/auth/passkey-registration"),
        ("POST", "/admin/users/{}/passkey-registration"),
        ("DELETE", "/admin/users/{}/mfa"),
    ):
        assert expected in calls, expected


def test_every_warden_route_a_screen_calls_is_mounted(console: Any) -> None:
    schema = console.app.openapi()["paths"]
    mounted = {
        (method.upper(), re.sub(r"\{[^}]*\}", "{}", path))
        for path, operations in schema.items()
        for method in operations
    }
    calls = warden_calls()
    assert len(calls) > 30
    assert calls <= mounted, sorted(calls - mounted)


def test_the_sign_in_form_offers_passkeys_by_autofill_and_by_button() -> None:
    signin = (SCRIPTS / "signin.js").read_text(encoding="utf-8")
    webauthn = (SCRIPTS / "webauthn.js").read_text(encoding="utf-8")
    assert 'autocomplete: "username webauthn"' in signin
    assert 'mediation: "conditional"' in signin
    assert "Sign in with a passkey" in signin
    assert "isConditionalMediationAvailable" in webauthn
    # The Level 3 helpers where the browser has them, with a fallback where it does not.
    for owner, name, argument in (
        ("PublicKeyCredential", "parseCreationOptionsFromJSON", "json"),
        ("PublicKeyCredential", "parseRequestOptionsFromJSON", "json"),
        ("credential", "toJSON", ""),
    ):
        assert f'typeof {owner}.{name} === "function"' in webauthn, name
        assert f"return {owner}.{name}({argument});" in webauthn, name


def test_no_script_writes_markup_or_evaluates_text() -> None:
    for script in SCRIPTS.glob("*.js"):
        source = script.read_text(encoding="utf-8")
        for forbidden in (
            r"\.(inner|outer)HTML\b",
            r"\binsertAdjacentHTML\(",
            r"\bdocument\.write",
            r"\beval\(",
            r"\bFunction\(",
        ):
            assert not re.search(forbidden, source), f"{forbidden} in {script.name}"


# The user's own keys


async def test_a_user_registers_lists_renames_and_removes_a_key(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "alice@example.com", "editor")
    token = await sign_in(client, "alice@example.com")
    key = authenticator()

    registered = await register_key(client, token, key, "Desk key")
    assert registered.status_code == 200, registered.text
    body = registered.json()
    assert body["credential"]["nickname"] == "Desk key"
    assert body["credential"]["discoverable"] is True
    assert len(body["recovery_codes"]) > 0

    listed = await client.get("/auth/webauthn/credentials", headers=bearer(token))
    assert [c["nickname"] for c in listed.json()["credentials"]] == ["Desk key"]
    credential_id = body["credential"]["id"]

    renamed = await client.patch(
        f"/auth/webauthn/credentials/{credential_id}",
        json={"nickname": "Blue key"},
        headers=bearer(token),
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["credential"]["nickname"] == "Blue key"

    removed = await client.delete(
        f"/auth/webauthn/credentials/{credential_id}", headers=bearer(token)
    )
    assert removed.status_code == 204
    listed = await client.get("/auth/webauthn/credentials", headers=bearer(token))
    assert listed.json()["credentials"] == []


async def test_a_passkey_sign_in_round_trip_through_the_sample(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "alice@example.com", "editor")
    token = await sign_in(client, "alice@example.com")
    key = authenticator(backup_eligible=True, backed_up=True, counter_step=0)
    assert (await register_key(client, token, key, "Phone")).status_code == 200
    await client.post("/auth/sign-out", headers=bearer(token))

    signed_in = await passkey_sign_in(client, key)
    assert signed_in.status_code == 200, signed_in.text
    tokens = signed_in.json()
    assert tokens["status"] == "signed_in"
    assert await amr(client, tokens["access_token"]) == ["hwk", "mfa"]

    renewed = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert renewed.status_code == 200


async def test_a_passkey_nobody_registered_gets_the_uniform_refusal(
    console: Any, client: httpx.AsyncClient
) -> None:
    stranger = authenticator()
    # A credential made for this relying party but never registered with it.
    stranger.register(
        {"rp": {"id": "localhost"}, "user": {"id": "AAAA"}, "challenge": "AAAA"}, origin=ORIGIN
    )
    refused = await passkey_sign_in(client, stranger)
    assert refused.status_code == 401
    assert refused.content == REFUSAL


# Second factor and forced enrolment


async def test_a_key_is_offered_beside_the_code_when_mfa_is_required(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "alice@example.com", "editor")
    token = await sign_in(client, "alice@example.com")
    key = authenticator(resident=False, user_verifying=False)
    assert (await register_key(client, token, key)).status_code == 200

    first = await client.post(
        "/auth/sign-in", json={"email": "alice@example.com", "password": PASSWORD}
    )
    body = first.json()
    assert body["status"] == "mfa_required"
    assert body["methods"] == ["webauthn"]

    options = await client.post(
        "/auth/webauthn/verify/options", json={"challenge": body["challenge"]}
    )
    assert options.status_code == 200, options.text
    credential = key.authenticate(options.json()["public_key"], origin=ORIGIN)
    verified = await client.post(
        "/auth/webauthn/verify", json={"challenge": body["challenge"], "credential": credential}
    )
    assert verified.status_code == 200, verified.text
    assert await amr(client, verified.json()["access_token"]) == ["pwd", "hwk"]


async def test_forced_enrolment_with_a_key_then_the_last_factor_is_kept(
    make_console: Any,
) -> None:
    console = await make_console(identity={"require_mfa": True})
    await make_user(console, "dana@example.com", "editor")
    key = authenticator()
    async with browser(console) as client:
        first = await client.post(
            "/auth/sign-in", json={"email": "dana@example.com", "password": PASSWORD}
        )
        body = first.json()
        assert body["status"] == "mfa_enrolment_required"
        challenge = body["challenge"]

        options = await client.post("/auth/webauthn/registration", json={"challenge": challenge})
        assert options.status_code == 200, options.text
        credential = key.register(options.json()["public_key"], origin=ORIGIN)
        confirmed = await client.post(
            "/auth/webauthn/registration/confirm",
            json={"challenge": challenge, "credential": credential, "nickname": "Keyring"},
        )
        assert confirmed.status_code == 200, confirmed.text
        session = confirmed.json()
        assert session["status"] == "signed_in"
        assert len(session["recovery_codes"]) > 0
        token = session["access_token"]

        # The account screen's Remove on the only second factor: refused, and why.
        key_id = session["credential"]["id"]
        refused = await client.delete(f"/auth/webauthn/credentials/{key_id}", headers=bearer(token))
        assert refused.status_code == 409
        assert "last second factor" in refused.json()["detail"]
        still = await client.get("/auth/webauthn/credentials", headers=bearer(token))
        assert len(still.json()["credentials"]) == 1


# Administration: passkey_only, the reset and the registration link


async def test_an_administrator_moves_a_user_to_passkey_only_and_sends_a_link(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "admin@example.com", "administrator")
    admin = await sign_in(client, "admin@example.com")
    bob = await make_user(console, "bob@example.com", "viewer")

    moved = await client.post(
        f"/admin/users/{bob.id}/sign-in-method",
        json={"sign_in_method": "passkey_only"},
        headers=bearer(admin),
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["user"]["sign_in_method"] == "passkey_only"
    assert moved.json()["has_passkey"] is False

    password = await client.post(
        "/auth/sign-in", json={"email": "bob@example.com", "password": PASSWORD}
    )
    assert password.status_code == 401

    sent = await client.post(f"/admin/users/{bob.id}/passkey-registration", headers=bearer(admin))
    assert sent.status_code == 202, sent.text
    message = await outbox_message(client, "bob@example.com", "passkey_registration")
    token = link_token(message["text"], "/passkey")

    # The /passkey page: options, the browser's answer, and the codes shown once.
    key = authenticator()
    options = await client.post("/auth/passkey-registration/options", json={"token": token})
    assert options.status_code == 200, options.text
    credential = key.register(options.json()["public_key"], origin=ORIGIN)
    registered = await client.post(
        "/auth/passkey-registration",
        json={"token": token, "credential": credential, "nickname": "Bob's key"},
    )
    assert registered.status_code == 200, registered.text
    assert registered.json()["status"] == "registered"
    assert len(registered.json()["recovery_codes"]) > 0

    again = await client.post("/auth/passkey-registration/options", json={"token": token})
    assert again.status_code == 401

    signed_in = await passkey_sign_in(client, key)
    assert signed_in.status_code == 200, signed_in.text

    detail = await client.get(f"/admin/users/{bob.id}", headers=bearer(admin))
    assert detail.json()["webauthn_credentials"] == 1


async def test_the_administrators_reset_removes_keys_and_ends_passkey_sign_in(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "admin@example.com", "administrator")
    admin = await sign_in(client, "admin@example.com")
    await make_user(console, "erin@example.com", "viewer")
    erin = await sign_in(client, "erin@example.com")
    key = authenticator()
    assert (await register_key(client, erin, key)).status_code == 200
    user = await console.identity.users.get_by_email("erin@example.com")

    reset = await client.delete(f"/admin/users/{user.id}/mfa", headers=bearer(admin))
    assert reset.status_code == 204

    refused = await passkey_sign_in(client, key)
    assert refused.status_code == 401
    assert refused.content == REFUSAL
    detail = await client.get(f"/admin/users/{user.id}", headers=bearer(admin))
    assert detail.json()["webauthn_credentials"] == 0


async def test_a_passkey_only_invitation_accepted_with_a_passkey(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "admin@example.com", "administrator")
    admin = await sign_in(client, "admin@example.com")
    invited = await client.post(
        "/admin/invitations",
        headers=bearer(admin),
        json={
            "email": "frank@example.org",
            "sign_in_method": "passkey_only",
            "roles": [{"role": "viewer"}],
        },
    )
    assert invited.status_code == 201, invited.text
    message = await outbox_message(client, "frank@example.org", "invitation")
    token = link_token(message["text"], "/accept")

    by_password = await client.post(
        "/auth/invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert by_password.status_code == 409

    key = authenticator()
    options = await client.post("/auth/invitations/accept/passkey/options", json={"token": token})
    assert options.status_code == 200, options.text
    credential = key.register(options.json()["public_key"], origin=ORIGIN)
    accepted = await client.post(
        "/auth/invitations/accept/passkey",
        json={"token": token, "credential": credential, "nickname": "Frank's passkey"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["email"] == "frank@example.org"
    assert len(accepted.json()["recovery_codes"]) > 0

    signed_in = await passkey_sign_in(client, key)
    assert signed_in.status_code == 200, signed_in.text
    me = await client.get("/api/me", headers=bearer(signed_in.json()["access_token"]))
    assert me.json()["roles"] == ["viewer"]
