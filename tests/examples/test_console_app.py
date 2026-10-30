"""The sample console against a real Postgres: mounting, the Content Security
Policy, a password sign-in, an invitation followed from the outbox, and the
product's own permission-gated notes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from console_support import PASSWORD

pytestmark = pytest.mark.db

STATIC = Path(__file__).resolve().parents[2] / "examples" / "console" / "static"


async def make_user(console: Any, email: str, *roles: str) -> Any:
    user = await console.identity.users.create(email, actor="test", password=PASSWORD)
    for role in roles:
        await console.identity.roles.assign(user.id, role, actor="test")
    return user


async def sign_in(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> str:
    answer = await client.post("/auth/sign-in", json={"email": email, "password": password})
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


# Mounting


async def test_every_router_is_mounted_under_the_configured_prefixes(console: Any) -> None:
    # The schema lists every mounted route, however FastAPI nests included routers.
    paths = set(console.app.openapi()["paths"])
    expected = {
        "/auth/sign-in",
        "/auth/totp/enrolment",
        "/auth/refresh",
        "/auth/sso/start",
        "/auth/sso/handoff",
        "/auth/invitations/accept",
        "/auth/password-reset",
        "/admin/users",
        "/admin/roles",
        "/admin/invitations",
        "/admin/api-keys",
        "/admin/sso/settings",
        "/admin/sso/test",
        "/audit/events",
        "/audit/export",
        "/audit/verify",
        "/audit/syslog/status",
        "/audit/syslog/test",
        "/keys/jwks.json",
        "/keys/jwks-historical.json",
        "/api/notes",
        "/api/outbox",
    }
    assert expected <= paths, sorted(expected - paths)


# Content Security Policy


def static_files() -> list[Path]:
    return sorted(p for p in STATIC.rglob("*") if p.is_file())


def test_the_console_has_pages_and_assets() -> None:
    names = {p.name for p in static_files()}
    assert "index.html" in names
    assert any(n.endswith(".js") for n in names)
    assert any(n.endswith(".css") for n in names)


def test_no_page_carries_inline_script_or_style() -> None:
    for page in STATIC.rglob("*.html"):
        html = page.read_text(encoding="utf-8")
        for tag in re.finditer(r"<script\b[^>]*>", html, re.IGNORECASE):
            assert "src=" in tag.group(0), f"inline script in {page.name}"
        assert not re.search(r"<style\b", html, re.IGNORECASE), f"style element in {page.name}"
        assert not re.search(r"\sstyle\s*=", html, re.IGNORECASE), f"style attribute in {page.name}"
        assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE), (
            f"event handler in {page.name}"
        )
        assert not re.search(r"javascript:", html, re.IGNORECASE), f"script URL in {page.name}"


async def test_every_page_and_asset_is_served_with_the_policy(client: httpx.AsyncClient) -> None:
    for path in static_files():
        url = "/static/" + path.relative_to(STATIC).as_posix()
        answer = await client.get(url)
        assert answer.status_code == 200, url
        assert_strict_csp(answer)
    for page in ("/", "/accept?t=x", "/reset?t=x", "/signed-in?code=x"):
        answer = await client.get(page)
        assert answer.status_code == 200, page
        assert answer.headers["content-type"].startswith("text/html")
        assert_strict_csp(answer)


async def test_warden_and_product_answers_carry_the_policy_too(client: httpx.AsyncClient) -> None:
    for answer in (
        await client.post("/auth/sign-in", json={"email": "nobody@example.com", "password": "x"}),
        await client.get("/api/notes"),
        await client.get("/keys/jwks.json"),
    ):
        assert_strict_csp(answer)


# Sign-in


async def test_a_password_sign_in_round_trip(console: Any, client: httpx.AsyncClient) -> None:
    await make_user(console, "alice@example.com", "editor")
    first = await client.post(
        "/auth/sign-in", json={"email": "alice@example.com", "password": PASSWORD}
    )
    assert first.status_code == 200
    tokens = first.json()

    me = await client.get("/api/me", headers=bearer(tokens["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "alice@example.com"
    assert "notes.write" in me.json()["permissions"]

    renewed = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert renewed.status_code == 200
    fresh = renewed.json()
    assert fresh["refresh_token"] != tokens["refresh_token"]

    out = await client.post("/auth/sign-out", headers=bearer(fresh["access_token"]))
    assert out.status_code == 204
    again = await client.post("/auth/refresh", json={"refresh_token": fresh["refresh_token"]})
    assert again.status_code == 401


async def test_a_wrong_password_gets_the_uniform_refusal(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "bob@example.com", "viewer")
    wrong = await client.post("/auth/sign-in", json={"email": "bob@example.com", "password": "no"})
    unknown = await client.post(
        "/auth/sign-in", json={"email": "nobody@example.com", "password": "no"}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.content == unknown.content


# Lifecycle


def link_token(text: str, path: str) -> str:
    link = next(word for word in text.split() if f"{path}?t=" in word)
    return parse_qs(urlsplit(link.rstrip(".")).query)["t"][0]


async def test_an_invitation_followed_from_the_outbox(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "admin@example.com", "administrator")
    admin = await sign_in(client, "admin@example.com")

    invited = await client.post(
        "/admin/invitations",
        headers=bearer(admin),
        json={"email": "carol@example.org", "roles": [{"role": "viewer"}]},
    )
    assert invited.status_code == 201, invited.text

    outbox = (await client.get("/api/outbox")).json()["messages"]
    message = next(m for m in outbox if m["to"] == "carol@example.org")
    assert message["kind"] == "invitation"
    token = link_token(message["text"], "/accept")

    accepted = await client.post(
        "/auth/invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {"status": "accepted", "email": "carol@example.org"}

    carol = await sign_in(client, "carol@example.org")
    me = (await client.get("/api/me", headers=bearer(carol))).json()
    assert me["roles"] == ["viewer"]

    reused = await client.post(
        "/auth/invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert reused.status_code == 401


# Product permissions, resource scope and product audit events


async def test_a_product_route_refused_without_its_permission_and_allowed_with_it(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "viewer@example.com", "viewer")
    await make_user(console, "editor@example.com", "editor")
    viewer = await sign_in(client, "viewer@example.com")
    editor = await sign_in(client, "editor@example.com")
    note = {"title": "Rota", "body": "Week one"}

    assert (await client.post("/api/notes", json=note)).status_code == 401
    assert (await client.post("/api/notes", json=note, headers=bearer(viewer))).status_code == 403
    created = await client.post("/api/notes", json=note, headers=bearer(editor))
    assert created.status_code == 201, created.text

    listed = await client.get("/api/notes", headers=bearer(viewer))
    assert listed.status_code == 200
    assert [n["title"] for n in listed.json()["notes"]] == ["Rota"]


async def test_the_resource_scope_hook_narrows_editing_to_the_owner(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "owner@example.com", "editor")
    await make_user(console, "other@example.com", "editor")
    await make_user(console, "lead@example.com", "notes-admin")
    owner = await sign_in(client, "owner@example.com")
    other = await sign_in(client, "other@example.com")
    lead = await sign_in(client, "lead@example.com")

    created = await client.post(
        "/api/notes", json={"title": "A", "body": ""}, headers=bearer(owner)
    )
    note_id = created.json()["id"]
    change = {"title": "B", "body": "changed"}

    refused = await client.put(f"/api/notes/{note_id}", json=change, headers=bearer(other))
    assert refused.status_code == 403
    by_owner = await client.put(f"/api/notes/{note_id}", json=change, headers=bearer(owner))
    assert by_owner.status_code == 200
    by_lead = await client.delete(f"/api/notes/{note_id}", headers=bearer(lead))
    assert by_lead.status_code == 204


async def test_note_changes_are_product_audit_events(
    console: Any, client: httpx.AsyncClient
) -> None:
    editor_user = await make_user(console, "writer@example.com", "editor")
    await make_user(console, "auditor@example.com", "auditor")
    editor = await sign_in(client, "writer@example.com")
    auditor = await sign_in(client, "auditor@example.com")

    created = await client.post(
        "/api/notes", json={"title": "T", "body": ""}, headers=bearer(editor)
    )
    events = await client.get(
        "/audit/events", params={"action": "console.note.created"}, headers=bearer(auditor)
    )
    assert events.status_code == 200, events.text
    [event] = events.json()["events"]
    assert event["actor"] == str(editor_user.id)
    assert event["resource_type"] == "note"
    assert event["resource_id"] == created.json()["id"]


# Bootstrap


async def test_bootstrap_creates_the_first_administrator(
    console: Any, client: httpx.AsyncClient
) -> None:
    from examples.console.bootstrap import create_administrator

    created = await create_administrator(console.identity, "first@example.com", PASSWORD)
    assert created.email == "first@example.com"
    token = await sign_in(client, "first@example.com")
    users = await client.get("/admin/users", headers=bearer(token))
    assert users.status_code == 200
    assert [u["email"] for u in users.json()["users"]] == ["first@example.com"]

    again = await create_administrator(console.identity, "first@example.com", PASSWORD)
    assert again.id == created.id
