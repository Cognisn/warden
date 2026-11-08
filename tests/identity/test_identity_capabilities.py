"""What a deployment can do, asked up front: ``Identity.capabilities()`` and its two routes.

Each capability is checked against the route that enforces it: a test flips
the condition and shows the answer and the behaviour change together, so a
client that reads the capabilities can never be told something the route
then contradicts. The 503s and refusals stay as they are, as the backstop.
Single sign-on's agreement is in ``sso/test_sso_capabilities.py``.
"""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import FAST_HASHER, PASSWORD, MemorySecrets, RecordingSender

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, IdentityCapabilities, PermissionRegistry, User
from warden.keys import KeyStore

pytestmark = pytest.mark.db

DOMAIN = "https://app.example.com"
LOOPBACK = "http://127.0.0.1:8000"
ANONYMOUS_FIELDS = {"password_reset", "single_sign_on", "passkey_sign_in"}
ADMIN_FIELDS = {
    "mail_sender",
    "invitations",
    "password_reset",
    "passkey_registration_link",
    "single_sign_on",
    "webauthn",
}


def deployment(
    *,
    base: str = DOMAIN,
    invitation_link: bool = True,
    reset_link: bool = True,
    passkey_link: bool = True,
) -> WardenConfig:
    """A configuration; leaving out a required link needs identity's link check off."""
    http: dict[str, Any] = {"public_base_url": base}
    if invitation_link:
        http["accept_invitation_link"] = f"{base}/accept?t={{token}}"
    if reset_link:
        http["reset_password_link"] = f"{base}/reset?t={{token}}"
    if passkey_link:
        http["passkey_registration_link"] = f"{base}/passkey?t={{token}}"
    complete = invitation_link and reset_link
    return parse_config(
        {"http": http, "identity": {"require_mfa": False, "enabled": complete}},
    )


@dataclasses.dataclass
class Deployment:
    identity: Identity
    client: httpx.AsyncClient
    mail: RecordingSender
    admin: dict[str, str]
    app: FastAPI


@pytest.fixture
async def make(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> AsyncIterator[Any]:
    """Build an Identity with every router mounted, an administrator and a client."""
    opened: list[httpx.AsyncClient] = []

    async def build(config: WardenConfig, *, sender: bool = True) -> Deployment:
        mail = RecordingSender()
        identity = Identity(
            config,
            db,
            keys,
            permissions,
            secrets=secrets,
            hasher=FAST_HASHER,
            mail_sender=mail if sender else None,
        )
        app = FastAPI()
        identity.install(app)
        app.include_router(identity.auth_router(), prefix="/auth")
        app.include_router(identity.lifecycle_router(), prefix="/auth")
        app.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
        # A route that fails with a 500 is part of what is compared, not a test error.
        transport = httpx.ASGITransport(
            app=app, client=("192.0.2.10", 50000), raise_app_exceptions=False
        )
        client = httpx.AsyncClient(transport=transport, base_url=DOMAIN)
        opened.append(client)
        email = f"admin-{len(opened)}@example.com"
        user = await identity.users.create(email, actor="test", password=PASSWORD)
        await identity.roles.assign(user.id, "admin", actor="test")
        return Deployment(identity, client, mail, await bearer(identity, user), app)

    try:
        yield build
    finally:
        for client in opened:
            await client.aclose()


async def bearer(identity: Identity, user: User) -> dict[str, str]:
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is not None
    return {"authorization": f"Bearer {result.tokens.access_token}"}


async def member(d: Deployment, email: str) -> User:
    return await d.identity.users.create(email, actor="test", password=PASSWORD)


# The result


async def test_a_complete_deployment_can_do_everything_but_single_sign_on(make: Any) -> None:
    d = await make(deployment())
    capabilities = await d.identity.capabilities()
    assert capabilities == IdentityCapabilities(
        mail_sender=True,
        invitations=True,
        password_reset=True,
        passkey_registration_link=True,
        single_sign_on=False,
        webauthn=True,
    )


async def test_without_a_sender_nothing_that_mails_is_available(make: Any) -> None:
    d = await make(deployment(), sender=False)
    capabilities = await d.identity.capabilities()
    assert not capabilities.mail_sender
    assert not capabilities.invitations
    assert not capabilities.password_reset
    assert not capabilities.passkey_registration_link
    assert capabilities.webauthn


def test_the_result_is_frozen_and_only_booleans() -> None:
    assert dataclasses.is_dataclass(IdentityCapabilities)
    fields = dataclasses.fields(IdentityCapabilities)
    assert {f.name for f in fields} == ADMIN_FIELDS
    assert all(f.type in (bool, "bool") for f in fields)
    value = IdentityCapabilities(**dict.fromkeys(ADMIN_FIELDS, False))
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.mail_sender = True  # type: ignore[misc]


# Agreement: each capability and its route change together


@pytest.mark.parametrize("sender", [True, False])
async def test_mail_sender_agrees_with_the_admin_reset_route(make: Any, sender: bool) -> None:
    d = await make(deployment(), sender=sender)
    user = await member(d, "carol@example.com")
    answer = await d.client.post(f"/admin/users/{user.id}/password-reset", headers=d.admin)
    unconfigured = answer.status_code == 503 and answer.json() == {
        "detail": "mail is not configured"
    }
    assert (await d.identity.capabilities()).mail_sender is (not unconfigured)


@pytest.mark.parametrize(
    ("sender", "link"), [(True, True), (False, True), (True, False), (False, False)]
)
async def test_invitations_agree_with_the_invite_route(make: Any, sender: bool, link: bool) -> None:
    d = await make(deployment(invitation_link=link), sender=sender)
    answer = await d.client.post(
        "/admin/invitations", json={"email": "dave@example.org"}, headers=d.admin
    )
    sent = answer.status_code == 201
    assert sent is (sender and link)
    assert (await d.identity.capabilities()).invitations is sent
    assert len(d.mail.sent) == (1 if sent else 0)


@pytest.mark.parametrize(
    ("sender", "link"), [(True, True), (False, True), (True, False), (False, False)]
)
async def test_password_reset_agrees_with_both_reset_routes(
    make: Any, sender: bool, link: bool
) -> None:
    d = await make(deployment(reset_link=link), sender=sender)
    user = await member(d, "erin@example.com")
    by_admin = await d.client.post(f"/admin/users/{user.id}/password-reset", headers=d.admin)
    by_admin_sent = by_admin.status_code == 202
    # The public request always answers 202; whether a link went out is the outbox's.
    public = await d.client.post("/auth/password-reset", json={"email": user.email})
    assert public.status_code == 202
    sent = len(d.mail.sent) == 2
    assert by_admin_sent is sent is (sender and link)
    capabilities = await d.identity.capabilities()
    assert capabilities.password_reset is sent
    assert (await anonymous(d.client))["password_reset"] is sent


@pytest.mark.parametrize(
    ("sender", "link", "base"),
    [
        (True, True, DOMAIN),
        (False, True, DOMAIN),
        (True, False, DOMAIN),
        (True, True, LOOPBACK),
        (False, False, LOOPBACK),
    ],
)
async def test_passkey_registration_link_agrees_with_its_route(
    make: Any, sender: bool, link: bool, base: str
) -> None:
    d = await make(deployment(base=base, passkey_link=link), sender=sender)
    user = await member(d, "frank@example.com")
    answer = await d.client.post(f"/admin/users/{user.id}/passkey-registration", headers=d.admin)
    sent = answer.status_code == 202
    assert sent is (sender and link and base == DOMAIN)
    assert (await d.identity.capabilities()).passkey_registration_link is sent


@pytest.mark.parametrize("base", [DOMAIN, LOOPBACK])
async def test_webauthn_agrees_with_passkey_sign_in(make: Any, base: str) -> None:
    d = await make(deployment(base=base))
    options = await d.client.post("/auth/passkey/options")
    offered = options.status_code == 200
    assert offered is (base == DOMAIN)
    assert (await d.identity.capabilities()).webauthn is offered
    assert (await anonymous(d.client))["passkey_sign_in"] is offered


# GET <auth>/capabilities


async def anonymous(client: httpx.AsyncClient, **kw: Any) -> dict[str, Any]:
    answer = await client.get("/auth/capabilities", **kw)
    assert answer.status_code == 200, answer.text
    body: dict[str, Any] = answer.json()
    return body


async def test_the_anonymous_route_answers_exactly_the_sign_in_fields(make: Any) -> None:
    d = await make(deployment())
    answer = await d.client.get("/auth/capabilities")
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert set(body) == ANONYMOUS_FIELDS
    assert all(isinstance(value, bool) for value in body.values())
    capabilities = await d.identity.capabilities()
    assert body == {
        "password_reset": capabilities.password_reset,
        "single_sign_on": capabilities.single_sign_on,
        "passkey_sign_in": capabilities.webauthn,
    }


async def test_the_anonymous_route_reveals_no_configuration_value(make: Any) -> None:
    d = await make(deployment())
    text = (await d.client.get("/auth/capabilities")).text
    for value in ("example.com", "app.", "http", "token", "@", "127.0.0.1"):
        assert value not in text


async def test_the_anonymous_route_answers_every_caller_identically(make: Any) -> None:
    d = await make(deployment())
    plain = await d.client.get("/auth/capabilities")
    signed_in = await d.client.get("/auth/capabilities", headers=d.admin)
    garbage = await d.client.get("/auth/capabilities", headers={"authorization": "Bearer x"})
    transport = httpx.ASGITransport(app=d.app, client=("198.51.100.7", 1))
    async with httpx.AsyncClient(transport=transport, base_url=DOMAIN) as elsewhere:
        other = await elsewhere.get("/auth/capabilities")
    for answer in (signed_in, garbage, other):
        assert answer.status_code == plain.status_code == 200
        assert answer.content == plain.content
        assert dict(answer.headers) == dict(plain.headers)


async def test_the_anonymous_route_follows_the_deployment(make: Any) -> None:
    bare = await make(deployment(base=LOOPBACK), sender=False)
    assert await anonymous(bare.client) == dict.fromkeys(ANONYMOUS_FIELDS, False)


# GET <admin>/capabilities


async def test_the_admin_route_answers_every_capability_as_a_boolean(make: Any) -> None:
    d = await make(deployment(passkey_link=False), sender=True)
    answer = await d.client.get("/admin/capabilities", headers=d.admin)
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert set(body) == ADMIN_FIELDS
    assert all(isinstance(value, bool) for value in body.values())
    assert body == dataclasses.asdict(await d.identity.capabilities())
    assert body["passkey_registration_link"] is False
    assert body["mail_sender"] is True


async def test_the_admin_route_without_a_sender(make: Any) -> None:
    d = await make(deployment(), sender=False)
    body = (await d.client.get("/admin/capabilities", headers=d.admin)).json()
    assert body == {
        "mail_sender": False,
        "invitations": False,
        "password_reset": False,
        "passkey_registration_link": False,
        "single_sign_on": False,
        "webauthn": True,
    }


async def test_the_admin_route_needs_the_user_administration_permission(make: Any) -> None:
    d = await make(deployment())
    assert (await d.client.get("/admin/capabilities")).status_code == 401
    viewer = await member(d, "grace@example.com")
    await d.identity.roles.assign(viewer.id, "viewer", actor="test")
    forbidden = await d.client.get("/admin/capabilities", headers=await bearer(d.identity, viewer))
    assert forbidden.status_code == 403
