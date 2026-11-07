"""Live check: a real browser and warden's WebAuthn routes (ruling P10).

Marked ``integration`` (skipped by default). Chromium, driven by Playwright,
loads a page from this directory and runs every ceremony through the
DevTools WebAuthn domain's virtual authenticators: a USB security key that
cannot verify the user and keeps no resident key, and a platform passkey
with resident keys and user verification. warden runs over a testcontainers
Postgres behind a small HTTP server on 127.0.0.1, and the page is loaded as
``http://localhost:<port>``, so the relying party ID is ``localhost``.

    WARDEN_IT_WEBAUTHN_PORT   a free port in the slot's own block

Install Chromium for Playwright first (``python -m playwright install
chromium``; see CLAUDE.md). Each flow asserts what the page saw and what
warden recorded.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows
from webauthn_live_support import (
    PASSKEY,
    SECURITY_KEY,
    LiveBrowser,
    LiveServer,
    live_app,
    live_config,
    mail_link,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity, SignInMethod, User

pytestmark = [pytest.mark.integration, pytest.mark.db]

PORT_TEXT = os.environ.get("WARDEN_IT_WEBAUTHN_PORT")

if not PORT_TEXT:
    pytest.skip("live WebAuthn check not configured", allow_module_level=True)

assert PORT_TEXT
PORT = int(PORT_TEXT)

SIGN_IN = "warden.identity.sign_in"
REFUSAL = {"detail": "authentication failed"}


@pytest.fixture
def config() -> WardenConfig:
    return live_config(PORT)


@pytest.fixture
async def server(identity: Identity) -> AsyncIterator[LiveServer]:
    async with LiveServer(live_app(identity), PORT) as live:
        yield live


@pytest.fixture
async def browser(server: LiveServer) -> AsyncIterator[LiveBrowser]:
    async with LiveBrowser(server.origin) as live:
        yield live


@pytest.fixture
async def admin(server: LiveServer, make_user: UserFactory) -> AsyncIterator[httpx.AsyncClient]:
    """The administrator's own client, signed in over the same live server."""
    user = await make_user("admin@example.com", roles=("admin",))
    async with httpx.AsyncClient(base_url=server.origin, timeout=10) as client:
        answer = await client.post(
            "/auth/sign-in", json={"email": user.email, "password": PASSWORD}
        )
        assert answer.status_code == 200, answer.text
        client.headers["authorization"] = f"Bearer {answer.json()['access_token']}"
        yield client


# What warden holds.


async def credentials(db: Database, user: User) -> list[dict[str, Any]]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT id, credential_id, sign_count, transports, discoverable, user_verified,"
            " nickname FROM warden.webauthn_credentials WHERE user_id = %s ORDER BY created_at",
            (user.id,),
        )
        names = (
            "id",
            "credential_id",
            "sign_count",
            "transports",
            "discoverable",
            "user_verified",
            "nickname",
        )
        return [dict(zip(names, row, strict=True)) for row in await cur.fetchall()]


async def live_sessions(db: Database, user: User) -> list[list[str]]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT amr FROM warden.sessions WHERE user_id = %s AND revoked_at IS NULL"
            " ORDER BY created_at",
            (user.id,),
        )
        return [list(row[0]) for row in await cur.fetchall()]


async def open_sign_in_challenges(db: Database) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.webauthn_challenges"
            " WHERE purpose = 'authentication' AND user_id IS NULL AND consumed_at IS NULL"
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def successes(db: Database, action: str, user: User) -> list[dict[str, Any]]:
    return [
        r
        for r in await audit_rows(db, action)
        if r["outcome"] == "success" and r["resource_id"] == str(user.id)
    ]


def ok(outcome: dict[str, Any]) -> dict[str, Any]:
    """The flow ran to the end in the browser and warden accepted every step."""
    assert outcome["error"] is None, outcome
    assert all(step["status"] in (200, 201) for step in outcome["steps"]), outcome
    return outcome


def last_step(outcome: dict[str, Any]) -> dict[str, Any]:
    step: dict[str, Any] = outcome["steps"][-1]
    return step


def same_credential(held: dict[str, Any], virtual: dict[str, Any]) -> bool:
    return bytes(held["credential_id"]) == virtual["credential_id"]


async def no_credential_material(db: Database, *secrets: str) -> None:
    """Nothing a ceremony or a session carried reached the audit trail."""
    trail = str(await audit_rows(db))
    for secret in secrets:
        assert secret not in trail


# The flows.


async def test_password_then_a_security_key_as_second_factor(
    browser: LiveBrowser,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
) -> None:
    alice = await make_user("alice@example.com")
    key = await browser.add_authenticator(SECURITY_KEY)
    await browser.open("/")

    # Signed in with the password alone, Alice adds a security key.
    signed_in = await browser.act("sign-in", email=alice.email, password=PASSWORD)
    assert last_step(signed_in)["body"]["status"] == "signed_in"
    added = await browser.act("register-key", nickname="Desk key")
    ok(added)
    options, confirmed = added["steps"]
    assert options["body"]["public_key"]["authenticatorSelection"]["userVerification"] == (
        "preferred"
    )
    assert confirmed["status"] == 200
    assert confirmed["body"]["credential"]["nickname"] == "Desk key"
    assert confirmed["body"]["credential"]["discoverable"] is False
    assert len(confirmed["body"]["recovery_codes"]) == 10

    (held,) = await credentials(db, alice)
    (virtual,) = await browser.credentials(key)
    assert same_credential(held, virtual)
    assert str(held["id"]) == confirmed["body"]["credential"]["id"]
    assert (held["discoverable"], held["user_verified"]) == (False, False)
    assert "usb" in held["transports"]
    (registered,) = await successes(db, "warden.identity.mfa.webauthn.registered", alice)
    assert registered["actor"] == str(alice.id)

    # Signing in again now asks for the second factor, and the key answers it.
    await browser.open("/")
    challenged = await browser.act("sign-in", email=alice.email, password=PASSWORD)
    body = last_step(challenged)["body"]
    assert body["status"] == "mfa_required"
    assert "webauthn" in body["methods"]
    verified = await browser.act("verify-key")
    ok(verified)
    options, answer = verified["steps"]
    allowed = options["body"]["public_key"]["allowCredentials"]
    (virtual,) = await browser.credentials(key)
    assert [entry["id"] for entry in allowed] == [virtual["id"]]
    assert answer["status"] == 200
    principal = await identity.authenticate(answer["body"]["access_token"])
    assert principal.user_id == alice.id
    assert principal.amr == ("pwd", "hwk")

    assert await live_sessions(db, alice) == [["pwd"], ["pwd", "hwk"]]
    events = await successes(db, SIGN_IN, alice)
    assert events[-1]["details"]["amr"] == ["pwd", "hwk"]
    # The second factor was answered first time: no refusal reached the trail.
    assert await audit_rows(db, "warden.identity.mfa.verify") == []
    (virtual,) = await browser.credentials(key)
    (held,) = await credentials(db, alice)
    assert held["sign_count"] == virtual["sign_count"] > 0
    await no_credential_material(
        db, answer["body"]["access_token"], answer["body"]["refresh_token"], body["challenge"]
    )


async def test_a_registered_passkey_signs_in_with_no_email(
    browser: LiveBrowser, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    bob = await make_user("bob@example.com")
    key = await browser.add_authenticator(PASSKEY)
    await browser.open("/")
    await browser.act("sign-in", email=bob.email, password=PASSWORD)
    added = await browser.act("register-key", nickname="Laptop")
    ok(added)
    assert last_step(added)["body"]["credential"]["discoverable"] is True
    (held,) = await credentials(db, bob)
    assert (held["discoverable"], held["user_verified"]) == (True, True)
    assert "internal" in held["transports"]

    # A fresh page: no session, no email typed; the passkey alone signs in.
    await browser.open("/")
    signed_in = await browser.act("passkey-sign-in")
    ok(signed_in)
    options, answer = signed_in["steps"]
    assert options["sent"] == [] and answer["sent"] == ["credential"]
    assert options["body"]["public_key"]["userVerification"] == "required"
    assert "allowCredentials" not in options["body"]["public_key"] or (
        options["body"]["public_key"]["allowCredentials"] == []
    )
    assert answer["status"] == 200
    principal = await identity.authenticate(answer["body"]["access_token"])
    assert principal.user_id == bob.id
    assert principal.amr == ("hwk", "mfa")

    assert (await live_sessions(db, bob))[-1] == ["hwk", "mfa"]
    event = (await successes(db, SIGN_IN, bob))[-1]
    assert event["details"] == {"amr": ["hwk", "mfa"], "credential_id": str(held["id"])}
    (virtual,) = await browser.credentials(key)
    assert same_credential(held, virtual)
    assert virtual["is_resident"] is True
    await no_credential_material(db, answer["body"]["access_token"])


async def test_passkey_sign_in_is_refused_when_the_authenticator_cannot_verify_the_user(
    browser: LiveBrowser, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    carol = await make_user("carol@example.com")
    key = await browser.add_authenticator(PASSKEY)
    await browser.open("/")
    await browser.act("sign-in", email=carol.email, password=PASSWORD)
    ok(await browser.act("register-key"))
    await browser.open("/")
    sessions_before = await live_sessions(db, carol)
    trail_before = len(await audit_rows(db, SIGN_IN))
    open_before = await open_sign_in_challenges(db)

    # The authenticator now fails to verify the user. warden asks for user
    # verification, so the browser refuses the ceremony and nothing reaches
    # the sign-in route.
    await browser.set_user_verified(key, verified=False)
    refused = await browser.act("passkey-sign-in")
    assert refused["error"] == "NotAllowedError"
    (options,) = refused["steps"]
    assert options["status"] == 200
    assert options["body"]["public_key"]["userVerification"] == "required"
    assert "access_token" not in str(refused)

    assert await live_sessions(db, carol) == sessions_before
    assert len(await audit_rows(db, SIGN_IN)) == trail_before
    assert await open_sign_in_challenges(db) == open_before + 1

    # The same key, verifying the user again, signs in: the refusal was user
    # verification and nothing else.
    await browser.set_user_verified(key, verified=True)
    await browser.open("/")
    signed_in = await browser.act("passkey-sign-in")
    ok(signed_in)
    principal = await identity.authenticate(last_step(signed_in)["body"]["access_token"])
    assert (principal.user_id, principal.amr) == (carol.id, ("hwk", "mfa"))


async def test_a_passkey_only_invitation_is_accepted_with_a_passkey(
    browser: LiveBrowser,
    admin: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    mail: RecordingSender,
) -> None:
    invited = await admin.post(
        "/admin/invitations",
        json={
            "email": "dana@example.com",
            "display_name": "Dana Example",
            "sign_in_method": "passkey_only",
            "roles": [{"role": "viewer"}],
        },
    )
    assert invited.status_code == 201, invited.text
    dana_id = uuid.UUID(invited.json()["user_id"])
    token = mail.token()
    link = mail_link(mail)
    assert link.startswith(f"http://localhost:{PORT}/invitation?t=")

    # Dana follows the link from the mail and accepts with a passkey.
    key = await browser.add_authenticator(PASSKEY)
    await browser.open(link.removeprefix(f"http://localhost:{PORT}"))
    accepted = await browser.act("accept-invitation")
    ok(accepted)
    options, answer = accepted["steps"]
    selection = options["body"]["public_key"]["authenticatorSelection"]
    assert (selection["residentKey"], selection["userVerification"]) == ("required", "required")
    assert answer["status"] == 200
    assert answer["body"]["status"] == "accepted"
    assert answer["body"]["email"] == "dana@example.com"
    assert "access_token" not in answer["body"]

    dana = await identity.users.get(dana_id)
    assert dana is not None
    assert dana.status.value == "active"
    assert dana.sign_in_method is SignInMethod.PASSKEY_ONLY
    assert await identity.roles.roles_of(dana.id) == ["viewer"]
    (held,) = await credentials(db, dana)
    (virtual,) = await browser.credentials(key)
    assert same_credential(held, virtual)
    assert (held["discoverable"], held["user_verified"]) == (True, True)
    (event,) = [
        r
        for r in await audit_rows(db, "warden.identity.invitation.accepted")
        if r["outcome"] == "success"
    ]
    assert event["resource_id"] == str(dana.id)
    assert event["details"]["method"] == "passkey"

    # The link is spent: following it again is the uniform refusal.
    again = await browser.act("accept-invitation")
    assert last_step(again)["status"] == 401
    assert last_step(again)["body"] == REFUSAL

    # Dana signs in with the passkey alone.
    await browser.open("/")
    signed_in = await browser.act("passkey-sign-in")
    ok(signed_in)
    principal = await identity.authenticate(last_step(signed_in)["body"]["access_token"])
    assert (principal.user_id, principal.amr) == (dana.id, ("hwk", "mfa"))
    await no_credential_material(db, token)


async def test_the_administrators_reset_then_a_registration_link(
    browser: LiveBrowser,
    admin: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    erin = await make_user("erin@example.com", display_name="Erin Example")
    lost = await browser.add_authenticator(PASSKEY)
    await browser.open("/")
    await browser.act("sign-in", email=erin.email, password=PASSWORD)
    ok(await browser.act("register-key"))
    (old,) = await credentials(db, erin)
    moved = await admin.post(
        f"/admin/users/{erin.id}/sign-in-method", json={"sign_in_method": "passkey_only"}
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["has_passkey"] is True

    # Erin loses the authenticator. The administrator resets her second
    # factors, which ends her sessions, then sends her a registration link.
    await browser.remove_authenticator(lost)
    reset = await admin.delete(f"/admin/users/{erin.id}/mfa")
    assert reset.status_code == 204
    assert await credentials(db, erin) == []
    assert await live_sessions(db, erin) == []
    (event,) = await successes(db, "warden.identity.mfa.reset", erin)
    assert event["details"]["webauthn_removed"] == 1
    sent = await admin.post(f"/admin/users/{erin.id}/passkey-registration")
    assert sent.status_code == 202, sent.text
    token = mail.token()
    link = mail_link(mail)
    assert link.startswith(f"http://localhost:{PORT}/passkey?t=")

    # Erin follows the link on a new authenticator and registers a passkey.
    key = await browser.add_authenticator(PASSKEY)
    await browser.open(link.removeprefix(f"http://localhost:{PORT}"))
    registered = await browser.act("register-from-link", nickname="New phone")
    ok(registered)
    answer = last_step(registered)
    assert answer["status"] == 200
    assert answer["body"]["status"] == "registered"
    assert answer["body"]["credential"]["nickname"] == "New phone"
    assert "access_token" not in answer["body"]
    (held,) = await credentials(db, erin)
    assert held["id"] != old["id"]
    (virtual,) = await browser.credentials(key)
    assert same_credential(held, virtual)
    (linked,) = await successes(db, "warden.identity.passkey.registered", erin)
    assert linked["details"]["credential_id"] == str(held["id"])
    (link_sent,) = await successes(db, "warden.identity.passkey.link_sent", erin)
    assert link_sent["actor"] != str(erin.id)

    # The new passkey signs Erin in; the link is spent.
    await browser.open("/")
    signed_in = await browser.act("passkey-sign-in")
    ok(signed_in)
    principal = await identity.authenticate(last_step(signed_in)["body"]["access_token"])
    assert (principal.user_id, principal.amr) == (erin.id, ("hwk", "mfa"))
    await browser.open(link.removeprefix(f"http://localhost:{PORT}"))
    again = await browser.act("register-from-link")
    assert last_step(again)["status"] == 401
    assert last_step(again)["body"] == REFUSAL
    await no_credential_material(db, token)
