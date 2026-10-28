"""Invitation acceptance through single sign-on, against a local fake provider.

The product's accept-invitation screen posts the link's token to
``POST <auth>/sso/start``. The login transaction records the token's hash,
the browser holds the token in a second HttpOnly cookie, and the callback,
once the provider's identity is verified, hands it to identity lifecycle's
``accept_with_sso`` with a pin that also writes the handoff code, so the
acceptance, the pin and the sign-in commit together or not at all.

Covers the email match (ignoring case) and allowed domains, the subject pin,
method and status rules (#154), and a single consume under concurrent SSO
and password acceptance (#127).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, ISSUER, FakeIdp
from fastapi import FastAPI
from identity_support import RecordingSender, UserFactory, audit_rows, race
from sso_support import (
    CLIENT_SECRET_NAME,
    COMPLETION,
    Started,
    callback,
    completion,
    handoff,
    provider_code,
    sign_in,
    sso_config,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, SignInMethod, UserStatus
from warden.identity.invitations import InvitationMismatch, StagedGrant
from warden.identity.sso.errors import SsoError
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import COOKIE_NAME, INVITATION_COOKIE_NAME, SingleSignOn

pytestmark = pytest.mark.db

INVITEE = "invitee@example.com"
NEW_PASSWORD = "a brand new passphrase"


@pytest.fixture
def config() -> WardenConfig:
    return sso_config(allowed_email_domains="example.com,example.org")


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    return secrets


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def sso(identity: Identity, idp: FakeIdp, secrets: Any) -> SingleSignOn:
    identity.sso = SingleSignOn(
        identity.config,
        identity.db,
        identity.sessions,
        identity.policy,
        secrets,
        http=ProviderHttp(idp.client()),
        settings_max_age=0,
    )
    return identity.sso


@pytest.fixture
def app(identity: Identity, sso: SingleSignOn) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.lifecycle_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


async def invite(
    identity: Identity,
    mail: RecordingSender,
    email: str = INVITEE,
    *,
    method: SignInMethod = SignInMethod.PASSWORD_AND_SSO,
    grants: tuple[StagedGrant, ...] = (),
) -> tuple[uuid.UUID, str]:
    invitation = await identity.invitations.create(
        email, actor="admin-1", sign_in_method=method, grants=grants
    )
    return invitation.user_id, mail.token()


async def start_with(client: httpx.AsyncClient, token: str) -> Started:
    """The accept-invitation screen's form, posted by the browser."""
    response = await client.post("/auth/sso/start", data={"invitation": token})
    assert response.status_code == 303, response.text
    location = httpx.URL(response.headers["location"])
    return Started({k: v for k, v in location.params.items()}, response)


async def accept(
    client: httpx.AsyncClient, idp: FakeIdp, token: str, **claims: Any
) -> dict[str, str]:
    """Start with the invitation, sign in at the provider, and land on the completion screen."""
    started = await start_with(client, token)
    return completion(await callback(client, provider_code(idp, started, **claims), started.state))


async def signed_in(client: httpx.AsyncClient, landed: dict[str, str]) -> dict[str, Any]:
    assert "code" in landed, landed
    response = await handoff(client, landed["code"])
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert body["status"] == "signed_in"
    return body


async def one(db: Database, query: str, *args: object) -> Any:
    async with db.connection() as conn:
        cur = await conn.execute(query, args)
        row = await cur.fetchone()
    return None if row is None else row[0]


async def status_of(db: Database, user_id: uuid.UUID) -> str | None:
    value = await one(db, "SELECT status FROM warden.users WHERE id = %s", user_id)
    return None if value is None else str(value)


async def pin_of(db: Database, user_id: uuid.UUID) -> tuple[str, str] | None:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT issuer, subject FROM warden.sso_identities WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    return None if row is None else (str(row[0]), str(row[1]))


async def handoffs_of(db: Database, user_id: uuid.UUID) -> int:
    return int(
        await one(db, "SELECT count(*) FROM warden.sso_handoff_codes WHERE user_id = %s", user_id)
    )


async def sso_reasons(db: Database) -> list[str]:
    return [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sso.sign_in")]


async def acceptance_rows(db: Database) -> list[dict[str, Any]]:
    return await audit_rows(db, "warden.identity.invitation.accepted")


async def still_usable(identity: Identity, db: Database, user_id: uuid.UUID, token: str) -> None:
    """The invitation can still be accepted, here with a password."""
    assert await status_of(db, user_id) == "invited"
    accepted = await identity.invitations.accept_with_password(token, NEW_PASSWORD)
    assert accepted.user_id == user_id


# The round trip


@pytest.mark.parametrize("method", [SignInMethod.PASSWORD_AND_SSO, SignInMethod.SSO_ONLY])
async def test_an_invitation_is_accepted_through_single_sign_on(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
    method: SignInMethod,
) -> None:
    user_id, token = await invite(identity, mail, method=method, grants=(StagedGrant("viewer"),))
    # The provider's address differs from the invited one only in case.
    body = await signed_in(
        client, await accept(client, idp, token, sub="s-invitee", email="Invitee@Example.COM")
    )
    principal = await identity.authenticate(body["access_token"])
    assert principal.user_id == user_id
    assert principal.amr == ("sso",)
    assert await status_of(db, user_id) == "active"
    assert await pin_of(db, user_id) == (ISSUER, "s-invitee")
    assert await one(db, "SELECT password_hash FROM warden.users WHERE id = %s", user_id) is None
    assert await identity.roles.roles_of(user_id) == ["viewer"]
    accepted = await acceptance_rows(db)
    assert accepted[-1]["outcome"] == "success"
    assert accepted[-1]["details"]["method"] == "sso"
    assert accepted[-1]["details"]["issuer"] == ISSUER
    pinned = await audit_rows(db, "warden.identity.sso.subject_pinned")
    assert [r["resource_id"] for r in pinned] == [str(user_id)]


async def test_the_accepted_user_then_signs_in_by_subject(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    await signed_in(client, await accept(client, idp, token, sub="s-invitee", email=INVITEE))
    # A normal sign-in, with no invitation, matches the pinned subject.
    response = await sign_in(client, idp, sub="s-invitee", email=INVITEE)
    assert response.status_code == 200, response.text
    principal = await identity.authenticate(response.json()["access_token"])
    assert principal.user_id == user_id
    # Another subject presenting the same address is refused.
    refused = await sign_in(client, idp, sub="s-other", email=INVITEE)
    assert refused.status_code == 401
    assert (await sso_reasons(db))[-1] == "subject_mismatch"


async def test_the_start_sets_an_invitation_cookie_and_keeps_the_token_out_of_urls(
    client: httpx.AsyncClient, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    _, token = await invite(identity, mail)
    started = await start_with(client, token)
    assert token not in started.response.headers["location"]
    cookies = started.response.headers.get_list("set-cookie")
    invitation = next(c for c in cookies if c.startswith(f"{INVITATION_COOKIE_NAME}="))
    lowered = invitation.lower()
    assert "httponly" in lowered
    assert "secure" in lowered
    assert "samesite=lax" in lowered
    assert "path=/auth/sso" in lowered
    assert any(c.startswith(f"{COOKIE_NAME}=") for c in cookies)
    # The transaction holds only the token's hash; the token itself is nowhere in the table.
    async with db.connection() as conn:
        cur = await conn.execute("SELECT * FROM warden.sso_login_transactions")
        rows = await cur.fetchall()
    assert len(rows) == 1
    assert hashlib.sha256(token.encode()).digest() in rows[0]
    assert all(token not in str(value) for value in rows[0])


async def test_the_callback_clears_the_invitation_cookie(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender
) -> None:
    _, token = await invite(identity, mail)
    started = await start_with(client, token)
    landed = await callback(
        client, provider_code(idp, started, sub="s-invitee", email=INVITEE), started.state
    )
    cleared = [
        c
        for c in landed.headers.get_list("set-cookie")
        if c.startswith(f"{INVITATION_COOKIE_NAME}=")
    ]
    assert cleared and ("max-age=0" in cleared[0].lower() or "expires=" in cleared[0].lower())
    assert INVITATION_COOKIE_NAME not in client.cookies


# The email must match, and the domain must be allowed


async def test_an_identity_for_another_address_leaves_the_invitation_usable(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    landed = await accept(client, idp, token, sub="s-someone", email="someone@example.com")
    assert landed == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "invitation_mismatch"
    assert (await acceptance_rows(db))[-1]["details"]["reason"] == "identity_mismatch"
    assert await pin_of(db, user_id) is None
    assert await handoffs_of(db, user_id) == 0
    # The right identity can still accept it through single sign-on.
    await signed_in(client, await accept(client, idp, token, sub="s-invitee", email=INVITEE))
    assert await pin_of(db, user_id) == (ISSUER, "s-invitee")


async def test_a_disallowed_domain_leaves_the_invitation_usable(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail, "outsider@example.net")
    landed = await accept(client, idp, token, sub="s-outsider", email="outsider@example.net")
    assert landed == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "domain_not_allowed"
    assert await pin_of(db, user_id) is None
    await still_usable(identity, db, user_id, token)


async def test_an_unverified_email_leaves_the_invitation_usable(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    landed = await accept(client, idp, token, sub="s-invitee", email=INVITEE, email_verified=False)
    assert landed == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "email_unverified"
    await still_usable(identity, db, user_id, token)


# The subject pin


async def test_a_subject_pinned_to_another_user_is_refused_and_nothing_is_accepted(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    identity: Identity,
    mail: RecordingSender,
    make_user: UserFactory,
    db: Database,
) -> None:
    alice = await make_user("alice@example.com")
    await signed_in(client, {"code": await _plain_code(client, idp, "s-alice", alice.email)})
    user_id, token = await invite(identity, mail)
    landed = await accept(client, idp, token, sub="s-alice", email=INVITEE)
    assert landed == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "already_pinned"
    assert await pin_of(db, user_id) is None
    assert await handoffs_of(db, user_id) == 0
    assert await pin_of(db, alice.id) == (ISSUER, "s-alice")
    await still_usable(identity, db, user_id, token)


async def _plain_code(client: httpx.AsyncClient, idp: FakeIdp, sub: str, email: str) -> str:
    response = await client.get("/auth/sso/start")
    params = dict(httpx.URL(response.headers["location"]).params.items())
    started = Started(params, response)
    landed = completion(
        await callback(client, provider_code(idp, started, sub=sub, email=email), started.state)
    )
    return landed["code"]


# Method and status (#154)


async def test_a_password_for_an_sso_only_invitation_leaves_it_usable_for_sso(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail, method=SignInMethod.SSO_ONLY)
    refused = await client.post(
        "/auth/invitations/accept", json={"token": token, "password": NEW_PASSWORD}
    )
    assert refused.status_code == 409
    assert await status_of(db, user_id) == "invited"
    await signed_in(client, await accept(client, idp, token, sub="s-invitee", email=INVITEE))
    assert await status_of(db, user_id) == "active"


async def test_a_status_refusal_uses_the_invitation_up(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    await identity.users.set_status(user_id, UserStatus.SUSPENDED, actor="admin-1")
    landed = await accept(client, idp, token, sub="s-invitee", email=INVITEE)
    assert landed == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "invitation_refused"
    assert (await acceptance_rows(db))[-1]["details"]["reason"] == "user_suspended"
    assert await status_of(db, user_id) == "suspended"
    assert await pin_of(db, user_id) is None
    assert await handoffs_of(db, user_id) == 0
    # Spent: back in the invited state, neither method can use it.
    await identity.users.set_status(user_id, UserStatus.INVITED, actor="admin-1")
    with pytest.raises(AuthenticationRefused):
        await identity.invitations.accept_with_password(token, NEW_PASSWORD)
    assert await accept(client, idp, token, sub="s-invitee", email=INVITEE) == {
        "error": "sso_failed"
    }
    assert (await acceptance_rows(db))[-1]["details"]["reason"] == "token_not_live"


async def test_an_accepted_invitation_cannot_be_used_again(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    _, token = await invite(identity, mail)
    await signed_in(client, await accept(client, idp, token, sub="s-invitee", email=INVITEE))
    assert await accept(client, idp, token, sub="s-invitee", email=INVITEE) == {
        "error": "sso_failed"
    }
    assert (await sso_reasons(db))[-1] == "invitation_refused"


# The invitation is bound to the browser that started


async def test_the_invitation_must_come_from_the_browser_that_started(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    _, other_token = await invite(identity, mail, "second@example.com")
    for cookie in (None, other_token, "A" * 43):
        started = await start_with(client, token)
        client.cookies.delete(INVITATION_COOKIE_NAME)
        if cookie is not None:
            client.cookies.set(
                INVITATION_COOKIE_NAME, cookie, domain="app.example.com", path="/auth/sso"
            )
        landed = await callback(
            client, provider_code(idp, started, sub="s-invitee", email=INVITEE), started.state
        )
        assert completion(landed) == {"error": "sso_failed"}
        assert (await sso_reasons(db))[-1] == "invitation_not_bound"
    assert await pin_of(db, user_id) is None
    await still_usable(identity, db, user_id, token)


async def test_an_invitation_cookie_does_not_turn_a_sign_in_into_an_acceptance(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    response = await client.get("/auth/sso/start")
    started = Started(dict(httpx.URL(response.headers["location"]).params.items()), response)
    client.cookies.set(INVITATION_COOKIE_NAME, token, domain="app.example.com", path="/auth/sso")
    landed = await callback(
        client, provider_code(idp, started, sub="s-invitee", email=INVITEE), started.state
    )
    assert completion(landed) == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "user_inactive"
    await still_usable(identity, db, user_id, token)


async def test_a_malformed_invitation_fails_at_the_start(
    client: httpx.AsyncClient, db: Database
) -> None:
    for body in ({"invitation": "nope"}, {}, {"invitation": "A" * 44}):
        response = await client.post("/auth/sso/start", data=body)
        assert response.status_code in (302, 303)
        assert response.headers["location"] == f"{COMPLETION}?error=sso_failed"
        assert (await sso_reasons(db))[-1] == "invitation_malformed"
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.sso_login_transactions")
        row = await cur.fetchone()
    assert row is not None and row[0] == 0


# Single consume under concurrency (#127)


async def prepared_callback(
    sso: SingleSignOn, idp: FakeIdp, identity: Identity, token: str, sub: str, email: str
) -> Callable[[], Awaitable[str]]:
    """Start an acceptance and sign in at the provider; returns the callback, ready to race."""
    begun = await sso.begin(invitation=token)
    params = dict(httpx.URL(begun.redirect_url).params.items())
    code = idp.issue_code(
        idp.claims(sub=sub, email=email, nonce=params["nonce"]),
        challenge=params["code_challenge"],
    )
    return partial(
        sso.complete,
        state=params["state"],
        code=code,
        error=None,
        binding=begun.binding,
        invitation=token,
        invitations=identity.invitations,
    )


async def test_concurrent_sso_and_password_acceptances_use_an_invitation_once(
    sso: SingleSignOn, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    for round_ in range(5):
        email = f"race-{round_}@example.com"
        user_id, token = await invite(identity, mail, email)
        callback_ = await prepared_callback(sso, idp, identity, token, f"s-race-{round_}", email)
        password_ = partial(identity.invitations.accept_with_password, token, NEW_PASSWORD)
        results = await race(callback_, password_)
        succeeded = [r for r in results if not isinstance(r, BaseException)]
        assert len(succeeded) == 1, results
        assert all(
            isinstance(r, SsoError | AuthenticationRefused | InvitationMismatch)
            for r in results
            if r not in succeeded
        ), results
        sso_won = isinstance(results[0], str)
        # Exactly one method's effects: a pin and a handoff code, or a password.
        assert (await pin_of(db, user_id) is not None) is sso_won
        assert (await handoffs_of(db, user_id) == 1) is sso_won
        password = await one(db, "SELECT password_hash FROM warden.users WHERE id = %s", user_id)
        assert (password is not None) is not sso_won
        assert await status_of(db, user_id) == "active"
        successes = [r for r in await acceptance_rows(db) if r["resource_id"] == str(user_id)]
        assert [r["outcome"] for r in successes].count("success") == 1


async def test_concurrent_sso_acceptances_of_one_invitation_pin_one_subject(
    sso: SingleSignOn, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    callbacks = [
        await prepared_callback(sso, idp, identity, token, subject, INVITEE)
        for subject in ("s-1", "s-2", "s-3", "s-4")
    ]
    results = await race(*callbacks)
    assert sum(isinstance(r, str) for r in results) == 1, results
    assert all(isinstance(r, SsoError) for r in results if not isinstance(r, str)), results
    pin = await pin_of(db, user_id)
    assert pin is not None and pin[1] in {"s-1", "s-2", "s-3", "s-4"}
    assert await handoffs_of(db, user_id) == 1
