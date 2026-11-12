"""Invitation acceptance through single sign-on, against a local fake provider.

The product's accept-invitation screen posts the link's token to
``POST <auth>/sso/start``, as a urlencoded form or a JSON object. The token
is sealed into the login transaction under a key derived from the browser's
login binding (the database holds only the binding's hash), and the
callback, after the binding check and once the provider's identity is
verified, opens it and hands it to identity lifecycle's ``accept_with_sso``
with a pin that also writes the handoff code, so the acceptance, the pin and
the sign-in commit together or not at all.

Covers the sealing (nothing of the token in clear, a tampered or moved
sealed value refused), both start bodies and the malformed-body refusal, the
email match (ignoring case) and allowed domains, the subject pin, method and
status rules (#154), and a single consume under concurrent SSO and password
acceptance (#127).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any, Literal

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
from warden.identity.sso.sealing import open_invitation
from warden.identity.sso.service import COOKIE_NAME, SingleSignOn

pytestmark = pytest.mark.db

INVITEE = "invitee@example.com"
NEW_PASSWORD = "a brand new passphrase"
# 0.1.0a8 held the token in this cookie; nothing sets or reads it now.
A8_INVITATION_COOKIE = "__Secure-warden-sso-invitation"

Body = Literal["form", "json"]
BODIES: tuple[Body, ...] = ("form", "json")


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


async def post_start(client: httpx.AsyncClient, token: str, body: Body) -> httpx.Response:
    """The accept-invitation screen's post: a urlencoded form, or a JSON object."""
    if body == "json":
        return await client.post("/auth/sso/start", json={"invitation": token})
    return await client.post("/auth/sso/start", data={"invitation": token})


async def start_with(client: httpx.AsyncClient, token: str, body: Body = "form") -> Started:
    response = await post_start(client, token, body)
    assert response.status_code == 303, response.text
    location = httpx.URL(response.headers["location"])
    return Started({k: v for k, v in location.params.items()}, response)


async def accept(
    client: httpx.AsyncClient, idp: FakeIdp, token: str, body: Body = "form", **claims: Any
) -> dict[str, str]:
    """Start with the invitation, sign in at the provider, and land on the completion screen."""
    started = await start_with(client, token, body)
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


async def transactions(db: Database) -> list[dict[str, Any]]:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT * FROM warden.sso_login_transactions")
        names = [c.name for c in cur.description or ()]
        rows = await cur.fetchall()
    return [dict(zip(names, row, strict=True)) for row in rows]


async def sealed_of(db: Database, state: str) -> bytes:
    value = await one(
        db,
        "SELECT invitation_sealed FROM warden.sso_login_transactions WHERE state_hash = %s",
        hashlib.sha256(state.encode()).digest(),
    )
    assert value is not None
    return bytes(value)


async def set_sealed(db: Database, state: str, sealed: bytes) -> None:
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.sso_login_transactions SET invitation_sealed = %s WHERE state_hash = %s",
            (sealed, hashlib.sha256(state.encode()).digest()),
        )


async def transaction_count(db: Database) -> int:
    return int(await one(db, "SELECT count(*) FROM warden.sso_login_transactions"))


async def still_usable(identity: Identity, db: Database, user_id: uuid.UUID, token: str) -> None:
    """The invitation can still be accepted, here with a password."""
    assert await status_of(db, user_id) == "invited"
    accepted = await identity.invitations.accept_with_password(token, NEW_PASSWORD)
    assert accepted.user_id == user_id


# The round trip


@pytest.mark.parametrize("body_type", BODIES)
@pytest.mark.parametrize("method", [SignInMethod.PASSWORD_AND_SSO, SignInMethod.SSO_ONLY])
async def test_an_invitation_is_accepted_through_single_sign_on(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
    method: SignInMethod,
    body_type: Body,
) -> None:
    user_id, token = await invite(identity, mail, method=method, grants=(StagedGrant("viewer"),))
    # The provider's address differs from the invited one only in case.
    landed = await accept(
        client, idp, token, body_type, sub="s-invitee", email="Invitee@Example.COM"
    )
    body = await signed_in(client, landed)
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


@pytest.mark.parametrize("body_type", BODIES)
async def test_the_start_seals_the_token_in_the_transaction(
    client: httpx.AsyncClient,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
    body_type: Body,
) -> None:
    _, token = await invite(identity, mail)
    started = await start_with(client, token, body_type)
    assert token not in started.response.headers["location"]
    # One cookie, the login binding; the token no longer rides in a cookie.
    cookies = started.response.headers.get_list("set-cookie")
    assert [c.split("=", 1)[0] for c in cookies] == [COOKIE_NAME]
    assert token not in " ".join(cookies)
    binding = client.cookies[COOKIE_NAME]

    rows = await transactions(db)
    assert len(rows) == 1
    row = rows[0]
    assert "invitation_hash" not in row
    sealed = row["invitation_sealed"]
    assert isinstance(sealed, bytes) and len(sealed) == 71
    # Nothing of the token, or of its hash, is in clear anywhere in the row.
    digest = hashlib.sha256(token.encode()).digest()
    for value in row.values():
        assert token not in str(value)
        assert digest.hex() not in str(value)
        if isinstance(value, bytes):
            assert token.encode() not in value
            assert digest not in value
    # It opens only with the browser's binding, bound to this row's state.
    assert open_invitation(sealed, binding=binding, state_hash=bytes(row["state_hash"])) == token
    assert bytes(row["binding_hash"]) == hashlib.sha256(binding.encode()).digest()


async def test_a_tampered_sealed_value_is_refused_and_leaves_the_invitation_usable(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    started = await start_with(client, token)
    tampered = bytearray(await sealed_of(db, started.state))
    tampered[-1] ^= 0x01
    await set_sealed(db, started.state, bytes(tampered))
    landed = await callback(
        client, provider_code(idp, started, sub="s-invitee", email=INVITEE), started.state
    )
    assert completion(landed) == {"error": "sso_failed"}
    refusal = (await audit_rows(db, "warden.identity.sso.sign_in"))[-1]
    assert refusal["outcome"] == "failure"
    assert refusal["details"] == {"reason": "invitation_not_bound"}
    assert await acceptance_rows(db) == []
    assert await pin_of(db, user_id) is None
    assert await handoffs_of(db, user_id) == 0
    await still_usable(identity, db, user_id, token)


async def test_a_sealed_value_moved_to_another_transaction_does_not_open(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    # Someone who can write the table moves the victim's sealed invitation
    # into a transaction of their own, to accept it with their own identity.
    victim_id, victim_token = await invite(identity, mail)
    own_id, own_token = await invite(identity, mail, "mallory@example.com")
    victim = await start_with(client, victim_token)
    own = await start_with(client, own_token)
    await set_sealed(db, own.state, await sealed_of(db, victim.state))
    landed = await callback(
        client, provider_code(idp, own, sub="s-mallory", email=INVITEE), own.state
    )
    assert completion(landed) == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "invitation_not_bound"
    assert await acceptance_rows(db) == []
    assert await pin_of(db, victim_id) is None
    await still_usable(identity, db, victim_id, victim_token)
    await still_usable(identity, db, own_id, own_token)


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


async def test_the_acceptance_must_finish_in_the_browser_that_started(
    client: httpx.AsyncClient,
    app: FastAPI,
    idp: FakeIdp,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
) -> None:
    user_id, token = await invite(identity, mail)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.20", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as other:
        # Another browser with no login cookie, then with one of its own.
        for expected in ("no_cookie", "binding_mismatch"):
            started = await start_with(client, token)
            if expected == "binding_mismatch":
                await other.get("/auth/sso/start")
            landed = await callback(
                other, provider_code(idp, started, sub="s-invitee", email=INVITEE), started.state
            )
            assert completion(landed) == {"error": "sso_failed"}
            assert (await sso_reasons(db))[-1] == expected
    assert await pin_of(db, user_id) is None
    await still_usable(identity, db, user_id, token)


async def test_an_invitation_cookie_does_not_turn_a_sign_in_into_an_acceptance(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    # A browser still holding 0.1.0a8's invitation cookie signs in as usual.
    user_id, token = await invite(identity, mail)
    response = await client.get("/auth/sso/start")
    started = Started(dict(httpx.URL(response.headers["location"]).params.items()), response)
    client.cookies.set(A8_INVITATION_COOKIE, token, domain="app.example.com", path="/auth/sso")
    landed = await callback(
        client, provider_code(idp, started, sub="s-invitee", email=INVITEE), started.state
    )
    assert completion(landed) == {"error": "sso_failed"}
    assert (await sso_reasons(db))[-1] == "user_inactive"
    await still_usable(identity, db, user_id, token)


FORM = "application/x-www-form-urlencoded"
JSON = "application/json"
MULTIPART = "multipart/form-data; boundary=b"


def _bodies(token: str) -> list[tuple[str | None, bytes]]:
    """Start bodies that must each be refused: (Content-Type, body).

    Most carry a well-formed, live token, so only the body's shape is wrong.
    """
    dumped = json.dumps
    part = f'--b\r\nContent-Disposition: form-data; name="invitation"\r\n\r\n{token}\r\n--b--'
    return [
        # A urlencoded form: missing, empty, malformed or repeated.
        (FORM, b""),
        (FORM, b"other=1"),
        (FORM, b"invitation="),
        (FORM, b"invitation=nope"),
        (FORM, f"invitation={'A' * 44}".encode()),
        (FORM, f"invitation={token}&invitation={token}".encode()),
        (FORM, f"invitation={token}&junk".encode()),
        (FORM, f"invitation={token}%0A".encode()),
        (FORM, f"invitation={token}\xff".encode("latin-1")),
        (FORM, dumped({"invitation": token}).encode()),
        (FORM, f"invitation={token}&pad={'x' * 4096}".encode()),
        # A JSON object: missing, mistyped, malformed or repeated.
        (JSON, b""),
        (JSON, b"{"),
        (JSON, b"{}"),
        (JSON, b"null"),
        (JSON, dumped([token]).encode()),
        (JSON, dumped(token).encode()),
        (JSON, dumped({"invitation": None}).encode()),
        (JSON, dumped({"invitation": 42}).encode()),
        (JSON, dumped({"invitation": [token]}).encode()),
        (JSON, dumped({"invitation": "nope"}).encode()),
        (JSON, dumped({"invitation": token + "\n"}).encode()),
        (JSON, f'{{"invitation": "{token}", "invitation": "{token}"}}'.encode()),
        (JSON, f"invitation={token}".encode()),
        (JSON, dumped({"invitation": token, "pad": "x" * 4096}).encode()),
        # Anything else.
        (None, f"invitation={token}".encode()),
        ("text/plain", f"invitation={token}".encode()),
        ("application/jsonx", dumped({"invitation": token}).encode()),
        (MULTIPART, part.encode()),
    ]


async def test_a_malformed_start_body_fails_at_the_start(
    client: httpx.AsyncClient, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    user_id, token = await invite(identity, mail)
    cases = _bodies(token)
    for content_type, content in cases:
        headers = {} if content_type is None else {"content-type": content_type}
        response = await client.post("/auth/sso/start", content=content, headers=headers)
        case = (content_type, content[:80])
        assert response.status_code in (302, 303), case
        assert response.headers["location"] == f"{COMPLETION}?error=sso_failed", case
        assert (await sso_reasons(db))[-1] == "invitation_malformed", case
    assert len(await sso_reasons(db)) == len(cases)
    assert await transaction_count(db) == 0
    await still_usable(identity, db, user_id, token)


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON",
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=UTF-8",
    ],
)
async def test_the_start_body_is_chosen_by_content_type(
    client: httpx.AsyncClient,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
    content_type: str,
) -> None:
    _, token = await invite(identity, mail)
    if "json" in content_type.lower():
        content = json.dumps({"invitation": token, "other": "ignored"}).encode()
    else:
        content = f"invitation={token}&other=ignored".encode()
    response = await client.post(
        "/auth/sso/start", content=content, headers={"content-type": content_type}
    )
    assert response.status_code == 303, response.text
    assert token not in response.headers["location"]
    assert await transaction_count(db) == 1


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
        if not sso_won:
            # The callback lost the race at lifecycle's consume, and not
            # earlier for some other reason (which would make the race vacuous).
            assert (await sso_reasons(db))[-1] == "invitation_refused"
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
