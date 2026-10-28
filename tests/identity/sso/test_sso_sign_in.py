"""Single sign-on end to end through warden's routes, against a local fake provider.

Covers PKCE, state and nonce, single-use login transactions bound to the
cookie, the one-time handoff code, account matching and subject pinning,
sessions issued as SSO, the fixed browser failure, and disabling.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, DROP, ISSUER, FakeIdp
from fastapi import FastAPI
from identity_support import PASSWORD, UserFactory, audit_rows, race
from sso_support import (
    CLIENT_SECRET_NAME,
    COMPLETION,
    callback,
    completion,
    handoff,
    provider_code,
    sign_in,
    sso_config,
    start,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, User, UserStatus
from warden.identity.sso.errors import SsoError
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import COOKIE_NAME, SingleSignOn

pytestmark = pytest.mark.db

ALICE = "alice@example.com"


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
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


@pytest.fixture
async def alice(make_user: UserFactory) -> User:
    return await make_user(ALICE)


async def tokens(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert body["status"] == "signed_in"
    return body


async def pin_of(db: Database, user_id: uuid.UUID) -> tuple[str, str] | None:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT issuer, subject FROM warden.sso_identities WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    return None if row is None else (str(row[0]), str(row[1]))


async def refusals(db: Database) -> list[str]:
    return [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sso.sign_in")]


async def sessions_of(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


# The round trip


async def test_a_pre_provisioned_user_signs_in(
    client: httpx.AsyncClient, idp: FakeIdp, identity: Identity, alice: User, db: Database
) -> None:
    body = await tokens(await sign_in(client, idp, sub="s-alice", email="Alice@Example.com"))
    principal = await identity.authenticate(body["access_token"])
    assert principal.user_id == alice.id
    assert principal.amr == ("sso",)
    assert await pin_of(db, alice.id) == (ISSUER, "s-alice")
    signed_in = await audit_rows(db, "warden.identity.sign_in")
    assert signed_in[-1]["outcome"] == "success"
    assert signed_in[-1]["details"]["amr"] == ["sso"]
    pinned = await audit_rows(db, "warden.identity.sso.subject_pinned")
    assert pinned[0]["resource_id"] == str(alice.id)


async def test_the_start_sends_pkce_state_and_nonce(client: httpx.AsyncClient) -> None:
    started = await start(client)
    params = started.params
    assert params["response_type"] == "code"
    assert params["client_id"] == "warden-client"
    assert params["redirect_uri"] == "https://app.example.com/auth/sso/callback"
    assert params["code_challenge_method"] == "S256"
    assert set(params["scope"].split()) == {"openid", "email", "profile"}
    assert len(params["state"]) >= 43 and len(params["nonce"]) >= 43
    assert len(params["code_challenge"]) == 43
    location = started.response.headers["location"]
    assert location.startswith(f"{ISSUER}/authorize?")


async def test_the_login_cookie_is_http_only_secure_and_same_site(
    client: httpx.AsyncClient,
) -> None:
    started = await start(client)
    cookie = started.response.headers["set-cookie"]
    attributes = {part.strip().lower() for part in cookie.split(";")}
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert "httponly" in attributes
    assert "secure" in attributes
    assert "samesite=lax" in attributes
    assert "path=/auth/sso" in attributes


async def test_the_verifier_reaches_only_the_token_endpoint(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User
) -> None:
    started = await start(client)
    code = provider_code(idp, started, sub="s-alice", email=ALICE)
    landed = completion(await callback(client, code, started.state))
    assert "code" in landed  # the fake checked S256(verifier) == challenge
    token_requests = [r for r in idp.requests if r.url.path.endswith("/token")]
    verifier = dict(httpx.QueryParams(token_requests[0].content.decode()))["code_verifier"]
    digest = hashlib.sha256(verifier.encode()).digest()
    assert (
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == started.params["code_challenge"]
    )
    assert verifier not in started.response.headers["location"]


async def test_no_token_ever_appears_in_a_url(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User
) -> None:
    started = await start(client)
    response = await callback(
        client, provider_code(idp, started, sub="s-alice", email=ALICE), started.state
    )
    landed = completion(response)
    assert set(landed) == {"code"}
    assert landed["code"].count(".") == 0  # not a JWT
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    body = await tokens(await handoff(client, landed["code"]))
    assert body["access_token"] not in response.headers["location"]


async def test_later_sign_ins_match_by_subject(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, identity: Identity
) -> None:
    await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    body = await tokens(await sign_in(client, idp, sub="s-alice", email="ALICE@example.com"))
    assert (await identity.authenticate(body["access_token"])).user_id == alice.id


# Account matching refusals


async def test_a_different_subject_for_a_pinned_user_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    response = await sign_in(client, idp, sub="s-forged", email=ALICE)
    assert response.json() == {"error": "sso_failed"}
    assert (await refusals(db))[-1] == "subject_mismatch"
    assert await pin_of(db, alice.id) == (ISSUER, "s-alice")
    assert await sessions_of(db, alice.id) == 1


async def test_an_email_that_disagrees_with_the_pinned_user_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, make_user: UserFactory, db: Database
) -> None:
    await make_user("bob@example.com")
    await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    response = await sign_in(client, idp, sub="s-alice", email="bob@example.com")
    assert response.status_code == 401
    assert (await refusals(db))[-1] == "email_mismatch"


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        ({"email_verified": False}, "email_unverified"),
        ({"email_verified": DROP}, "email_unverified"),
        ({"email": DROP}, "email_missing"),
        ({"email": "nobody@example.com"}, "no_account"),
        ({"email": "alice@example.net"}, "domain_not_allowed"),
    ],
)
async def test_first_sign_in_refusals(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    alice: User,
    db: Database,
    claims: dict[str, Any],
    reason: str,
) -> None:
    response = await sign_in(client, idp, **{"sub": "s-alice", "email": ALICE, **claims})
    assert response.status_code == 401
    assert (await refusals(db))[-1] == reason
    assert await pin_of(db, alice.id) is None


async def test_allowed_domains_are_checked_on_every_sign_in(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, sso: SingleSignOn, db: Database
) -> None:
    await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    await sso.settings.update(actor="admin", allowed_email_domains=["example.org"])
    response = await sign_in(client, idp, sub="s-alice", email=ALICE)
    assert response.status_code == 401
    assert (await refusals(db))[-1] == "domain_not_allowed"


@pytest.mark.parametrize("status", [UserStatus.SUSPENDED, UserStatus.DEACTIVATED])
async def test_a_user_who_is_not_active_gets_nothing(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    alice: User,
    identity: Identity,
    db: Database,
    status: UserStatus,
) -> None:
    await identity.users.set_status(alice.id, status, actor="test")
    response = await sign_in(client, idp, sub="s-alice", email=ALICE)
    assert response.status_code == 401
    assert (await refusals(db))[-1] == "user_inactive"
    assert await pin_of(db, alice.id) is None


async def test_an_invited_user_gets_nothing(
    client: httpx.AsyncClient, idp: FakeIdp, make_user: UserFactory, db: Database
) -> None:
    invited = await make_user("ivy@example.com", password=None, status=UserStatus.INVITED)
    response = await sign_in(client, idp, sub="s-ivy", email="ivy@example.com")
    assert response.status_code == 401
    assert await pin_of(db, invited.id) is None


async def test_a_user_suspended_before_the_handoff_gets_nothing(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, identity: Identity, db: Database
) -> None:
    started = await start(client)
    landed = completion(
        await callback(
            client, provider_code(idp, started, sub="s-alice", email=ALICE), started.state
        )
    )
    await identity.users.set_status(alice.id, UserStatus.SUSPENDED, actor="test")
    assert (await handoff(client, landed["code"])).status_code == 401
    await identity.users.set_status(alice.id, UserStatus.ACTIVE, actor="test")
    # The refusal used the code up.
    assert (await handoff(client, landed["code"])).status_code == 401
    assert await sessions_of(db, alice.id) == 0


# Token validation reaches the browser only as the fixed failure


async def test_a_wrong_nonce_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    response = await sign_in(client, idp, sub="s-alice", email=ALICE, nonce="forged")
    assert response.status_code == 401
    assert (await refusals(db))[-1] == "id_token_invalid:nonce"


async def test_the_browser_sees_one_fixed_failure_whatever_the_reason(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    locations = set()
    for claims in (
        {"nonce": "forged"},
        {"email": "nobody@example.com"},
        {"email_verified": False},
        {"aud": "another-client"},
    ):
        started = await start(client)
        code = provider_code(idp, started, **{"sub": "s-alice", "email": ALICE, **claims})
        response = await callback(client, code, started.state)
        locations.add(response.headers["location"])
    assert locations == {f"{COMPLETION}?error=sso_failed"}
    assert len(set(await refusals(db))) == 4


async def test_a_provider_error_is_refused(client: httpx.AsyncClient, db: Database) -> None:
    started = await start(client)
    response = await client.get(
        "/auth/sso/callback",
        params={"error": "access_denied", "error_description": "<b>x</b>", "state": started.state},
    )
    assert completion(response) == {"error": "sso_failed"}
    rows = await audit_rows(db, "warden.identity.sso.sign_in")
    assert rows[-1]["details"] == {"reason": "provider_error", "provider_error": "access_denied"}


async def test_a_failed_token_exchange_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    idp.token_status = 500
    response = await sign_in(client, idp, sub="s-alice", email=ALICE)
    assert response.status_code == 401
    assert (await refusals(db))[-1] == "token_exchange_failed"


async def test_a_missing_client_secret_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database, secrets: Any
) -> None:
    del secrets.values[CLIENT_SECRET_NAME]
    response = await sign_in(client, idp, sub="s-alice", email=ALICE)
    assert response.status_code == 401
    assert (await refusals(db))[-1] == "client_secret_missing"


# Login transactions and handoff codes are single-use and cookie-bound


async def test_a_state_is_used_once(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    started = await start(client)
    first = provider_code(idp, started, sub="s-alice", email=ALICE)
    assert "code" in completion(await callback(client, first, started.state))
    second = provider_code(idp, started, sub="s-alice", email=ALICE)
    assert completion(await callback(client, second, started.state)) == {"error": "sso_failed"}
    assert (await refusals(db))[-1] == "transaction_used"


async def test_a_state_is_bound_to_the_browser_that_started_it(
    client: httpx.AsyncClient, app: FastAPI, idp: FakeIdp, alice: User, db: Database
) -> None:
    started = await start(client)
    code = provider_code(idp, started, sub="s-alice", email=ALICE)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as other:
        assert completion(await callback(other, code, started.state)) == {"error": "sso_failed"}
        other.cookies.set(COOKIE_NAME, "A" * 43, domain="app.example.com", path="/auth/sso")
        assert completion(await callback(other, code, started.state)) == {"error": "sso_failed"}
    assert (await refusals(db))[-2:] == ["no_cookie", "binding_mismatch"]


async def test_an_expired_transaction_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    started = await start(client)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.sso_login_transactions SET expires_at = now() - interval '1 second'"
        )
    code = provider_code(idp, started, sub="s-alice", email=ALICE)
    assert completion(await callback(client, code, started.state)) == {"error": "sso_failed"}
    assert (await refusals(db))[-1] == "transaction_expired"


async def test_concurrent_callbacks_for_one_state_issue_one_handoff(
    sso: SingleSignOn, idp: FakeIdp, alice: User, db: Database
) -> None:
    begun = await sso.begin()
    params = dict(httpx.URL(begun.redirect_url).params.items())
    codes = [
        idp.issue_code(
            idp.claims(sub="s-alice", email=ALICE, nonce=params["nonce"]),
            challenge=params["code_challenge"],
        )
        for _ in range(4)
    ]
    results = await race(
        *(
            lambda c=c: sso.complete(
                state=params["state"], code=c, error=None, binding=begun.binding
            )
            for c in codes
        )
    )
    handoffs = [r for r in results if isinstance(r, str)]
    assert len(handoffs) == 1, results
    assert all(isinstance(r, SsoError) for r in results if not isinstance(r, str))


async def test_a_handoff_code_is_used_once_even_concurrently(
    sso: SingleSignOn, idp: FakeIdp, alice: User, db: Database
) -> None:
    begun = await sso.begin()
    params = dict(httpx.URL(begun.redirect_url).params.items())
    code = idp.issue_code(
        idp.claims(sub="s-alice", email=ALICE, nonce=params["nonce"]),
        challenge=params["code_challenge"],
    )
    handed = await sso.complete(state=params["state"], code=code, error=None, binding=begun.binding)
    results = await race(*(lambda: sso.exchange(handed, begun.binding) for _ in range(5)))
    issued = [r for r in results if not isinstance(r, BaseException)]
    assert len(issued) == 1, results
    assert all(isinstance(r, AuthenticationRefused) for r in results if r not in issued)
    assert await sessions_of(db, alice.id) == 1


async def test_a_handoff_needs_the_login_cookie(
    client: httpx.AsyncClient, app: FastAPI, idp: FakeIdp, alice: User, db: Database
) -> None:
    started = await start(client)
    landed = completion(
        await callback(
            client, provider_code(idp, started, sub="s-alice", email=ALICE), started.state
        )
    )
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as other:
        assert (await handoff(other, landed["code"])).status_code == 401
    assert await sessions_of(db, alice.id) == 0
    await tokens(await handoff(client, landed["code"]))


async def test_handoff_refusals_are_the_uniform_refusal(
    client: httpx.AsyncClient,
) -> None:
    sign_in_refusal = await client.post("/auth/sign-in", json={"email": "x", "password": "y"})
    for body in ({"code": "nope"}, {}, {"code": 7}):
        refused = await client.post("/auth/sso/handoff", json=body)
        assert refused.status_code == 401
        assert refused.content == sign_in_refusal.content
        assert refused.headers["www-authenticate"] == "Bearer"


async def test_concurrent_first_sign_ins_with_different_subjects_pin_one(
    sso: SingleSignOn, idp: FakeIdp, alice: User, db: Database
) -> None:
    async def attempt(subject: str) -> str:
        begun = await sso.begin()
        params = dict(httpx.URL(begun.redirect_url).params.items())
        code = idp.issue_code(
            idp.claims(sub=subject, email=ALICE, nonce=params["nonce"]),
            challenge=params["code_challenge"],
        )
        return await sso.complete(
            state=params["state"], code=code, error=None, binding=begun.binding
        )

    results = await race(*(lambda s=s: attempt(s) for s in ("s-1", "s-2", "s-3", "s-4")))
    assert sum(isinstance(r, str) for r in results) == 1, results
    reasons = [r.reason for r in results if isinstance(r, SsoError)]
    assert reasons == ["subject_mismatch"] * 3
    pin = await pin_of(db, alice.id)
    assert pin is not None and pin[1] in {"s-1", "s-2", "s-3", "s-4"}


# Sessions


async def test_sso_sessions_skip_forced_totp_enrolment(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, identity: Identity
) -> None:
    await identity.policy.update(actor="admin", require_mfa=True)
    await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    password = await client.post("/auth/sign-in", json={"email": ALICE, "password": PASSWORD})
    assert password.json()["status"] == "mfa_enrolment_required"


async def test_an_sso_session_refreshes(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, identity: Identity
) -> None:
    body = await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    refreshed = await tokens(
        await client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]})
    )
    assert (await identity.authenticate(refreshed["access_token"])).amr == ("sso",)


async def test_disabling_sso_ends_sso_sessions_and_refuses_new_ones(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, identity: Identity, sso: SingleSignOn
) -> None:
    body = await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    started = await start(client)
    landed = completion(
        await callback(
            client, provider_code(idp, started, sub="s-alice", email=ALICE), started.state
        )
    )
    password = await tokens(
        await client.post("/auth/sign-in", json={"email": ALICE, "password": PASSWORD})
    )

    await sso.settings.update(actor="admin", enabled=False)

    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(body["access_token"])
    assert (await handoff(client, landed["code"])).status_code == 401
    assert (await client.get("/auth/sso/start")).headers["location"] == (
        f"{COMPLETION}?error=sso_failed"
    )
    assert (await identity.authenticate(password["access_token"])).user_id == alice.id


async def test_no_sso_session_survives_a_concurrent_disable(
    sso: SingleSignOn, idp: FakeIdp, alice: User, db: Database
) -> None:
    for _ in range(6):
        await sso.settings.update(actor="admin", enabled=True)
        begun = await sso.begin()
        params = dict(httpx.URL(begun.redirect_url).params.items())
        code = idp.issue_code(
            idp.claims(sub="s-alice", email=ALICE, nonce=params["nonce"]),
            challenge=params["code_challenge"],
        )
        handed = await sso.complete(
            state=params["state"], code=code, error=None, binding=begun.binding
        )
        await race(
            lambda handed=handed, binding=begun.binding: sso.exchange(handed, binding),
            lambda: sso.settings.update(actor="admin", enabled=False),
        )
        async with db.connection() as conn:
            cur = await conn.execute(
                "SELECT count(*) FROM warden.sessions WHERE revoked_at IS NULL AND 'sso' = ANY(amr)"
            )
            row = await cur.fetchone()
        assert row is not None and row[0] == 0


# Break-glass


async def test_password_sign_in_works_with_the_provider_down(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, db: Database
) -> None:
    idp.fail_all = True
    response = await client.get("/auth/sso/start")
    assert response.headers["location"] == f"{COMPLETION}?error=sso_failed"
    assert (await refusals(db))[-1] == "discovery_unavailable"
    await tokens(await client.post("/auth/sign-in", json={"email": ALICE, "password": PASSWORD}))


# Housekeeping


async def test_prune_removes_expired_transactions_and_codes(
    client: httpx.AsyncClient, sso: SingleSignOn, db: Database
) -> None:
    await start(client)
    await start(client)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.sso_login_transactions SET expires_at = now() - interval '1 second'"
        )
    assert await sso.prune() == 2


async def test_unpin_lets_the_user_pin_a_new_subject(
    client: httpx.AsyncClient, idp: FakeIdp, alice: User, sso: SingleSignOn, db: Database
) -> None:
    await tokens(await sign_in(client, idp, sub="s-alice", email=ALICE))
    assert await sso.unpin(alice.id, actor="admin") is True
    await tokens(await sign_in(client, idp, sub="s-alice-2", email=ALICE))
    assert await pin_of(db, alice.id) == (ISSUER, "s-alice-2")
    rows = await audit_rows(db, "warden.identity.sso.subject_unpinned")
    assert rows[0]["actor"] == "admin"
