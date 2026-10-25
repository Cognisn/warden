"""Sign-in throttling per (identifier, source address)."""

from __future__ import annotations

import ipaddress

import httpx
import pytest
from fastapi import FastAPI
from identity_support import (
    FAST_HASHER,
    PASSWORD,
    MemorySecrets,
    UserFactory,
    audit_rows,
    current_code,
    enrol_totp,
    race,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, PermissionRegistry, TokenPair
from warden.keys import KeyStore

pytestmark = pytest.mark.db

LIMIT = 3
IP_A = ipaddress.ip_address("192.0.2.20")
IP_B = ipaddress.ip_address("198.51.100.20")
REFUSAL = b'{"detail":"authentication failed"}'


@pytest.fixture
def throttled(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> Identity:
    return Identity(
        config,
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        sign_in_attempt_limit=LIMIT,
        sign_in_window_seconds=900,
    )


async def _fail(identity: Identity, email: str, ip: object = IP_A) -> str:
    with pytest.raises(AuthenticationRefused) as refused:
        await identity.sign_in(email, "wrong password", source_ip=ip)  # type: ignore[arg-type]
    return refused.value.reason


async def test_attempts_beyond_the_limit_are_refused_even_with_the_right_password(
    throttled: Identity, make_user: UserFactory, db: Database
) -> None:
    await make_user("tina@example.com")
    for _ in range(LIMIT):
        assert await _fail(throttled, "tina@example.com") == "wrong_password"
    with pytest.raises(AuthenticationRefused) as refused:
        await throttled.sign_in("tina@example.com", PASSWORD, source_ip=IP_A)
    assert refused.value.reason == "throttled"
    rows = await audit_rows(db, "identity.sign_in")
    assert rows[-1]["details"] == {"reason": "throttled", "identifier": "tina@example.com"}


async def test_another_address_is_not_affected(throttled: Identity, make_user: UserFactory) -> None:
    """An attacker elsewhere cannot lock the user out."""
    await make_user("uma@example.com")
    for _ in range(LIMIT + 1):
        await _fail(throttled, "uma@example.com", IP_A)
    result = await throttled.sign_in("uma@example.com", PASSWORD, source_ip=IP_B)
    assert result.tokens is not None


async def test_the_identifier_is_matched_without_regard_to_case(
    throttled: Identity, make_user: UserFactory
) -> None:
    await make_user("vic@example.com")
    for email in ("vic@example.com", "VIC@example.com", "Vic@Example.com"):
        await _fail(throttled, email)
    assert await _fail(throttled, "vIc@example.COM") == "throttled"


async def test_unknown_identifiers_are_throttled_alike(throttled: Identity) -> None:
    """Throttling must not reveal whether an account exists."""
    reasons = [await _fail(throttled, "ghost@example.com") for _ in range(LIMIT + 1)]
    assert reasons == ["unknown_user"] * LIMIT + ["throttled"]


async def test_a_successful_sign_in_resets_the_count(
    throttled: Identity, make_user: UserFactory
) -> None:
    await make_user("wes@example.com")
    for _ in range(LIMIT - 1):
        await _fail(throttled, "wes@example.com")
    assert (await throttled.sign_in("wes@example.com", PASSWORD, source_ip=IP_A)).tokens
    for _ in range(LIMIT - 1):
        assert await _fail(throttled, "wes@example.com") == "wrong_password"


async def test_a_password_alone_does_not_reset_the_count_when_mfa_follows(
    throttled: Identity, make_user: UserFactory
) -> None:
    """Otherwise a password holder gets unlimited challenges, and so unlimited code guesses."""
    user = await make_user("xia@example.com")
    secret = await enrol_totp(throttled, user)
    for _ in range(LIMIT):
        result = await throttled.sign_in("xia@example.com", PASSWORD, source_ip=IP_A)
        assert result.challenge is not None
    with pytest.raises(AuthenticationRefused) as refused:
        await throttled.sign_in("xia@example.com", PASSWORD, source_ip=IP_A)
    assert refused.value.reason == "throttled"
    del secret


async def test_completing_the_second_factor_resets_the_count(
    throttled: Identity, make_user: UserFactory
) -> None:
    user = await make_user("yan@example.com")
    secret = await enrol_totp(throttled, user)
    for _ in range(LIMIT - 1):
        await _fail(throttled, "yan@example.com")
    result = await throttled.sign_in("yan@example.com", PASSWORD, source_ip=IP_A)
    assert result.challenge is not None
    pair = await throttled.verify_totp(
        result.challenge.token, current_code(secret, 1), source_ip=IP_A
    )
    assert isinstance(pair, TokenPair)
    for _ in range(LIMIT - 1):
        assert await _fail(throttled, "yan@example.com") == "wrong_password"


async def test_the_window_expires(
    throttled: Identity, make_user: UserFactory, db: Database
) -> None:
    await make_user("zed@example.com")
    for _ in range(LIMIT + 1):
        await _fail(throttled, "zed@example.com")
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.sign_in_attempts"
            " SET window_started_at = window_started_at - interval '16 minutes'"
        )
    assert (await throttled.sign_in("zed@example.com", PASSWORD, source_ip=IP_A)).tokens


async def test_concurrent_attempts_cannot_exceed_the_limit(
    throttled: Identity, make_user: UserFactory, db: Database
) -> None:
    """Barriered concurrent attempts: no more than the limit reach password verification."""
    for round_number in range(3):
        email = f"race-{round_number}@example.com"
        await make_user(email)
        results = await race(
            *(lambda e=email: throttled.sign_in(e, "wrong", source_ip=IP_A) for _ in range(8))
        )
        reasons = sorted(r.reason for r in results if isinstance(r, AuthenticationRefused))
        assert reasons == ["throttled"] * (8 - LIMIT) + ["wrong_password"] * LIMIT, results


async def test_throttling_over_http_uses_the_client_address_and_the_uniform_refusal(
    throttled: Identity, make_user: UserFactory
) -> None:
    await make_user("http@example.com")
    app = FastAPI()
    throttled.install(app)
    app.include_router(throttled.auth_router(), prefix="/auth")

    def client(ip: str) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app, client=(ip, 50000))
        return httpx.AsyncClient(transport=transport, base_url="https://app.example.com")

    body = {"email": "http@example.com", "password": "wrong"}
    async with client("192.0.2.30") as a:
        for _ in range(LIMIT):
            await a.post("/auth/sign-in", json=body)
        refused = await a.post(
            "/auth/sign-in", json={"email": "http@example.com", "password": PASSWORD}
        )
        assert refused.status_code == 401 and refused.content == REFUSAL
    async with client("192.0.2.31") as b:
        ok = await b.post("/auth/sign-in", json={"email": "http@example.com", "password": PASSWORD})
        assert ok.status_code == 200


async def test_expired_attempt_records_can_be_pruned(
    throttled: Identity, make_user: UserFactory, db: Database
) -> None:
    await _fail(throttled, "old@example.com")
    await _fail(throttled, "new@example.com")
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.sign_in_attempts SET window_started_at = now() - interval '1 day'"
            " WHERE window_started_at = (SELECT min(window_started_at)"
            " FROM warden.sign_in_attempts)"
        )
    assert await throttled.prune_sign_in_attempts() == 1
