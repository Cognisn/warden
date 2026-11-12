"""Password sign-in over HTTP: outcomes, uniform refusals, timing and rehashing."""

from __future__ import annotations

import hashlib
import statistics
import time
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import (
    PASSWORD,
    MemorySecrets,
    UserFactory,
    audit_rows,
    enrol_totp,
    make_config,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity, PermissionRegistry, SignInMethod, UserStatus
from warden.identity.passwords import PasswordHasher
from warden.keys import KeyStore

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'


def _assert_refusal(response: httpx.Response) -> None:
    assert response.status_code == 401
    assert response.content == REFUSAL
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"


async def _sign_in(client: httpx.AsyncClient, email: str, password: str) -> httpx.Response:
    return await client.post("/auth/sign-in", json={"email": email, "password": password})


async def test_sign_in_without_mfa_issues_tokens(
    client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    user = await make_user("alice@example.com")
    response = await _sign_in(client, "ALICE@example.com", PASSWORD)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "signed_in"
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    assert body["access_token"].count(".") == 2
    assert body["refresh_token"]
    assert response.headers["cache-control"] == "no-store"
    rows = await audit_rows(db, "warden.identity.sign_in")
    assert rows[-1]["outcome"] == "success"
    assert rows[-1]["actor"] == str(user.id)
    assert rows[-1]["details"]["amr"] == ["pwd"]


async def test_confirmed_totp_turns_sign_in_into_a_challenge(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    body = (await _sign_in(client, user.email, PASSWORD)).json()
    assert body["status"] == "mfa_required"
    assert body["challenge"] and body["expires_in"] == 300
    assert "access_token" not in body


async def test_an_unconfirmed_enrolment_is_not_mfa(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory, db: Database
) -> None:
    """#130: a started but unconfirmed enrolment neither challenges nor satisfies MFA."""
    user = await make_user()
    await identity.mfa.begin_enrolment(user.id, account=user.email)
    assert not await identity.mfa.has_confirmed_totp(user.id)
    body = (await _sign_in(client, user.email, PASSWORD)).json()
    assert body["status"] == "signed_in"
    rows = await audit_rows(db, "warden.identity.sign_in")
    assert rows[-1]["details"]["amr"] == ["pwd"]


async def test_require_mfa_without_confirmed_totp_forces_enrolment(
    db: Database, keys: KeyStore, permissions: PermissionRegistry, secrets: MemorySecrets
) -> None:
    from identity_support import FAST_HASHER

    identity = Identity(
        make_config(require_mfa=True), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER
    )
    app = FastAPI()
    identity.install(app)
    app.include_router(identity.auth_router(), prefix="/auth")
    user = await identity.users.create("fred@example.com", actor="t", password=PASSWORD)
    await identity.mfa.begin_enrolment(user.id, account=user.email)  # unconfirmed (#130)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        body = (await _sign_in(c, user.email, PASSWORD)).json()
    assert body["status"] == "mfa_enrolment_required"
    assert "access_token" not in body


async def _refusal_cases(identity: Identity, make_user: UserFactory) -> dict[str, dict[str, Any]]:
    active = await make_user("active@example.com")
    sso = await make_user("sso@example.com", sign_in_method=SignInMethod.SSO_ONLY)
    suspended = await make_user("suspended@example.com")
    await identity.users.set_status(suspended.id, UserStatus.SUSPENDED, actor="t")
    del active, sso
    return {
        "unknown_user": {"email": "nobody@example.com", "password": PASSWORD},
        "wrong_password": {"email": "active@example.com", "password": "wrong " + PASSWORD},
        "sso_only": {"email": "sso@example.com", "password": PASSWORD},
        "user_inactive": {"email": "suspended@example.com", "password": PASSWORD},
    }


async def test_every_sign_in_failure_is_byte_identical(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory, db: Database
) -> None:
    cases = await _refusal_cases(identity, make_user)
    for payload in cases.values():
        _assert_refusal(await client.post("/auth/sign-in", json=payload))
    for malformed in (
        b"not json",
        b"{}",
        b'{"email": "active@example.com"}',
        b'{"email": 5, "password": []}',
        b'["active@example.com", "pw"]',
    ):
        response = await client.post(
            "/auth/sign-in", content=malformed, headers={"content-type": "application/json"}
        )
        _assert_refusal(response)
        assert b"active@example.com" not in response.content
    reasons = [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sign_in")]
    assert reasons[:4] == list(cases)


async def test_the_reason_is_audited_never_returned(
    client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    await make_user("gina@example.com")
    response = await _sign_in(client, "gina@example.com", "not the password")
    assert b"wrong" not in response.content and b"password" not in response.content
    rows = await audit_rows(db, "warden.identity.sign_in")
    assert rows[-1]["outcome"] == "failure"
    assert rows[-1]["details"] == {"reason": "wrong_password", "identifier": "gina@example.com"}
    assert "not the password" not in str(rows)


async def test_sign_in_timing_does_not_reveal_a_username(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    """#133: unknown user, wrong password and SSO-only take indistinguishable time.

    Uses argon2-cffi's default (production) cost, so password hashing
    dominates every path, and interleaves the cases so drift affects all
    equally. A missing dummy verification for unknown users makes that path
    an order of magnitude faster and fails this test.
    """
    identity = Identity(
        config,
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=PasswordHasher(),
        sign_in_attempt_limit=1000,
    )
    app = FastAPI()
    identity.install(app)
    app.include_router(identity.auth_router(), prefix="/auth")
    await identity.users.create("known@example.com", actor="t", password=PASSWORD)
    await identity.users.create(
        "sso-only@example.com",
        actor="t",
        password=PASSWORD,
        sign_in_method=SignInMethod.SSO_ONLY,
    )
    await identity.users.create("sso-no-password@example.com", actor="t", password=None)
    await identity.users.set_sign_in_method(
        (await identity.users.get_by_email("sso-no-password@example.com")).id,  # type: ignore[union-attr]
        SignInMethod.SSO_ONLY,
        actor="t",
    )
    cases = {
        "unknown": ("nobody-here@example.com", PASSWORD),
        "wrong_password": ("known@example.com", "wrong " + PASSWORD),
        "sso_only": ("sso-only@example.com", PASSWORD),
        "sso_only_no_password": ("sso-no-password@example.com", PASSWORD),
    }
    samples: dict[str, list[float]] = {name: [] for name in cases}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        for email, password in cases.values():  # warm-up
            _assert_refusal(await _sign_in(c, email, password))
        for _ in range(12):
            for name, (email, password) in cases.items():
                start = time.perf_counter()
                response = await _sign_in(c, email, password)
                samples[name].append(time.perf_counter() - start)
                _assert_refusal(response)
    medians = {name: statistics.median(values) for name, values in samples.items()}
    slowest, fastest = max(medians.values()), min(medians.values())
    assert fastest / slowest > 0.75, medians


async def test_legacy_pbkdf2_hash_is_rehashed_to_argon2id_on_sign_in(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user("legacy@example.com", password=None)
    salt = "bGVnYWN5c2FsdA"
    digest = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt.encode(), 1000).hex()
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.users SET password_hash = %s WHERE id = %s",
            (f"pbkdf2:sha256:1000${salt}${digest}", user.id),
        )
    response = await _sign_in(client, "legacy@example.com", PASSWORD)
    assert response.json()["status"] == "signed_in"
    async with db.connection() as conn:
        cur = await conn.execute("SELECT password_hash FROM warden.users WHERE id = %s", (user.id,))
        row = await cur.fetchone()
    assert row is not None and row[0].startswith("$argon2id$")
    rows = await audit_rows(db, "warden.identity.sign_in")
    assert rows[-1]["details"]["rehashed"] is True
    # The new hash works; the legacy one is gone.
    assert (await _sign_in(client, "legacy@example.com", PASSWORD)).json()["status"] == "signed_in"


async def test_a_failed_legacy_sign_in_keeps_the_legacy_hash(
    client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    user = await make_user("legacy2@example.com", password=None)
    digest = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), b"c2FsdA", 1000).hex()
    legacy = f"pbkdf2:sha256:1000$c2FsdA${digest}"
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.users SET password_hash = %s WHERE id = %s", (legacy, user.id)
        )
    _assert_refusal(await _sign_in(client, "legacy2@example.com", "wrong"))
    async with db.connection() as conn:
        cur = await conn.execute("SELECT password_hash FROM warden.users WHERE id = %s", (user.id,))
        row = await cur.fetchone()
    assert row is not None and row[0] == legacy


@pytest.mark.parametrize(
    "identifier",
    ["hunter2-not-an-email", "correct horse battery staple", "x" * 400, "a@b"],
)
async def test_an_identifier_that_is_not_an_email_address_is_not_audited(
    client: httpx.AsyncClient, db: Database, identifier: str
) -> None:
    """Someone who types their password into the email field must not have it recorded."""
    _assert_refusal(await _sign_in(client, identifier, PASSWORD))
    rows = await audit_rows(db, "warden.identity.sign_in")
    assert rows[-1]["details"] == {"reason": "unknown_user", "identifier_recorded": False}
    assert identifier not in str(rows)
