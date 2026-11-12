"""TOTP verification, recovery codes, challenges and enrolment."""

from __future__ import annotations

import time

import httpx
import pytest
from identity_support import (
    PASSWORD,
    MemorySecrets,
    UserFactory,
    audit_rows,
    current_code,
    enrol_totp,
    make_config,
    race,
)

from warden.db import Database
from warden.identity import (
    AuthenticationRefused,
    Identity,
    PermissionRegistry,
    SignInMethod,
    TokenPair,
    User,
    UserStatus,
)
from warden.identity.totp import PERIOD, code_at, step_for
from warden.keys import KeyStore

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'


async def _challenge(identity: Identity, user: User) -> str:
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "verify"
    return result.challenge.token


async def _fresh_code(secret: bytes) -> str:
    """A code for a step no earlier verification has claimed: the next one.

    Enrolment claims the current step. If the next step is outside the
    acceptance window by the time it is used, that is a test bug, so leave
    at least a few seconds of the current step.
    """
    if PERIOD - time.time() % PERIOD < 3:
        time.sleep(PERIOD - time.time() % PERIOD + 0.1)
    return current_code(secret, 1)


async def _enrolled(identity: Identity, make_user: UserFactory) -> tuple[User, bytes]:
    user = await make_user()
    return user, await enrol_totp(identity, user)


async def test_totp_completes_sign_in(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user, secret = await _enrolled(identity, make_user)
    result = await identity.verify_totp(await _challenge(identity, user), await _fresh_code(secret))
    assert isinstance(result, TokenPair)
    rows = await audit_rows(db, "warden.identity.sign_in")
    assert rows[-1]["outcome"] == "success"
    assert rows[-1]["details"]["amr"] == ["pwd", "otp"]


async def test_a_code_is_accepted_once_per_step(identity: Identity, make_user: UserFactory) -> None:
    """#124, sequentially: the same code with a second challenge is refused."""
    user, secret = await _enrolled(identity, make_user)
    code = await _fresh_code(secret)
    await identity.verify_totp(await _challenge(identity, user), code)
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(await _challenge(identity, user), code)


async def test_an_earlier_step_is_refused_after_a_later_one(
    identity: Identity, make_user: UserFactory
) -> None:
    user, secret = await _enrolled(identity, make_user)
    await identity.verify_totp(await _challenge(identity, user), await _fresh_code(secret))
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(await _challenge(identity, user), current_code(secret))


async def test_concurrent_submits_of_one_code_succeed_once(
    identity: Identity, make_user: UserFactory
) -> None:
    """#124: barriered concurrent submits of one code, each with its own challenge."""
    for _ in range(4):
        user, secret = await _enrolled(identity, make_user)
        challenges = [await _challenge(identity, user) for _ in range(3)]
        code = await _fresh_code(secret)
        results = await race(*(lambda c=c, k=code: identity.verify_totp(c, k) for c in challenges))
        assert sum(isinstance(r, TokenPair) for r in results) == 1, results
        assert sum(isinstance(r, AuthenticationRefused) for r in results) == 2, results


async def test_a_challenge_completes_at_most_one_sign_in(
    identity: Identity, make_user: UserFactory
) -> None:
    """One challenge, a valid TOTP code and a valid recovery code submitted together."""
    for _ in range(4):
        user = await make_user()
        enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
        codes = await identity.mfa.confirm_enrolment(
            user.id, current_code(enrolment.secret), actor="t"
        )
        assert codes is not None
        challenge = await _challenge(identity, user)
        totp_code = await _fresh_code(enrolment.secret)
        results = await race(
            lambda c=challenge, k=totp_code: identity.verify_totp(c, k),
            lambda c=challenge, k=codes[0]: identity.use_recovery_code(c, k),
        )
        assert sum(isinstance(r, TokenPair) for r in results) == 1, results
        assert sum(isinstance(r, AuthenticationRefused) for r in results) == 1, results
        # The losing request's claim is undone: if TOTP won, the recovery code survives.
        unused = await _unused_recovery_codes(identity, user)
        assert unused == (10 if isinstance(results[0], TokenPair) else 9), results


async def test_a_recovery_code_is_not_used_up_when_the_challenge_is_lost(
    identity: Identity, make_user: UserFactory, migrated_dsn: str
) -> None:
    """Deterministic version of the race: the code is claimed, then the challenge is lost.

    A separate connection holds the challenge row, so the recovery request
    claims its code and then waits on the challenge. The holder marks the
    challenge consumed and commits; the request must refuse and undo its claim.
    """
    import asyncio

    import psycopg

    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret), actor="t")
    assert codes is not None
    challenge = await _challenge(identity, user)
    async with await psycopg.AsyncConnection.connect(migrated_dsn) as holder:
        await holder.execute(
            "SELECT 1 FROM warden.mfa_challenges WHERE user_id = %s FOR UPDATE", (user.id,)
        )
        attempt = asyncio.create_task(identity.use_recovery_code(challenge, codes[0]))
        for _ in range(200):  # until the request is waiting on the challenge row lock
            # Activity statistics are snapshotted per transaction; refresh them.
            await holder.execute("SELECT pg_stat_clear_snapshot()")
            cur = await holder.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'"
                " AND query LIKE 'UPDATE%%mfa_challenges%%'"
            )
            row = await cur.fetchone()
            if row is not None and row[0] > 0:
                break
            await asyncio.sleep(0.05)
        else:
            attempt.cancel()
            pytest.fail("the recovery request never reached the challenge")
        await holder.execute(
            "UPDATE warden.mfa_challenges SET consumed_at = now() WHERE user_id = %s", (user.id,)
        )
        await holder.commit()
        with pytest.raises(AuthenticationRefused) as refused:
            await attempt
    assert refused.value.reason == "challenge_used"
    assert await _unused_recovery_codes(identity, user) == 10


async def _unused_recovery_codes(identity: Identity, user: User) -> int:
    async with identity.db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.recovery_codes WHERE user_id = %s AND used_at IS NULL",
            (user.id,),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


@pytest.mark.parametrize(
    "code",
    [
        "\uff11\uff12\uff13\uff14\uff15\uff16",
        "123456\n",
        "\u0661\u0662\u0663\u0664\u0665\u0666",
        "12345",
        "",
        "x" * 5000,
    ],
)
async def test_malformed_codes_are_refused_uniformly_over_http(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory, code: str
) -> None:
    """#125 and #135: never a server error, always the uniform refusal."""
    user, _secret = await _enrolled(identity, make_user)
    challenge = await _challenge(identity, user)
    response = await client.post("/auth/totp/verify", json={"challenge": challenge, "code": code})
    assert response.status_code == 401 and response.content == REFUSAL


async def test_non_string_code_is_refused_uniformly(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user, _secret = await _enrolled(identity, make_user)
    challenge = await _challenge(identity, user)
    for code in (123456, None, ["123456"], {"a": 1}):
        response = await client.post(
            "/auth/totp/verify", json={"challenge": challenge, "code": code}
        )
        assert response.status_code == 401 and response.content == REFUSAL


async def test_totp_over_http_issues_tokens(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user, secret = await _enrolled(identity, make_user)
    challenge = await _challenge(identity, user)
    response = await client.post(
        "/auth/totp/verify", json={"challenge": challenge, "code": await _fresh_code(secret)}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "signed_in"


async def test_recovery_code_completes_sign_in_once(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret), actor="t")
    assert codes is not None and len(codes) == 10
    result = await identity.use_recovery_code(await _challenge(identity, user), codes[3].upper())
    assert isinstance(result, TokenPair)
    with pytest.raises(AuthenticationRefused):
        await identity.use_recovery_code(await _challenge(identity, user), codes[3])
    rows = await audit_rows(db, "warden.identity.sign_in")
    assert rows[-1]["details"]["amr"] == ["pwd", "recovery_code"]


async def test_concurrent_use_of_one_recovery_code_succeeds_once(
    identity: Identity, make_user: UserFactory
) -> None:
    """#126: barriered concurrent submits of one recovery code."""
    for _ in range(4):
        user = await make_user()
        enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
        codes = await identity.mfa.confirm_enrolment(
            user.id, current_code(enrolment.secret), actor="t"
        )
        assert codes is not None
        challenges = [await _challenge(identity, user) for _ in range(3)]
        results = await race(
            *(lambda c=c, k=codes[0]: identity.use_recovery_code(c, k) for c in challenges)
        )
        assert sum(isinstance(r, TokenPair) for r in results) == 1, results
        assert sum(isinstance(r, AuthenticationRefused) for r in results) == 2, results


async def test_unconfirmed_totp_cannot_verify(identity: Identity, make_user: UserFactory) -> None:
    """#130: codes from an unconfirmed enrolment are never accepted."""
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    async with identity.db.connection() as conn:
        assert await identity.mfa.claim_totp(conn, user.id, current_code(enrolment.secret)) is False


async def test_verify_issues_nothing_to_a_user_suspended_after_the_password_step(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    """#132: the status is checked when the second factor is presented."""
    user, secret = await _enrolled(identity, make_user)
    challenge = await _challenge(identity, user)
    await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="t")
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(challenge, await _fresh_code(secret))
    rows = await audit_rows(db, "warden.identity.mfa.verify")
    assert rows[-1]["details"]["reason"] == "user_inactive"


async def test_verify_issues_nothing_once_the_user_is_sso_only(
    identity: Identity, make_user: UserFactory
) -> None:
    user, secret = await _enrolled(identity, make_user)
    challenge = await _challenge(identity, user)
    await identity.users.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="t")
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(challenge, await _fresh_code(secret))


async def test_a_challenge_dies_after_five_wrong_codes(
    identity: Identity, make_user: UserFactory
) -> None:
    user, secret = await _enrolled(identity, make_user)
    challenge = await _challenge(identity, user)
    good = await _fresh_code(secret)
    wrong = "000000" if good != "000000" else "111111"
    for _ in range(5):
        with pytest.raises(AuthenticationRefused):
            await identity.verify_totp(challenge, wrong)
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(challenge, good)


async def test_an_expired_challenge_is_refused(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user, secret = await _enrolled(identity, make_user)
    challenge = await _challenge(identity, user)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.mfa_challenges SET expires_at = now() - interval '1 second'"
        )
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(challenge, await _fresh_code(secret))


async def test_an_unknown_challenge_is_refused(identity: Identity) -> None:
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp("not-a-challenge", "123456")


async def test_enrolment_cannot_restart_once_confirmed(
    identity: Identity, make_user: UserFactory
) -> None:
    from warden.identity import MfaError

    user, _secret = await _enrolled(identity, make_user)
    with pytest.raises(MfaError):
        await identity.mfa.begin_enrolment(user.id, account=user.email)


async def test_restarting_an_unconfirmed_enrolment_replaces_the_secret(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    first = await identity.mfa.begin_enrolment(user.id, account=user.email)
    second = await identity.mfa.begin_enrolment(user.id, account=user.email)
    assert first.secret != second.secret
    assert await identity.mfa.confirm_enrolment(user.id, current_code(first.secret), actor="t") is (
        None
    )
    assert await identity.mfa.confirm_enrolment(user.id, current_code(second.secret), actor="t")


async def test_confirmation_is_audited(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user, _ = await _enrolled(identity, make_user)
    actions = [r["action"] for r in await audit_rows(db) if r["resource_id"] == str(user.id)]
    assert "warden.identity.mfa.enrolment_started" in actions
    assert "warden.identity.mfa.enrolled" in actions


async def test_forced_enrolment_over_http(
    db: Database, keys: KeyStore, permissions: PermissionRegistry, secrets: MemorySecrets
) -> None:
    from fastapi import FastAPI
    from identity_support import FAST_HASHER

    identity = Identity(
        make_config(require_mfa=True), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER
    )
    app = FastAPI()
    identity.install(app)
    app.include_router(identity.auth_router(), prefix="/auth")
    await identity.users.create("hana@example.com", actor="t", password=PASSWORD)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        signed = (
            await c.post("/auth/sign-in", json={"email": "hana@example.com", "password": PASSWORD})
        ).json()
        assert signed["status"] == "mfa_enrolment_required"
        challenge = signed["challenge"]
        begun = (await c.post("/auth/totp/enrolment", json={"challenge": challenge})).json()
        assert begun["uri"].startswith("otpauth://totp/")
        import base64

        secret = base64.b32decode(begun["secret"] + "=" * (-len(begun["secret"]) % 8))
        wrong = await c.post(
            "/auth/totp/enrolment/confirm", json={"challenge": challenge, "code": "12345x"}
        )
        assert wrong.status_code == 401 and wrong.content == REFUSAL
        confirmed = await c.post(
            "/auth/totp/enrolment/confirm",
            json={"challenge": challenge, "code": code_at(secret, step_for(time.time()))},
        )
        assert confirmed.status_code == 200
        body = confirmed.json()
        assert body["status"] == "signed_in" and len(body["recovery_codes"]) == 10
        # The enrolment challenge is used up.
        again = await c.post("/auth/totp/enrolment", json={"challenge": challenge})
        assert again.status_code == 401 and again.content == REFUSAL


async def test_voluntary_enrolment_with_an_access_token(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    tokens = (
        await client.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    ).json()
    auth = {"authorization": f"Bearer {tokens['access_token']}"}
    begun = (await client.post("/auth/totp/enrolment", headers=auth, json={})).json()
    import base64

    secret = base64.b32decode(begun["secret"] + "=" * (-len(begun["secret"]) % 8))
    confirmed = await client.post(
        "/auth/totp/enrolment/confirm",
        headers=auth,
        json={"code": code_at(secret, step_for(time.time()))},
    )
    assert confirmed.status_code == 200
    body = confirmed.json()
    assert len(body["recovery_codes"]) == 10 and "access_token" not in body


async def test_a_signed_in_users_wrong_enrolment_code_is_a_400_not_a_sign_out(
    client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    """A 401 would tell the client its session ended; it has not."""
    user = await make_user()
    tokens = (
        await client.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    ).json()
    auth = {"authorization": f"Bearer {tokens['access_token']}"}
    await client.post("/auth/totp/enrolment", headers=auth, json={})
    for code in ("000000x", 123456, None):
        response = await client.post(
            "/auth/totp/enrolment/confirm", headers=auth, json={"code": code}
        )
        assert response.status_code == 400
        assert response.content == b'{"detail":"code not accepted"}'
    rows = await audit_rows(db, "warden.identity.mfa.verify")
    assert rows[-1]["details"] == {"reason": "wrong_code", "method": "enrolment"}
