"""An administrator's TOTP reset: the way back for a user who lost both factors."""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

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
    make_config,
    race,
)

from warden.db import Database
from warden.identity import (
    AuthenticationRefused,
    Identity,
    PermissionRegistry,
    TokenPair,
    User,
    UserError,
)
from warden.identity.totp import PERIOD
from warden.keys import KeyStore

pytestmark = pytest.mark.db

ACTION = "warden.identity.mfa.reset"
REFUSAL = b'{"detail":"authentication failed"}'


@pytest.fixture
def strict(
    db: Database, keys: KeyStore, permissions: PermissionRegistry, secrets: MemorySecrets
) -> Identity:
    """An Identity whose session policy requires a second factor."""
    return Identity(
        make_config(require_mfa=True), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER
    )


def _app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def client(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_app(identity), client=("203.0.113.9", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


def _wait_for_room() -> None:
    """Leave a few seconds of the current step, so the next step's code stays in the window."""
    if PERIOD - time.time() % PERIOD < 3:
        time.sleep(PERIOD - time.time() % PERIOD + 0.1)


async def _enrol(identity: Identity, user: User) -> tuple[bytes, list[str]]:
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret), actor="t")
    assert codes is not None
    return enrolment.secret, codes


async def _signed_in(identity: Identity, user: User, secret: bytes) -> TokenPair:
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "verify"
    _wait_for_room()
    return await identity.verify_totp(result.challenge.token, current_code(secret, 1))


async def _bearer(identity: Identity, user: User) -> dict[str, str]:
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is not None
    return {"authorization": f"Bearer {result.tokens.access_token}"}


async def _counts(db: Database, user: User) -> tuple[int, int]:
    """(TOTP credentials, recovery codes) the user has."""
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT (SELECT count(*) FROM warden.totp_credentials WHERE user_id = %s),"
            " (SELECT count(*) FROM warden.recovery_codes WHERE user_id = %s)",
            (user.id, user.id),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0]), int(row[1])


async def _live_sessions(db: Database, user: User) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s AND revoked_at IS NULL",
            (user.id,),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


# The method


async def test_a_reset_removes_the_credential_and_every_recovery_code(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    await _enrol(identity, user)
    assert await _counts(db, user) == (1, 10)
    assert await identity.reset_totp(user.id, actor="admin") is True
    assert await _counts(db, user) == (0, 0)
    assert await identity.mfa.has_confirmed_totp(user.id) is False


async def test_a_reset_leaves_other_users_alone(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user, other = await make_user(), await make_user()
    await _enrol(identity, user)
    await _enrol(identity, other)
    await identity.reset_totp(user.id, actor="admin")
    assert await _counts(db, other) == (1, 10)


async def test_an_unconfirmed_enrolment_is_removed_too(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    await identity.mfa.begin_enrolment(user.id, account=user.email)
    assert await identity.reset_totp(user.id, actor="admin") is True
    assert await _counts(db, user) == (0, 0)


async def test_an_old_recovery_code_is_refused_after_a_reset(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    _secret, codes = await _enrol(identity, user)
    # A challenge issued before the reset must not let a recovery code through after it.
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "verify"
    await identity.reset_totp(user.id, actor="admin")
    with pytest.raises(AuthenticationRefused):
        await identity.use_recovery_code(result.challenge.token, codes[0])


async def test_an_old_totp_code_is_refused_after_a_reset(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    secret, _codes = await _enrol(identity, user)
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None
    await identity.reset_totp(user.id, actor="admin")
    _wait_for_room()
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(result.challenge.token, current_code(secret, 1))


async def test_sign_in_then_asks_for_enrolment_and_enrolment_succeeds_again(
    strict: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    secret, _codes = await _enrol(strict, user)
    await strict.reset_totp(user.id, actor="admin")
    signed = await strict.sign_in(user.email, PASSWORD)
    assert signed.tokens is None and signed.challenge is not None
    assert signed.challenge.purpose == "enrol"
    enrolment = await strict.begin_enrolment(challenge=signed.challenge.token)
    assert enrolment.secret != secret
    codes, tokens = await strict.confirm_enrolment(
        current_code(enrolment.secret), challenge=signed.challenge.token
    )
    assert len(codes) == 10 and isinstance(tokens, TokenPair)


async def test_without_a_required_factor_sign_in_issues_a_session_after_a_reset(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    await _enrol(identity, user)
    await identity.reset_totp(user.id, actor="admin")
    signed = await identity.sign_in(user.email, PASSWORD)
    assert signed.challenge is None and signed.tokens is not None


async def test_a_reset_of_an_unknown_user_is_refused(identity: Identity, db: Database) -> None:
    with pytest.raises(UserError, match="does not exist"):
        await identity.reset_totp(uuid.uuid4(), actor="admin")
    assert await audit_rows(db, ACTION) == []


async def test_a_reset_with_no_enrolment_succeeds_and_is_audited(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    assert await identity.reset_totp(user.id, actor="admin") is False
    rows = await audit_rows(db, ACTION)
    assert len(rows) == 1
    assert rows[0]["details"] == {
        "totp_removed": False,
        "recovery_codes_removed": 0,
        "sessions_ended": 0,
    }


# The audit event


async def test_the_reset_is_audited_once_without_a_secret_or_code(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    admin = await make_user(roles=("admin",))
    user = await make_user()
    secret, codes = await _enrol(identity, user)
    await identity.reset_totp(user.id, actor=str(admin.id), source_ip="198.51.100.7")
    rows = await audit_rows(db, ACTION)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == "success"
    assert row["actor"] == str(admin.id)
    assert (row["resource_type"], row["resource_id"]) == ("user", str(user.id))
    assert row["details"] == {
        "totp_removed": True,
        "recovery_codes_removed": 10,
        "sessions_ended": 0,
    }
    text = json.dumps(row, default=str).lower()
    encoded = base64.b32encode(secret).decode("ascii").rstrip("=").lower()
    assert encoded not in text and secret.hex() not in text
    assert not any(code.lower() in text for code in codes)


async def test_the_reset_and_its_audit_event_stand_or_fall_together(
    identity: Identity, make_user: UserFactory, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the audit event cannot be written, the enrolment is still there."""
    from warden.identity import service

    user = await make_user()
    await _enrol(identity, user)

    async def failing(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(service, "record_audit", failing)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await identity.reset_totp(user.id, actor="admin")
    assert await _counts(db, user) == (1, 10)


# Sessions (Skuld question 12)


async def test_a_reset_ends_every_session_of_the_user(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    secret, codes = await _enrol(identity, user)
    first = await _signed_in(identity, user, secret)
    challenge = (await identity.sign_in(user.email, PASSWORD)).challenge
    assert challenge is not None
    second = await identity.use_recovery_code(challenge.token, codes[0])
    other = await make_user()
    other_secret, _ = await _enrol(identity, other)
    kept = await _signed_in(identity, other, other_secret)

    await identity.reset_totp(user.id, actor="admin")

    for pair in (first, second):
        with pytest.raises(AuthenticationRefused):
            await identity.refresh(pair.refresh_token)
        with pytest.raises(AuthenticationRefused):
            await identity.authenticate(pair.access_token)
    assert await _live_sessions(db, user) == 0
    rows = await audit_rows(db, ACTION)
    assert rows[-1]["details"]["sessions_ended"] == 2
    # Another user's session is untouched.
    assert isinstance(await identity.refresh(kept.refresh_token), TokenPair)


# The route


async def test_the_route_answers_204_with_no_body(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    admin = await make_user(roles=("admin",))
    user = await make_user()
    await _enrol(identity, user)
    answer = await client.delete(
        f"/admin/users/{user.id}/totp", headers=await _bearer(identity, admin)
    )
    assert answer.status_code == 204
    assert answer.content == b""
    assert answer.headers["cache-control"] == "no-store"
    assert await _counts(db, user) == (0, 0)
    rows = await audit_rows(db, ACTION)
    assert rows[-1]["actor"] == str(admin.id)
    assert rows[-1]["resource_id"] == str(user.id)


async def test_the_route_is_idempotent(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    admin = await make_user(roles=("admin",))
    user = await make_user()
    headers = await _bearer(identity, admin)
    for _ in range(2):
        answer = await client.delete(f"/admin/users/{user.id}/totp", headers=headers)
        assert answer.status_code == 204
    assert len(await audit_rows(db, ACTION)) == 2


@pytest.mark.parametrize("target", ["missing", "not-a-uuid", "0" * 36])
async def test_the_route_answers_404_for_no_such_user(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory, target: str
) -> None:
    admin = await make_user(roles=("admin",))
    user_id = str(uuid.uuid4()) if target == "missing" else target
    answer = await client.delete(
        f"/admin/users/{user_id}/totp", headers=await _bearer(identity, admin)
    )
    assert answer.status_code == 404
    assert answer.json() == {"detail": "not found"}


async def test_the_route_refuses_a_caller_without_the_permission(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory, db: Database
) -> None:
    viewer = await make_user(roles=("viewer",))
    user = await make_user()
    secret, _codes = await _enrol(identity, user)
    url = f"/admin/users/{user.id}/totp"
    anonymous = await client.delete(url)
    assert anonymous.status_code == 401 and anonymous.content == REFUSAL
    forbidden = await client.delete(url, headers=await _bearer(identity, viewer))
    assert forbidden.status_code == 403
    # A user cannot reset their own enrolment through the admin route either.
    own = await _signed_in(identity, user, secret)
    answer = await client.delete(url, headers={"authorization": f"Bearer {own.access_token}"})
    assert answer.status_code == 403
    assert await _counts(db, user) == (1, 10)
    assert await audit_rows(db, ACTION) == []


# Concurrency


async def test_a_reset_racing_an_enrolment_confirmation_ends_consistently(
    strict: Identity, make_user: UserFactory, db: Database
) -> None:
    """Barriered: the reset and a forced enrolment's confirmation, over HTTP.

    Whichever wins, the user ends with no credential, no recovery codes
    and no live session, and neither request fails with a server error.
    """
    admin = await make_user(roles=("admin",))
    admin_secret, _ = await _enrol(strict, admin)
    headers = {
        "authorization": f"Bearer {(await _signed_in(strict, admin, admin_secret)).access_token}"
    }
    transport = httpx.ASGITransport(app=_app(strict), client=("203.0.113.9", 50000))
    outcomes: set[int] = set()
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        for round_ in range(6):
            user = await make_user()
            signed = (
                await c.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
            ).json()
            assert signed["status"] == "mfa_enrolment_required"
            challenge = signed["challenge"]
            begun = (await c.post("/auth/totp/enrolment", json={"challenge": challenge})).json()
            secret = base64.b32decode(begun["secret"] + "=" * (-len(begun["secret"]) % 8))
            code = current_code(secret)
            body = {"challenge": challenge, "code": code}
            url = f"/admin/users/{user.id}/totp"
            calls = [
                lambda b=body: c.post("/auth/totp/enrolment/confirm", json=b),
                lambda u=url: c.delete(u, headers=headers),
            ]
            # Alternate which request is scheduled first.
            flip = round_ % 2 == 1
            results = await race(*(calls[::-1] if flip else calls))
            confirm, reset = results[::-1] if flip else results
            assert isinstance(confirm, httpx.Response), confirm
            assert isinstance(reset, httpx.Response), reset
            assert reset.status_code == 204
            assert confirm.status_code in (200, 401), confirm.text
            outcomes.add(confirm.status_code)
            assert await _counts(db, user) == (0, 0)
            assert await _live_sessions(db, user) == 0
            assert (
                len([r for r in await audit_rows(db, ACTION) if r["resource_id"] == str(user.id)])
                == 1
            )


async def _still_waiting(task: asyncio.Task[object]) -> bool:
    """True if ``task`` is still blocked half a second later."""
    await asyncio.sleep(0.5)
    return not task.done()


async def test_a_reset_waits_for_a_confirmation_holding_the_credential(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    """The confirmation's transaction is open, its codes not yet committed.

    The reset blocks on the credential until the confirmation commits, then
    removes the credential and the codes the confirmation wrote.
    """
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    async with db.transaction() as tx:
        codes = await identity.mfa.confirm_enrolment(
            user.id, current_code(enrolment.secret), actor="t", conn=tx
        )
        assert codes is not None
        reset = asyncio.create_task(identity.reset_totp(user.id, actor="admin"))
        assert await _still_waiting(reset)
    assert await asyncio.wait_for(reset, 10) is True
    assert await _counts(db, user) == (0, 0)
    rows = await audit_rows(db, ACTION)
    assert rows[-1]["details"]["recovery_codes_removed"] == 10


async def test_a_confirmation_waits_for_a_reset_holding_the_credential(
    identity: Identity, make_user: UserFactory, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reset's transaction is open, its deletes not yet committed.

    The confirmation blocks on the credential until the reset commits, then
    finds nothing to confirm and writes no codes.
    """
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    deleted, release = asyncio.Event(), asyncio.Event()
    revoke_all = identity.sessions.revoke_all

    async def held(*args: Any, **kwargs: Any) -> int:
        # Runs inside the reset's transaction, after the deletes.
        deleted.set()
        await release.wait()
        return await revoke_all(*args, **kwargs)

    monkeypatch.setattr(identity.sessions, "revoke_all", held)
    reset = asyncio.create_task(identity.reset_totp(user.id, actor="admin"))
    await asyncio.wait_for(deleted.wait(), 10)
    confirm = asyncio.create_task(
        identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret), actor="t")
    )
    assert await _still_waiting(confirm)
    release.set()
    assert await asyncio.wait_for(reset, 10) is True
    assert await asyncio.wait_for(confirm, 10) is None
    assert await _counts(db, user) == (0, 0)


async def test_a_reset_arriving_before_the_confirmations_codes_does_not_deadlock(
    identity: Identity, make_user: UserFactory, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The confirmation holds the credential but has not yet written its codes.

    Writing the codes takes a key-share lock on the user through the foreign
    key; a reset that had locked the user row for update would deadlock here.
    """
    user = await make_user()
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    locked, release = asyncio.Event(), asyncio.Event()
    replace = identity.mfa._replace_recovery_codes

    async def held(*args: Any, **kwargs: Any) -> list[str]:
        locked.set()
        await release.wait()
        return await replace(*args, **kwargs)

    monkeypatch.setattr(identity.mfa, "_replace_recovery_codes", held)
    confirm = asyncio.create_task(
        identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret), actor="t")
    )
    await asyncio.wait_for(locked.wait(), 10)
    reset = asyncio.create_task(identity.reset_totp(user.id, actor="admin"))
    assert await _still_waiting(reset)
    release.set()
    codes = await asyncio.wait_for(confirm, 10)
    assert codes is not None and len(codes) == 10
    assert await asyncio.wait_for(reset, 10) is True
    assert await _counts(db, user) == (0, 0)
