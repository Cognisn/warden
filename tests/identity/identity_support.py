"""Helpers shared by identity tests (imported as ``identity_support``)."""

from __future__ import annotations

import asyncio
import time
import uuid
import weakref
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import unquote

import httpx

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, User
from warden.identity.dependencies import APP_STATE_KEY
from warden.identity.mail import MailMessage
from warden.identity.passwords import PasswordHasher
from warden.identity.service import PasswordChangeIssued, SignInResult
from warden.identity.tokens import TokenPair
from warden.identity.totp import code_at, step_for

# Cheap parameters for speed; the timing test builds its own default-cost hasher.
FAST_HASHER = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "correct horse battery staple"

UserFactory = Callable[..., Awaitable[User]]


class RecordingSender:
    """The product's mail sender, recording instead of sending. ``fail`` makes it refuse."""

    def __init__(self) -> None:
        self.sent: list[MailMessage] = []
        self.fail = False

    async def send(self, message: MailMessage) -> None:
        if self.fail:
            raise ConnectionError("mail.example.com is unreachable")
        self.sent.append(message)

    def token(self, index: int = -1) -> str:
        """The token in a sent message's link (the test links end ``?t=<token>``)."""
        link = next(line for line in self.sent[index].text.splitlines() if "?t=" in line).strip()
        return unquote(link.rpartition("?t=")[2].split()[0].rstrip("."))


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


def make_config(**identity: Any) -> WardenConfig:
    return parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "identity": identity,
        }
    )


def current_code(secret: bytes, offset: int = 0) -> str:
    return code_at(secret, step_for(time.time()) + offset)


def identity_code(identity: Identity, secret: bytes) -> str:
    """The current code by the Identity's own clock (a test may have moved it)."""
    return code_at(secret, step_for(identity.mfa._clock()))


async def enrol_totp(identity: Identity, user: User) -> bytes:
    """Enrol and confirm TOTP for ``user``; returns the secret.

    Confirmation claims the current step, so a later verification in the
    same step needs the next step's code (``current_code(secret, 1)``).
    """
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(
        user.id, identity_code(identity, enrolment.secret), actor="test"
    )
    assert codes is not None
    remember_totp(identity, user.id, enrolment.secret)
    return enrolment.secret


# Password sign-in always needs a second factor (ruling CS14). Tests that are
# about something else reach a session through these helpers, which pass the
# second factor the way a client would: TOTP, enrolled the first time it is
# needed. The secret each test enrolled is remembered per Identity.
_TOTP_SECRETS: weakref.WeakKeyDictionary[Identity, dict[uuid.UUID, bytes]] = (
    weakref.WeakKeyDictionary()
)


def remember_totp(identity: Identity, user_id: uuid.UUID, secret: bytes) -> None:
    _TOTP_SECRETS.setdefault(identity, {})[user_id] = secret


async def fresh_totp_code(identity: Identity, user_id: uuid.UUID) -> str:
    """A code the user's confirmed TOTP accepts now, enrolling TOTP first if they hold none.

    A code is accepted once per time step; a helper that only needs a session
    clears the user's last used step so a test can sign in as often as it
    likes. Single use per step is tested on its own (test_identity_mfa).
    """
    secret = _TOTP_SECRETS.get(identity, {}).get(user_id)
    confirmed = await identity.mfa.has_confirmed_totp(user_id)
    if secret is None or not confirmed:
        user = await identity.users.get(user_id)
        assert user is not None
        assert not confirmed, "the user holds TOTP the test did not enrol through enrol_totp"
        secret = await enrol_totp(identity, user)
    async with identity.db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.totp_credentials SET last_used_step = NULL WHERE user_id = %s",
            (user_id,),
        )
    return identity_code(identity, secret)


async def _user_id(identity: Identity, email: str) -> uuid.UUID:
    user = await identity.users.get_by_email(email)
    assert user is not None, email
    return user.id


async def complete_sign_in(
    identity: Identity, email: str, password: str = PASSWORD, **kw: Any
) -> SignInResult:
    """A password sign-in carried through its second factor: the session or forced change.

    A user holding no second factor is enrolled in TOTP (as a forced
    enrolment would) and signed in again; ``kw`` goes to every call.
    """
    result = await identity.sign_in(email, password, **kw)
    if result.challenge is None:
        return result
    user_id = await _user_id(identity, email)
    if result.challenge.purpose == "enrol":
        await fresh_totp_code(identity, user_id)
        result = await identity.sign_in(email, password, **kw)
        assert result.challenge is not None and result.challenge.purpose == "verify", result
    answer = await identity.verify_totp(
        result.challenge.token, await fresh_totp_code(identity, user_id), **kw
    )
    if isinstance(answer, PasswordChangeIssued):
        return SignInResult(password_change=answer)
    return SignInResult(tokens=answer)


async def sign_in_tokens(
    identity: Identity, email: str, password: str = PASSWORD, **kw: Any
) -> TokenPair:
    """The session from ``complete_sign_in``; fails if the password must change first."""
    result = await complete_sign_in(identity, email, password, **kw)
    assert result.tokens is not None, result
    return result.tokens


def identity_of(client: httpx.AsyncClient) -> Identity:
    """The Identity installed in the app an ASGI test client talks to."""
    transport = client._transport
    assert isinstance(transport, httpx.ASGITransport)
    identity: Identity = getattr(transport.app.state, APP_STATE_KEY)  # type: ignore[attr-defined]
    return identity


async def http_sign_in(
    client: httpx.AsyncClient,
    email: str,
    password: str = PASSWORD,
    *,
    prefix: str = "/auth",
    headers: Mapping[str, str] | None = None,
    identity: Identity | None = None,
) -> httpx.Response:
    """``POST <prefix>/sign-in`` carried through the second factor over HTTP.

    The final response: the session, a forced password change, or the
    refusal. A user holding no second factor is enrolled in TOTP first.
    """
    body = {"email": email, "password": password}
    response = await client.post(f"{prefix}/sign-in", json=body, headers=headers)
    if response.status_code != 200:
        return response
    status = response.json().get("status")
    if status not in ("mfa_required", "mfa_enrolment_required"):
        return response
    identity = identity or identity_of(client)
    user_id = await _user_id(identity, email)
    if status == "mfa_enrolment_required":
        await fresh_totp_code(identity, user_id)
        response = await client.post(f"{prefix}/sign-in", json=body, headers=headers)
        assert response.json().get("status") == "mfa_required", response.text
    challenge = response.json()["challenge"]
    code = await fresh_totp_code(identity, user_id)
    return await client.post(
        f"{prefix}/totp/verify", json={"challenge": challenge, "code": code}, headers=headers
    )


async def audit_rows(db: Database, action: str | None = None) -> list[dict[str, Any]]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT action, outcome, actor, resource_type, resource_id, details"
            " FROM warden.audit_events WHERE %s::text IS NULL OR action = %s ORDER BY id",
            (action, action),
        )
        names = ("action", "outcome", "actor", "resource_type", "resource_id", "details")
        return [dict(zip(names, row, strict=True)) for row in await cur.fetchall()]


async def race(*calls: Callable[[], Awaitable[Any]]) -> list[Any]:
    """Run ``calls`` as concurrent tasks released together by a barrier.

    Every task waits at the barrier until all have been scheduled, then
    starts its database work. Exceptions are returned, not raised, so a
    test can assert on each outcome.
    """
    barrier = asyncio.Barrier(len(calls))

    async def run(call: Callable[[], Awaitable[Any]]) -> Any:
        await barrier.wait()
        return await call()

    return list(await asyncio.gather(*(run(c) for c in calls), return_exceptions=True))


async def direct_session(
    identity: Identity, user_id: uuid.UUID, amr: tuple[str, ...] = ("pwd", "otp")
) -> TokenPair:
    """A session started directly, as a sign-in with ``amr`` would have started it."""
    policy = await identity.policy.current()
    async with identity.db.transaction() as tx:
        new = await identity.sessions.start(tx, user_id, list(amr), policy)
    return await identity.sessions.finish(new)


async def age_sessions(identity: Identity, user_id: uuid.UUID, seconds: int) -> None:
    """Make every session of the user ``seconds`` older, as if signed in that long ago."""
    async with identity.db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.sessions SET created_at = created_at - %s * interval '1 second'"
            " WHERE user_id = %s",
            (seconds, user_id),
        )
