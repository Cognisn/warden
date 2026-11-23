"""Passkey sign-in and the allowed second factors, and equal work on every refusal.

Skuld release warden 0.2.0, question 1 (answer b): while the administrator
does not allow passkeys as a second factor, sign-in with a passkey alone is
refused, uniformly and audited ``factor_not_allowed``, for every user whose
method in force is not ``passkey_only``. A ``passkey_only`` user's passkey
is how they sign in, so they sign in as before.

Every refusal of a passkey sign-in that gets past the challenge does the
same work before it is refused: the same statements, in the same order,
and one signature verification, whatever the reason.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import psycopg
import pytest
from fido2.cose import ES256
from identity_support import UserFactory, audit_rows
from passkey_support import (
    assert_refused,
    give_passkey,
    http_client,
    passkey_assertion,
    passkey_authenticator,
    passkey_config,
    passkey_options,
    passkey_sign_in,
    set_method,
    set_status,
)
from soft_authenticator import SoftwareAuthenticator, other_key

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity, SignInMethod, User
from warden.identity.webauthn import WebAuthnPurpose

pytestmark = pytest.mark.db


@pytest.fixture
def config() -> WardenConfig:
    return passkey_config(sign_in_attempt_limit=1000)


@pytest.fixture
async def http(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(identity) as client:
        yield client


async def _allow(identity: Identity, *factors: str) -> None:
    await identity.update_sign_in_settings(actor="admin-1", allowed_second_factors=list(factors))


async def _passkey_user(
    identity: Identity, make_user: UserFactory, method: SignInMethod = SignInMethod.PASSWORD_AND_SSO
) -> tuple[User, SoftwareAuthenticator]:
    user = await make_user()
    key, _ = await give_passkey(identity, user)
    if method is not SignInMethod.PASSWORD_AND_SSO:
        await set_method(identity.db, user.id, method)
    return user, key


async def _last_failure(db: Database) -> dict[str, Any]:
    rows = [r for r in await audit_rows(db, "warden.identity.sign_in") if r["outcome"] == "failure"]
    assert rows, "no sign-in failure was audited"
    return rows[-1]


async def _sessions(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


# Passkey sign-in while passkeys are not an allowed second factor.


@pytest.mark.parametrize("method", [SignInMethod.PASSWORD_AND_SSO, SignInMethod.PASSWORD])
async def test_passkey_sign_in_is_refused_while_passkeys_are_not_allowed(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    method: SignInMethod,
) -> None:
    user, key = await _passkey_user(identity, make_user, method)
    (before,) = await identity.webauthn_credentials.list(user.id)
    await _allow(identity, "totp")
    assert_refused(await passkey_sign_in(http, await passkey_assertion(http, key)))
    failure = await _last_failure(db)
    assert failure["details"] == {
        "reason": "factor_not_allowed",
        "method": "passkey",
        "credential_id": str(before.id),
    }
    assert failure["resource_id"] == str(user.id)
    assert await _sessions(db, user.id) == 0
    # A refused sign-in changes nothing: the counter and last use stay as they were.
    (after,) = await identity.webauthn_credentials.list(user.id)
    assert after.sign_count == before.sign_count
    assert after.last_used_at == before.last_used_at


async def test_a_passkey_only_user_signs_in_while_passkeys_are_not_allowed(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user, key = await _passkey_user(identity, make_user, SignInMethod.PASSKEY_ONLY)
    await _allow(identity, "totp")
    answer = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert answer.status_code == 200, answer.text
    principal = await identity.authenticate(answer.json()["access_token"])
    assert principal.user_id == user.id
    assert principal.amr == ("hwk", "mfa")


async def test_the_allowed_set_is_read_when_the_sign_in_is_decided(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    """No cached copy: each change of the setting applies to the next sign-in."""
    _, key = await _passkey_user(identity, make_user)
    assert (await passkey_sign_in(http, await passkey_assertion(http, key))).status_code == 200
    await _allow(identity, "totp")
    assert_refused(await passkey_sign_in(http, await passkey_assertion(http, key)))
    await _allow(identity, "totp", "passkey")
    assert (await passkey_sign_in(http, await passkey_assertion(http, key))).status_code == 200
    await _allow(identity, "passkey")
    assert (await passkey_sign_in(http, await passkey_assertion(http, key))).status_code == 200


async def test_the_refusal_is_byte_identical_to_a_bad_signature(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    _, refused_key = await _passkey_user(identity, make_user)
    _, other = await _passkey_user(identity, make_user, SignInMethod.PASSKEY_ONLY)
    await _allow(identity, "totp")
    not_allowed = await passkey_sign_in(http, await passkey_assertion(http, refused_key))
    bad = await passkey_sign_in(http, await passkey_assertion(http, other, signing_key=other_key()))
    assert_refused(not_allowed)
    assert_refused(bad)
    assert not_allowed.content == bad.content
    assert dict(not_allowed.headers) == dict(bad.headers)


async def test_a_user_whose_passkeys_became_disallowed_during_the_ceremony_gets_no_session(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checked again in the transaction that issues the session."""
    user, key = await _passkey_user(identity, make_user)
    webauthn = identity.webauthn
    assert webauthn is not None
    finish = webauthn.finish_authentication

    async def finish_then_disallow(*args: Any, **kwargs: Any) -> Any:
        assertion = await finish(*args, **kwargs)
        await _allow(identity, "totp")
        return assertion

    monkeypatch.setattr(webauthn, "finish_authentication", finish_then_disallow)
    assert_refused(await passkey_sign_in(http, await passkey_assertion(http, key)))
    assert (await _last_failure(db))["details"]["reason"] == "factor_not_allowed"
    assert await _sessions(db, user.id) == 0


# Equal work on every refusal.


class _Trace:
    """The statements run and signatures verified during one sign-in, in order."""

    def __init__(self) -> None:
        self.steps: list[str] | None = None

    def record(self, step: str) -> None:
        if self.steps is not None:
            self.steps.append(step)

    async def run(self, call: Callable[[], Any]) -> list[str]:
        self.steps = []
        try:
            await call()
        finally:
            steps, self.steps = self.steps, None
        return steps


@pytest.fixture
def trace(monkeypatch: pytest.MonkeyPatch) -> _Trace:
    recorder = _Trace()
    execute = psycopg.AsyncCursor.execute

    async def traced_execute(self: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        text = query if isinstance(query, str | bytes) else query.as_string(self)
        recorder.record(" ".join(str(text).split()))
        return await execute(self, query, *args, **kwargs)

    verify = ES256.verify

    def traced_verify(self: Any, message: bytes, signature: bytes) -> None:
        recorder.record("verify")
        verify(self, message, signature)

    monkeypatch.setattr(psycopg.AsyncCursor, "execute", traced_execute)
    monkeypatch.setattr(ES256, "verify", traced_verify)
    return recorder


async def test_every_refusal_after_the_challenge_does_the_same_work(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    trace: _Trace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The session policy is cached for a while; hold it still, so a reload cannot
    # land inside one traced sign-in and not another.
    held = await identity.policy.current()

    async def fixed_policy() -> Any:
        return held

    monkeypatch.setattr(identity.policy, "current", fixed_policy)

    stranger = passkey_authenticator()
    stranger.register(
        {"rp": {"id": "app.example.com"}, "user": {"id": "AAAA"}, "challenge": "AAAA"}
    )
    _, handle_key = await _passkey_user(identity, make_user)
    suspended, suspended_key = await _passkey_user(identity, make_user)
    await set_status(db, suspended.id, "suspended")
    _, sso_key = await _passkey_user(identity, make_user, SignInMethod.SSO_ONLY)
    _, signature_key = await _passkey_user(identity, make_user, SignInMethod.PASSKEY_ONLY)
    _, not_allowed_key = await _passkey_user(identity, make_user)
    hidden = await make_user()
    hidden_key, _ = await give_passkey(
        identity,
        hidden,
        SoftwareAuthenticator(resident=False),
        purpose=WebAuthnPurpose.SECOND_FACTOR,
        report_rk=False,
    )
    unverified = await make_user()
    unverified_key, _ = await give_passkey(
        identity,
        unverified,
        passkey_authenticator(user_verifying=False),
        purpose=WebAuthnPurpose.SECOND_FACTOR,
    )
    await _allow(identity, "totp")

    async def hidden_assertion() -> dict[str, Any]:
        options = (await passkey_options(http)).json()["public_key"]
        return hidden_key.authenticate(
            options, credential_id=hidden_key.only_credential().credential_id
        )

    cases: dict[str, Callable[[], Any]] = {
        "unknown_credential": lambda: passkey_assertion(http, stranger),
        "user_handle": lambda: passkey_assertion(http, handle_key, user_handle=b"\x00" * 64),
        "inactive_user": lambda: passkey_assertion(http, suspended_key),
        "sso_only": lambda: passkey_assertion(http, sso_key),
        "signature": lambda: passkey_assertion(http, signature_key, signing_key=other_key()),
        "factor_not_allowed": lambda: passkey_assertion(http, not_allowed_key),
        "not_discoverable": hidden_assertion,
        "user_verification": lambda: passkey_assertion(http, unverified_key, uv=True),
    }
    traces: dict[str, list[str]] = {}
    for _ in range(2):  # the first round warms every cache; the second is compared
        for name, make in cases.items():
            credential = await make()

            async def attempt(credential: Any = credential) -> None:
                assert_refused(await passkey_sign_in(http, credential))

            traces[name] = await trace.run(attempt)
            assert (await _last_failure(db))["details"]["reason"] == name
    first = traces["unknown_credential"]
    assert first.count("verify") == 1, first
    for name, steps in traces.items():
        assert steps == first, (name, steps, first)
