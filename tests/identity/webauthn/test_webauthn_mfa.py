"""Security keys and passkeys as a second factor, peers of TOTP (rulings P4 and P7).

Through the HTTP routes, with the software authenticator: registration
signed in and in forced enrolment, the second step of a password sign-in,
the methods a user holds, shared recovery codes, the last-factor rule, and
the user's own list, rename and remove.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fido2.utils import websafe_encode
from identity_support import (
    PASSWORD,
    RecordingSender,
    UserFactory,
    audit_rows,
    current_code,
    enrol_totp,
    race,
)
from soft_authenticator import SoftwareAuthenticator, other_key
from webauthn_support import expire_challenges

from warden.db import Database
from warden.identity import Identity, SignInMethod, User, UserStatus
from warden.identity.mail import MailKind

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'
LAST_FACTOR = {
    "detail": "the last second factor cannot be removed while a second factor is required"
}


def _app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def http(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_app(identity), client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


async def _require_mfa(identity: Identity) -> None:
    await identity.policy.update(actor="test", require_mfa=True)


async def _sign_in(http: httpx.AsyncClient, user: User) -> httpx.Response:
    return await http.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})


async def _bearer(http: httpx.AsyncClient, user: User) -> dict[str, str]:
    """Sign in with the password alone (the user holds no second factor yet)."""
    answer = await _sign_in(http, user)
    assert answer.json()["status"] == "signed_in", answer.json()
    return {"authorization": f"Bearer {answer.json()['access_token']}"}


async def _challenge(http: httpx.AsyncClient, user: User, status: str = "mfa_required") -> str:
    answer = (await _sign_in(http, user)).json()
    assert answer["status"] == status, answer
    token: str = answer["challenge"]
    return token


async def _register(
    http: httpx.AsyncClient,
    authenticator: SoftwareAuthenticator,
    *,
    headers: dict[str, str] | None = None,
    challenge: str | None = None,
    nickname: str | None = None,
    **tamper: Any,
) -> httpx.Response:
    body: dict[str, Any] = {} if challenge is None else {"challenge": challenge}
    begun = await http.post("/auth/webauthn/registration", json=body, headers=headers or {})
    assert begun.status_code == 200, begun.text
    response = authenticator.register(begun.json()["public_key"], **tamper)
    confirm = {**body, "credential": response}
    if nickname is not None:
        confirm["nickname"] = nickname
    return await http.post(
        "/auth/webauthn/registration/confirm", json=confirm, headers=headers or {}
    )


async def _with_key(
    http: httpx.AsyncClient, user: User, **authenticator: Any
) -> SoftwareAuthenticator:
    """Register a security key for a signed-in user holding no second factor."""
    key = SoftwareAuthenticator(**authenticator)
    answer = await _register(http, key, headers=await _bearer(http, user))
    assert answer.status_code == 200, answer.text
    return key


async def _options(http: httpx.AsyncClient, challenge: str) -> httpx.Response:
    return await http.post("/auth/webauthn/verify/options", json={"challenge": challenge})


async def _assertion(
    http: httpx.AsyncClient, challenge: str, key: SoftwareAuthenticator, **tamper: Any
) -> dict[str, Any]:
    options = await _options(http, challenge)
    assert options.status_code == 200, options.text
    return key.authenticate(options.json()["public_key"], **tamper)


async def _verify(http: httpx.AsyncClient, challenge: str, credential: object) -> httpx.Response:
    return await http.post(
        "/auth/webauthn/verify", json={"challenge": challenge, "credential": credential}
    )


async def _key_sign_in(
    http: httpx.AsyncClient, user: User, key: SoftwareAuthenticator, **tamper: Any
) -> httpx.Response:
    challenge = await _challenge(http, user)
    return await _verify(http, challenge, await _assertion(http, challenge, key, **tamper))


async def _amr(identity: Identity, answer: httpx.Response) -> tuple[str, ...]:
    principal = await identity.authenticate(answer.json()["access_token"])
    return principal.amr


async def _recovery_code_count(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.recovery_codes WHERE user_id = %s AND used_at IS NULL",
            (user_id,),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


def _refused(answer: httpx.Response) -> None:
    assert answer.status_code == 401
    assert answer.content == REFUSAL
    assert answer.headers["www-authenticate"] == "Bearer"
    assert answer.headers["cache-control"] == "no-store"


# The second factor at sign-in.


async def test_password_then_key_signs_in_with_pwd_and_hwk(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    key = await _with_key(http, user)
    answer = await _key_sign_in(http, user, key)
    assert answer.status_code == 200, answer.text
    assert answer.json()["status"] == "signed_in"
    assert await _amr(identity, answer) == ("pwd", "hwk")
    (event,) = [
        row
        for row in await audit_rows(db, "warden.identity.sign_in")
        if row["outcome"] == "success" and row["details"].get("amr") == ["pwd", "hwk"]
    ]
    assert event["resource_id"] == str(user.id)
    (credential,) = await identity.webauthn_credentials.list(user.id)
    assert event["details"]["credential_id"] == str(credential.id)


async def test_a_key_without_user_verification_still_passes_as_a_second_factor(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    key = await _with_key(http, user, user_verifying=False)
    (credential,) = await identity.webauthn_credentials.list(user.id)
    assert credential.user_verified is False
    answer = await _key_sign_in(http, user, key)
    assert answer.status_code == 200, answer.text
    assert await _amr(identity, answer) == ("pwd", "hwk")


async def test_the_options_list_only_that_users_credentials(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user, other = await make_user(), await make_user()
    key = await _with_key(http, user)
    await _with_key(http, other)
    options = await _options(http, await _challenge(http, user))
    allowed = options.json()["public_key"]["allowCredentials"]
    assert [d["id"] for d in allowed] == [websafe_encode(key.only_credential().credential_id)]
    assert options.json()["public_key"]["userVerification"] == "preferred"
    assert "expires_at" in options.json()


async def test_mfa_required_lists_the_kinds_the_user_holds(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    totp_only, key_only, both = await make_user(), await make_user(), await make_user()
    await enrol_totp(identity, totp_only)
    await _with_key(http, key_only)
    headers = await _bearer(http, both)
    await enrol_totp(identity, both)
    assert (await _register(http, SoftwareAuthenticator(), headers=headers)).status_code == 200

    for user, methods in (
        (totp_only, ["totp"]),
        (key_only, ["webauthn"]),
        (both, ["totp", "webauthn"]),
    ):
        answer = (await _sign_in(http, user)).json()
        assert answer["status"] == "mfa_required"
        assert answer["methods"] == methods
        assert set(answer) == {"status", "challenge", "expires_in", "methods"}


async def test_an_enrolment_challenge_keeps_its_published_shape(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    await _require_mfa(identity)
    answer = (await _sign_in(http, await make_user())).json()
    assert answer["status"] == "mfa_enrolment_required"
    assert set(answer) == {"status", "challenge", "expires_in"}


async def test_a_key_alone_turns_a_password_sign_in_into_a_challenge(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    """The methods-held check: a key counts even where the policy requires nothing."""
    user = await make_user()
    await _with_key(http, user)
    answer = (await _sign_in(http, user)).json()
    assert answer["status"] == "mfa_required"


async def test_a_totp_code_still_completes_a_challenge_for_a_user_with_both(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, user)
    secret = await enrol_totp(identity, user)
    assert (await _register(http, SoftwareAuthenticator(), headers=headers)).status_code == 200
    challenge = await _challenge(http, user)
    answer = await http.post(
        "/auth/totp/verify", json={"challenge": challenge, "code": current_code(secret, 1)}
    )
    assert answer.status_code == 200, answer.text
    assert await _amr(identity, answer) == ("pwd", "otp")


# Refusals: the same bytes as /totp/verify's, the reason in the audit trail.


async def test_every_key_refusal_is_byte_identical_to_totp_verifys(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    key = await _with_key(http, user)
    totp = await http.post("/auth/totp/verify", json={"challenge": "x" * 43, "code": "123456"})
    _refused(totp)

    challenge = await _challenge(http, user)
    refusals = [
        await _options(http, "x" * 43),
        await http.post("/auth/webauthn/verify/options", content=b"not json"),
        await _verify(http, "x" * 43, {}),
        await _verify(http, challenge, "not a credential"),
        await _verify(
            http, challenge, await _assertion(http, challenge, key, signing_key=other_key())
        ),
        await _verify(
            http,
            challenge,
            await _assertion(http, challenge, key, origin="https://evil.example.net"),
        ),
        await http.post("/auth/webauthn/verify", content=b"[]"),
    ]
    for answer in refusals:
        _refused(answer)
        assert answer.content == totp.content
        assert dict(answer.headers) == dict(totp.headers)

    reasons = [
        (row["details"]["method"], row["details"]["reason"])
        for row in await audit_rows(db, "warden.identity.mfa.verify")
        if row["details"]["method"] == "webauthn"
    ]
    assert ("webauthn", "unknown_challenge") in reasons
    assert ("webauthn", "malformed") in reasons
    assert ("webauthn", "signature") in reasons
    assert ("webauthn", "origin") in reasons


async def test_a_user_without_keys_is_refused_options(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    _refused(await _options(http, await _challenge(http, user)))
    reasons = [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.mfa.verify")]
    assert "no_credentials" in reasons


@pytest.mark.parametrize("status", [UserStatus.SUSPENDED, UserStatus.DEACTIVATED])
async def test_a_user_no_longer_active_is_refused_at_the_second_step(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    status: UserStatus,
) -> None:
    user = await make_user()
    key = await _with_key(http, user)
    challenge = await _challenge(http, user)
    assertion = await _assertion(http, challenge, key)
    await identity.users.set_status(user.id, status, actor="test")
    _refused(await _verify(http, challenge, assertion))
    _refused(await _options(http, challenge))
    reasons = [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.mfa.verify")]
    assert reasons.count("user_inactive") == 2


async def test_a_user_moved_to_sso_only_is_refused_at_the_second_step(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    key = await _with_key(http, user)
    challenge = await _challenge(http, user)
    assertion = await _assertion(http, challenge, key)
    # Behind the service's back: since wave 11 the service refuses sso_only while the
    # user holds a key (Skuld question 25); the second step must still re-check.
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.users SET sign_in_method = 'sso_only' WHERE id = %s", (user.id,)
        )
    _refused(await _verify(http, challenge, assertion))


async def test_a_user_moved_off_password_sign_in_is_refused_by_identitys_own_re_check(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """``passkey_only`` (wave 11) passes the ceremony's own check; identity's refuses it."""
    user = await make_user()
    key = await _with_key(http, user)
    challenge = await _challenge(http, user)
    assertion = await _assertion(http, challenge, key)
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.users SET sign_in_method = 'passkey_only' WHERE id = %s", (user.id,)
        )
    _refused(await _verify(http, challenge, assertion))
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s", (user.id,)
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 1  # only the session that registered the key
    # Refused before the ceremony ran: the key was not used.
    (stored,) = await identity.webauthn_credentials.list(user.id)
    assert (stored.sign_count, stored.last_used_at) == (0, None)
    (refused,) = [
        r
        for r in await audit_rows(db, "warden.identity.mfa.verify")
        if r["details"]["method"] == "webauthn"
    ]
    assert refused["details"]["reason"] == "sso_only"


async def test_a_user_suspended_during_the_ceremony_gets_no_session(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status is checked again in the transaction that issues the session."""
    user = await make_user()
    key = await _with_key(http, user)
    challenge = await _challenge(http, user)
    assertion = await _assertion(http, challenge, key)
    assert identity.webauthn is not None
    finish = identity.webauthn.finish_authentication

    async def suspended_meanwhile(*args: Any, **kwargs: Any) -> Any:
        result = await finish(*args, **kwargs)
        await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="test")
        return result

    monkeypatch.setattr(identity.webauthn, "finish_authentication", suspended_meanwhile)
    _refused(await _verify(http, challenge, assertion))
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s AND amr = %s",
            (user.id, ["pwd", "hwk"]),
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 0


async def test_one_challenge_completes_at_most_one_sign_in(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    """Two good assertions for one mfa_required challenge: one session, in turn or at once."""
    user = await make_user()
    key = await _with_key(http, user, counter_step=0)  # no counter, as synced passkeys
    challenge = await _challenge(http, user)
    first = await _assertion(http, challenge, key)
    second = await _assertion(http, challenge, key)
    assert (await _verify(http, challenge, first)).status_code == 200
    _refused(await _verify(http, challenge, second))

    challenge = await _challenge(http, user)
    assertions = [await _assertion(http, challenge, key) for _ in range(4)]
    answers = await race(*[(lambda a=a: _verify(http, challenge, a)) for a in assertions])
    assert sorted(a.status_code for a in answers) == [200, 401, 401, 401]


async def test_two_first_keys_at_once_issue_the_codes_once(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    for _ in range(4):
        user = await make_user()
        headers = await _bearer(http, user)
        responses = []
        for _ in range(2):
            begun = await http.post("/auth/webauthn/registration", json={}, headers=headers)
            responses.append(SoftwareAuthenticator().register(begun.json()["public_key"]))
        answers = await race(
            *[
                (
                    lambda r=r, h=headers: http.post(
                        "/auth/webauthn/registration/confirm",
                        json={"credential": r},
                        headers=h,
                    )
                )
                for r in responses
            ]
        )
        issued = sorted(len(a.json()["recovery_codes"]) for a in answers)
        assert issued == [0, 10], issued
        assert await _recovery_code_count(db, user.id) == 10


async def test_wrong_assertions_use_up_the_challenges_attempts(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    key = await _with_key(http, user)
    challenge = await _challenge(http, user)
    for _ in range(5):  # identity.mfa_max_failures
        _refused(
            await _verify(
                http, challenge, await _assertion(http, challenge, key, signing_key=other_key())
            )
        )
    _refused(await _options(http, challenge))


async def test_a_counter_that_does_not_increase_is_refused_and_audited_as_a_clone(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    key = await _with_key(http, user)
    assert (await _key_sign_in(http, user, key)).status_code == 200
    _refused(await _key_sign_in(http, user, key, counter=1))
    (credential,) = await identity.webauthn_credentials.list(user.id)
    (clone,) = await audit_rows(db, "warden.identity.mfa.webauthn.clone_suspected")
    assert clone["outcome"] == "failure"
    assert clone["resource_id"] == str(user.id)
    assert clone["details"] == {"credential_id": str(credential.id)}


async def test_the_same_assertion_twice_at_once_gives_exactly_one_session(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    key = await _with_key(http, user)
    challenge = await _challenge(http, user)
    assertion = await _assertion(http, challenge, key)
    answers = await race(*[lambda: _verify(http, challenge, assertion) for _ in range(6)])
    statuses = sorted(a.status_code for a in answers)
    assert statuses == [200, 401, 401, 401, 401, 401], statuses
    async with identity.db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s AND amr = %s",
            (user.id, ["pwd", "hwk"]),
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 1


# Registration as a second factor.


async def test_registration_is_a_second_factor_ceremony_with_a_nickname(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, user)
    begun = await http.post("/auth/webauthn/registration", json={}, headers=headers)
    selection = begun.json()["public_key"]["authenticatorSelection"]
    assert (selection["residentKey"], selection["userVerification"]) == ("preferred", "preferred")
    assert selection.get("requireResidentKey", False) is False
    key = SoftwareAuthenticator()
    response = key.register(begun.json()["public_key"])
    answer = await http.post(
        "/auth/webauthn/registration/confirm",
        json={"credential": response, "nickname": "Desk key"},
        headers=headers,
    )
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["credential"]["nickname"] == "Desk key"
    assert body["credential"]["discoverable"] is False
    assert len(body["recovery_codes"]) == 10
    (event,) = await audit_rows(db, "warden.identity.mfa.webauthn.registered")
    assert event["outcome"] == "success"
    assert event["details"] == {
        "credential_id": body["credential"]["id"],
        "discoverable": False,
        "user_verified": True,
        "first_factor": True,
    }


async def test_a_discoverable_verified_credential_is_recorded_as_such(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    await _with_key(http, user, resident=True)
    (credential,) = await identity.webauthn_credentials.list(user.id)
    assert credential.discoverable is True
    assert credential.user_verified is True


async def test_forced_enrolment_completed_by_a_key_signs_in_and_issues_codes_once(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    await _require_mfa(identity)
    user = await make_user()
    challenge = await _challenge(http, user, "mfa_enrolment_required")
    key = SoftwareAuthenticator()
    answer = await _register(http, key, challenge=challenge, nickname="Laptop")
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["status"] == "signed_in"
    assert len(body["recovery_codes"]) == 10
    assert body["credential"]["nickname"] == "Laptop"
    assert await _amr(identity, answer) == ("pwd", "hwk")
    assert await _recovery_code_count(db, user.id) == 10
    assert [m.kind for m in mail.sent] == [MailKind.MFA_ENROLLED]
    # Skuld question 22: one neutral wording for either kind of factor.
    assert f"Two-step verification was set up on {user.email} on " in mail.sent[0].text
    assert "authenticator app" not in mail.sent[0].text
    assert "authenticator app" not in (mail.sent[0].html or "")

    # require_mfa is now satisfied by the key: the next sign-in asks for it.
    assert (await _sign_in(http, user)).json()["status"] == "mfa_required"
    assert (await _key_sign_in(http, user, key)).status_code == 200
    # A recovery code covers the key too.
    challenge = await _challenge(http, user)
    used = await http.post(
        "/auth/recovery-code", json={"challenge": challenge, "code": body["recovery_codes"][0]}
    )
    assert used.status_code == 200, used.text


async def test_an_enrolment_challenge_is_used_once(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    await _require_mfa(identity)
    user = await make_user()
    challenge = await _challenge(http, user, "mfa_enrolment_required")
    assert (await _register(http, SoftwareAuthenticator(), challenge=challenge)).status_code == 200
    _refused(await http.post("/auth/webauthn/registration", json={"challenge": challenge}))


async def test_a_refused_registration_under_a_challenge_is_the_uniform_refusal(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    await _require_mfa(identity)
    user = await make_user()
    challenge = await _challenge(http, user, "mfa_enrolment_required")
    _refused(
        await _register(
            http, SoftwareAuthenticator(), challenge=challenge, origin="https://evil.example.net"
        )
    )
    assert await identity.webauthn_credentials.count(user.id) == 0
    _refused(await http.post("/auth/webauthn/registration", json={"challenge": "x" * 43}))


async def test_a_forced_enrolment_refused_after_the_key_is_stored_keeps_no_key(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The user suspended while the key is stored: no session, and the key goes again."""
    await _require_mfa(identity)
    user = await make_user()
    challenge = await _challenge(http, user, "mfa_enrolment_required")
    assert identity.webauthn is not None
    finish = identity.webauthn.finish_registration

    async def suspended_meanwhile(*args: Any, **kwargs: Any) -> Any:
        registration = await finish(*args, **kwargs)
        await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="test")
        return registration

    monkeypatch.setattr(identity.webauthn, "finish_registration", suspended_meanwhile)
    _refused(await _register(http, SoftwareAuthenticator(), challenge=challenge))
    assert await identity.webauthn_credentials.count(user.id) == 0
    assert await _recovery_code_count(db, user.id) == 0


async def test_a_second_factor_added_later_issues_no_codes(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    # TOTP first, then a key.
    user = await make_user()
    headers = await _bearer(http, user)
    enrolment = await http.post("/auth/totp/enrolment", json={}, headers=headers)
    secret = enrolment.json()["secret"]
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8))
    confirmed = await http.post(
        "/auth/totp/enrolment/confirm", json={"code": current_code(raw)}, headers=headers
    )
    codes = confirmed.json()["recovery_codes"]
    assert len(codes) == 10
    answer = await _register(http, SoftwareAuthenticator(), headers=headers)
    assert answer.status_code == 200, answer.text
    assert answer.json()["recovery_codes"] == []
    assert await _recovery_code_count(db, user.id) == 10
    assert [m.kind for m in mail.sent] == [MailKind.MFA_ENROLLED]

    # A key first, then TOTP.
    other = await make_user()
    other_headers = await _bearer(http, other)
    first = await _register(http, SoftwareAuthenticator(), headers=other_headers)
    assert len(first.json()["recovery_codes"]) == 10
    enrolment = await http.post("/auth/totp/enrolment", json={}, headers=other_headers)
    secret = enrolment.json()["secret"]
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8))
    confirmed = await http.post(
        "/auth/totp/enrolment/confirm", json={"code": current_code(raw)}, headers=other_headers
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json() == {"recovery_codes": []}
    assert await _recovery_code_count(db, other.id) == 10
    assert [m.kind for m in mail.sent] == [MailKind.MFA_ENROLLED, MailKind.MFA_ENROLLED]
    # A second key issues none either.
    second = await _register(http, SoftwareAuthenticator(), headers=other_headers)
    assert second.json()["recovery_codes"] == []


async def test_a_signed_in_refusal_says_the_credential_was_not_accepted(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, user)
    answer = await _register(
        http, SoftwareAuthenticator(), headers=headers, origin="https://evil.example.net"
    )
    assert answer.status_code == 400
    assert answer.json() == {"detail": "credential not accepted"}
    (event,) = await audit_rows(db, "warden.identity.mfa.webauthn.registered")
    assert event["outcome"] == "failure"
    assert event["details"] == {"reason": "origin"}
    bad_name = await _register(http, SoftwareAuthenticator(), headers=headers, nickname="")
    assert bad_name.status_code == 400
    assert bad_name.json() == {"detail": "the nickname is not valid"}


async def test_the_credential_limit_is_a_409(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, user)
    for _ in range(10):  # webauthn.max_credentials_per_user
        assert (await _register(http, SoftwareAuthenticator(), headers=headers)).status_code == 200
    answer = await http.post("/auth/webauthn/registration", json={}, headers=headers)
    assert answer.status_code == 409
    assert answer.json() == {"detail": "the credential limit is reached"}


async def test_an_sso_only_user_cannot_register_a_key(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, user)
    await identity.users.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="test")
    answer = await http.post("/auth/webauthn/registration", json={}, headers=headers)
    assert answer.status_code == 409
    assert answer.json() == {"detail": "security keys are not available to this user"}


async def test_registration_needs_a_bearer_or_a_challenge(http: httpx.AsyncClient) -> None:
    _refused(await http.post("/auth/webauthn/registration", json={}))
    _refused(await http.post("/auth/webauthn/registration/confirm", json={"credential": {}}))
    _refused(await http.get("/auth/webauthn/credentials"))


# Management: list, rename, remove.


async def test_a_user_lists_renames_and_removes_their_keys(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, user)
    await _register(http, SoftwareAuthenticator(), headers=headers, nickname="One")
    await _register(
        http,
        SoftwareAuthenticator(backup_eligible=True, backed_up=True, resident=True),
        headers=headers,
    )
    listed = await http.get("/auth/webauthn/credentials", headers=headers)
    assert listed.status_code == 200
    first, second = listed.json()["credentials"]
    assert set(first) == {
        "id",
        "nickname",
        "created_at",
        "last_used_at",
        "aaguid",
        "backup_eligible",
        "backup_state",
        "discoverable",
        "passkey",
    }
    assert first["nickname"] == "One"
    assert first["aaguid"] == "2fc0579f-8113-47ea-b116-bb5a8db9202a"
    assert (second["backup_eligible"], second["backup_state"], second["discoverable"]) == (
        True,
        True,
        True,
    )

    renamed = await http.patch(
        f"/auth/webauthn/credentials/{second['id']}", json={"nickname": "Phone"}, headers=headers
    )
    assert renamed.status_code == 200
    assert renamed.json()["credential"]["nickname"] == "Phone"
    cleared = await http.patch(
        f"/auth/webauthn/credentials/{second['id']}", json={"nickname": None}, headers=headers
    )
    assert cleared.json()["credential"]["nickname"] is None
    bad = await http.patch(
        f"/auth/webauthn/credentials/{second['id']}", json={"nickname": "a\nb"}, headers=headers
    )
    assert (bad.status_code, bad.json()) == (400, {"detail": "the nickname is not valid"})

    removed = await http.delete(f"/auth/webauthn/credentials/{first['id']}", headers=headers)
    assert removed.status_code == 204
    again = await http.delete(f"/auth/webauthn/credentials/{first['id']}", headers=headers)
    assert (again.status_code, again.json()) == (404, {"detail": "not found"})
    assert [c.id for c in await identity.webauthn_credentials.list(user.id)] == [
        uuid.UUID(second["id"])
    ]
    renamed_events = await audit_rows(db, "warden.identity.mfa.webauthn.renamed")
    assert [e["details"] for e in renamed_events] == [{"credential_id": second["id"]}] * 2
    (removed_event,) = await audit_rows(db, "warden.identity.mfa.webauthn.removed")
    assert removed_event["details"] == {
        "credential_id": first["id"],
        "recovery_codes_removed": 0,
    }


async def test_a_user_cannot_touch_another_users_key(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    owner, other = await make_user(), await make_user()
    await _with_key(http, owner)
    (credential,) = await identity.webauthn_credentials.list(owner.id)
    headers = await _bearer(http, other)
    url = f"/auth/webauthn/credentials/{credential.id}"
    assert (await http.patch(url, json={"nickname": "Mine"}, headers=headers)).status_code == 404
    assert (await http.delete(url, headers=headers)).status_code == 404
    assert (
        await http.delete("/auth/webauthn/credentials/not-a-uuid", headers=headers)
    ).status_code == 404
    assert await identity.webauthn_credentials.count(owner.id) == 1


async def test_the_last_factor_cannot_be_removed_while_mfa_is_required(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    await _require_mfa(identity)
    user = await make_user()
    challenge = await _challenge(http, user, "mfa_enrolment_required")
    answer = await _register(http, SoftwareAuthenticator(), challenge=challenge)
    headers = {"authorization": f"Bearer {answer.json()['access_token']}"}
    credential_id = answer.json()["credential"]["id"]
    refused = await http.delete(f"/auth/webauthn/credentials/{credential_id}", headers=headers)
    assert (refused.status_code, refused.json()) == (409, LAST_FACTOR)
    assert await identity.webauthn_credentials.count(user.id) == 1
    (event,) = await audit_rows(db, "warden.identity.mfa.webauthn.removed")
    assert event["outcome"] == "failure"
    assert event["details"] == {"credential_id": credential_id, "reason": "last_factor"}

    # With TOTP as well, the key can go.
    await enrol_totp(identity, user)
    removed = await http.delete(f"/auth/webauthn/credentials/{credential_id}", headers=headers)
    assert removed.status_code == 204


async def test_the_last_factor_can_go_where_mfa_is_not_required_and_takes_the_codes(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, user)
    answer = await _register(http, SoftwareAuthenticator(), headers=headers)
    credential_id = answer.json()["credential"]["id"]
    removed = await http.delete(f"/auth/webauthn/credentials/{credential_id}", headers=headers)
    assert removed.status_code == 204
    assert await _recovery_code_count(db, user.id) == 0
    (event,) = await audit_rows(db, "warden.identity.mfa.webauthn.removed")
    assert event["details"]["recovery_codes_removed"] == 10
    assert (await _sign_in(http, user)).json()["status"] == "signed_in"


async def test_two_removals_of_the_last_two_factors_at_once_never_leave_none(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    await _require_mfa(identity)
    user = await make_user()
    challenge = await _challenge(http, user, "mfa_enrolment_required")
    answer = await _register(http, SoftwareAuthenticator(), challenge=challenge)
    headers = {"authorization": f"Bearer {answer.json()['access_token']}"}
    assert (await _register(http, SoftwareAuthenticator(), headers=headers)).status_code == 200
    ids = [c.id for c in await identity.webauthn_credentials.list(user.id)]
    for _ in range(3):
        answers = await race(
            *[
                (lambda cid=cid: http.delete(f"/auth/webauthn/credentials/{cid}", headers=headers))
                for cid in ids
            ]
        )
        assert sorted(a.status_code for a in answers) == [204, 409]
        assert await identity.webauthn_credentials.count(user.id) == 1
        assert (await _register(http, SoftwareAuthenticator(), headers=headers)).status_code == 200
        ids = [c.id for c in await identity.webauthn_credentials.list(user.id)]


# The administrator's view.


async def test_the_administrators_view_shows_how_many_keys_a_user_holds(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    admin = await make_user(roles=("admin",))
    headers = await _bearer(http, admin)
    user = await make_user()
    shown = await http.get(f"/admin/users/{user.id}", headers=headers)
    assert shown.json()["webauthn_credentials"] == 0
    key_headers = await _bearer(http, user)
    for _ in range(2):
        await _register(http, SoftwareAuthenticator(), headers=key_headers)
    shown = await http.get(f"/admin/users/{user.id}", headers=headers)
    assert shown.json()["webauthn_credentials"] == 2
    # The password status joined the view additively in wave 17.
    assert set(shown.json()) == {"user", "roles", "webauthn_credentials", "password"}


# Pruning (wave 9 decision D19).


async def test_pruning_removes_expired_ceremony_challenges_and_keeps_live_ones(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    from warden.identity.webauthn import WebAuthnPurpose

    user = await make_user()
    assert identity.webauthn is not None
    await identity.webauthn.begin_registration(user.id, WebAuthnPurpose.SECOND_FACTOR)
    await expire_challenges(db)
    await identity.webauthn.begin_registration(user.id, WebAuthnPurpose.SECOND_FACTOR)
    report = await identity.prune()
    assert report.webauthn_challenges == 1
    assert report.total >= 1
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.webauthn_challenges WHERE expires_at > now()"
        )
        live = await cur.fetchone()
        cur = await conn.execute("SELECT count(*) FROM warden.webauthn_challenges")
        every = await cur.fetchone()
    assert live is not None and every is not None
    assert (live[0], every[0]) == (1, 1)
