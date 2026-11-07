"""Passkey-only sign-in and the passkey_only sign-in method (rulings P5, P6 and P7).

Through the HTTP routes, with the software authenticator: discoverable
sign-in with user verification required, amr ``["hwk", "mfa"]``, the
uniform refusal for every failure, the throttle, and what ``passkey_only``
refuses.
"""

from __future__ import annotations

import statistics
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from identity_support import (
    FAST_HASHER,
    PASSWORD,
    MemorySecrets,
    RecordingSender,
    UserFactory,
    audit_rows,
    race,
)
from passkey_support import (
    assert_refused,
    expire_challenge_of,
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
from warden.identity import Identity, PermissionRegistry, SignInMethod, User
from warden.identity.webauthn import WebAuthnPurpose
from warden.keys import KeyStore

pytestmark = pytest.mark.db


@pytest.fixture
def config() -> WardenConfig:
    # Room for many refusals from one address; the throttle tests build their own.
    return passkey_config(sign_in_attempt_limit=1000)


@pytest.fixture
async def http(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(identity) as client:
        yield client


async def _amr(identity: Identity, answer: httpx.Response) -> tuple[str, ...]:
    principal = await identity.authenticate(answer.json()["access_token"])
    return principal.amr


async def _last_sign_in_failure(db: Database) -> dict[str, Any]:
    rows = [r for r in await audit_rows(db, "warden.identity.sign_in") if r["outcome"] == "failure"]
    assert rows, "no sign-in failure was audited"
    return rows[-1]


async def _passkey_user(
    identity: Identity, make_user: UserFactory, method: SignInMethod = SignInMethod.PASSWORD_AND_SSO
) -> tuple[User, SoftwareAuthenticator]:
    user = await make_user()
    key, _ = await give_passkey(identity, user)
    if method is not SignInMethod.PASSWORD_AND_SSO:
        await identity.users.set_sign_in_method(user.id, method, actor="test")
    return user, key


# Signing in.


async def test_a_password_and_sso_user_signs_in_with_a_passkey_alone(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user, key = await _passkey_user(identity, make_user)
    answer = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["status"] == "signed_in"
    assert set(body) == {
        "status",
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "refresh_expires_in",
    }
    assert await _amr(identity, answer) == ("hwk", "mfa")
    (credential,) = await identity.webauthn_credentials.list(user.id)
    (event,) = [
        r
        for r in await audit_rows(db, "warden.identity.sign_in")
        if r["outcome"] == "success" and r["details"].get("amr") == ["hwk", "mfa"]
    ]
    assert event["resource_id"] == str(user.id)
    assert event["details"] == {"amr": ["hwk", "mfa"], "credential_id": str(credential.id)}


async def test_a_passkey_only_user_signs_in_with_a_passkey(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    _, key = await _passkey_user(identity, make_user, SignInMethod.PASSKEY_ONLY)
    answer = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert answer.status_code == 200, answer.text
    assert await _amr(identity, answer) == ("hwk", "mfa")


async def test_passkey_sign_in_satisfies_require_mfa_with_no_second_step(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    _, key = await _passkey_user(identity, make_user)
    await identity.policy.update(actor="test", require_mfa=True)
    answer = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert answer.status_code == 200, answer.text
    assert answer.json()["status"] == "signed_in"


async def test_a_second_factor_key_that_came_out_discoverable_with_verification_signs_in(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    """P5: any password_and_sso user who has registered a passkey, however it was offered."""
    user = await make_user()
    key, credential = await give_passkey(
        identity, user, passkey_authenticator(), purpose=WebAuthnPurpose.SECOND_FACTOR
    )
    assert credential.discoverable and credential.user_verified
    answer = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert answer.status_code == 200, answer.text


async def test_a_second_factor_key_that_is_not_discoverable_cannot_sign_in_alone(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    key, credential = await give_passkey(
        identity,
        user,
        SoftwareAuthenticator(resident=False),
        purpose=WebAuthnPurpose.SECOND_FACTOR,
        report_rk=False,
    )
    assert credential.discoverable is False
    options = (await passkey_options(http)).json()["public_key"]
    assertion = key.authenticate(options, credential_id=key.only_credential().credential_id)
    assert_refused(await passkey_sign_in(http, assertion))
    assert (await _last_sign_in_failure(db))["details"]["reason"] == "not_discoverable"
    (after,) = await identity.webauthn_credentials.list(user.id)
    assert after.sign_count == credential.sign_count and after.last_used_at is None


async def test_a_key_registered_without_user_verification_cannot_sign_in_alone(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """Even when the key verifies the user this time: it was not a passkey when registered."""
    user = await make_user()
    key, credential = await give_passkey(
        identity,
        user,
        passkey_authenticator(user_verifying=False),
        purpose=WebAuthnPurpose.SECOND_FACTOR,
    )
    assert credential.discoverable is True and credential.user_verified is False
    assertion = await passkey_assertion(http, key, uv=True)
    assert_refused(await passkey_sign_in(http, assertion))
    assert (await _last_sign_in_failure(db))["details"]["reason"] == "user_verification"


# The options.


async def test_the_options_name_no_credential_and_require_user_verification(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    await _passkey_user(identity, make_user)
    answer = await passkey_options(http)
    assert answer.status_code == 200, answer.text
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert set(body) == {"public_key", "expires_at"}
    public_key = body["public_key"]
    assert "allowCredentials" not in public_key
    assert public_key["userVerification"] == "required"
    assert public_key["rpId"] == "app.example.com"


async def test_the_options_are_identical_in_shape_for_every_caller(
    identity: Identity, make_user: UserFactory
) -> None:
    user, key = await _passkey_user(identity, make_user)
    shapes = []
    challenges = set()
    for address in ("192.0.2.10", "198.51.100.7", "203.0.113.200"):
        async with http_client(identity, (address, 40000)) as http:
            signed_in = await passkey_sign_in(http, await passkey_assertion(http, key))
            bearer = {"authorization": f"Bearer {signed_in.json()['access_token']}"}
            for headers in ({}, bearer):
                body = (await passkey_options(http, **headers)).json()
                public_key = dict(body["public_key"])
                challenges.add(public_key.pop("challenge"))
                shapes.append((sorted(body), public_key))
    assert all(shape == shapes[0] for shape in shapes), shapes
    assert len(challenges) == len(shapes)  # a fresh challenge every time
    assert user.email not in str(shapes)


async def test_the_options_are_refused_uniformly_without_a_relying_party(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
) -> None:
    config = passkey_config("https://192.0.2.1")
    identity = Identity(
        config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER, mail_sender=mail
    )
    assert identity.webauthn is None
    async with http_client(identity) as http:
        assert_refused(await passkey_options(http))
        assert_refused(await passkey_sign_in(http, {"id": "x"}))


# Every refusal is the same.


async def test_every_passkey_sign_in_failure_is_byte_identical(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    async def fresh(method: SignInMethod = SignInMethod.PASSWORD_AND_SSO) -> tuple[User, Any]:
        return await _passkey_user(identity, make_user, method)

    cases: dict[str, Any] = {}

    stranger = passkey_authenticator()
    stranger.register(
        {"rp": {"id": "app.example.com"}, "user": {"id": "AAAA"}, "challenge": "AAAA"}
    )
    cases["unknown_credential"] = await passkey_assertion(http, stranger)

    _, key = await fresh()
    cases["user_handle"] = await passkey_assertion(http, key, user_handle=b"\x00" * 64)

    user, key = await fresh()
    await set_status(db, user.id, "suspended")
    cases["inactive_user"] = await passkey_assertion(http, key)

    user, key = await fresh()
    await set_status(db, user.id, "deactivated")
    cases["deactivated"] = await passkey_assertion(http, key)

    user, key = await fresh()
    await set_method(db, user.id, SignInMethod.SSO_ONLY)
    cases["sso_only"] = await passkey_assertion(http, key)

    _, key = await fresh()
    cases["user_verification"] = await passkey_assertion(http, key, uv=False)

    _, key = await fresh()
    signed = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert signed.status_code == 200
    cases["suspected_clone"] = await passkey_assertion(http, key, counter=1)

    _, key = await fresh()
    cases["signature"] = await passkey_assertion(http, key, signing_key=other_key())

    _, key = await fresh()
    used = await passkey_assertion(http, key)
    assert (await passkey_sign_in(http, used)).status_code == 200
    cases["challenge_used"] = used

    _, key = await fresh()
    stale = await passkey_assertion(http, key)
    await expire_challenge_of(db, stale)
    cases["challenge_expired"] = stale

    cases["malformed"] = "not a credential"

    for name, credential in cases.items():
        answer = await passkey_sign_in(http, credential)
        assert_refused(answer)
        failure = await _last_sign_in_failure(db)
        expected = {
            "inactive_user": "inactive_user",
            "deactivated": "inactive_user",
        }.get(name, name)
        assert failure["details"]["reason"] == expected, (name, failure)
        assert failure["details"]["method"] == "passkey", name
        assert set(failure["details"]) <= {"reason", "method", "credential_id"}, failure
    # Nothing from a response reaches the trail: no challenge, signature or handle.
    for row in await audit_rows(db):
        text = str(row["details"])
        for credential in cases.values():
            if isinstance(credential, dict):
                assert credential["response"]["signature"] not in text
                assert credential["id"] not in text


async def test_passkey_sign_in_timing_does_not_reveal_why_it_failed(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """As #133 measures password sign-in: interleaved cases, medians within a quarter."""
    stranger = passkey_authenticator()
    stranger.register(
        {"rp": {"id": "app.example.com"}, "user": {"id": "AAAA"}, "challenge": "AAAA"}
    )
    _, handle_key = await _passkey_user(identity, make_user)
    suspended, suspended_key = await _passkey_user(identity, make_user)
    await set_status(db, suspended.id, "suspended")
    _, signature_key = await _passkey_user(identity, make_user)
    cases: dict[str, tuple[SoftwareAuthenticator, dict[str, Any]]] = {
        "unknown_credential": (stranger, {}),
        "user_handle": (handle_key, {"user_handle": b"\x00" * 64}),
        "inactive_user": (suspended_key, {}),
        "signature": (signature_key, {"signing_key": other_key()}),
    }
    samples: dict[str, list[float]] = {name: [] for name in cases}
    for key, tamper in cases.values():  # warm-up
        assert_refused(await passkey_sign_in(http, await passkey_assertion(http, key, **tamper)))
    for _ in range(15):
        for name, (key, tamper) in cases.items():
            credential = await passkey_assertion(http, key, **tamper)
            start = time.perf_counter()
            answer = await passkey_sign_in(http, credential)
            samples[name].append(time.perf_counter() - start)
            assert_refused(answer)
    medians = {name: statistics.median(values) for name, values in samples.items()}
    assert min(medians.values()) / max(medians.values()) > 0.75, medians


# Single use.


async def test_the_same_assertion_sent_concurrently_gives_one_session(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user, key = await _passkey_user(identity, make_user)
    credential = await passkey_assertion(http, key)
    answers = await race(*[lambda: passkey_sign_in(http, credential) for _ in range(6)])
    statuses = sorted(a.status_code for a in answers)
    assert statuses == [200, 401, 401, 401, 401, 401], answers
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s", (user.id,)
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 1


# The throttle.


async def test_failures_from_one_address_throttle_passkey_sign_in_from_it(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    identity = Identity(
        passkey_config(),
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        mail_sender=mail,
        sign_in_attempt_limit=3,
    )
    users = []
    for _ in range(2):
        user = await identity.users.create(
            f"user-{uuid.uuid4().hex[:8]}@example.com", actor="test", password=PASSWORD
        )
        users.append((user, (await give_passkey(identity, user))[0]))
    (_, first), (_, second) = users
    async with http_client(identity, ("198.51.100.20", 1)) as http:
        for _ in range(3):
            bad = await passkey_assertion(http, first, signing_key=other_key())
            assert_refused(await passkey_sign_in(http, bad))
        # A good assertion for another user from the same address is refused now.
        assert_refused(await passkey_sign_in(http, await passkey_assertion(http, second)))
        assert (await _last_sign_in_failure(db))["details"]["reason"] == "throttled"
    async with http_client(identity, ("198.51.100.21", 1)) as http:
        answer = await passkey_sign_in(http, await passkey_assertion(http, second))
        assert answer.status_code == 200, answer.text


async def test_failures_with_one_credential_throttle_it_from_every_address(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
) -> None:
    identity = Identity(
        passkey_config(),
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        mail_sender=mail,
        sign_in_attempt_limit=3,
    )
    user = await identity.users.create("held@example.com", actor="test", password=PASSWORD)
    key, _ = await give_passkey(identity, user)
    for octet in range(3):
        async with http_client(identity, (f"203.0.113.{octet + 1}", 1)) as http:
            bad = await passkey_assertion(http, key, signing_key=other_key())
            assert_refused(await passkey_sign_in(http, bad))
    async with http_client(identity, ("203.0.113.99", 1)) as http:
        assert_refused(await passkey_sign_in(http, await passkey_assertion(http, key)))
        assert (await _last_sign_in_failure(db))["details"]["reason"] == "throttled"


async def test_a_passkey_sign_in_clears_the_count_for_its_address_and_credential(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
) -> None:
    identity = Identity(
        passkey_config(),
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        mail_sender=mail,
        sign_in_attempt_limit=3,
    )
    user = await identity.users.create("clear@example.com", actor="test", password=PASSWORD)
    key, _ = await give_passkey(identity, user)
    async with http_client(identity) as http:
        for _ in range(2):
            bad = await passkey_assertion(http, key, signing_key=other_key())
            assert_refused(await passkey_sign_in(http, bad))
        assert (await passkey_sign_in(http, await passkey_assertion(http, key))).status_code == 200
        for _ in range(2):
            bad = await passkey_assertion(http, key, signing_key=other_key())
            assert_refused(await passkey_sign_in(http, bad))
        assert (await passkey_sign_in(http, await passkey_assertion(http, key))).status_code == 200


# passkey_only refuses the password paths (P5).


async def test_password_sign_in_for_a_passkey_only_user_is_byte_identical_to_a_wrong_password(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    passkey_only, _ = await _passkey_user(identity, make_user, SignInMethod.PASSKEY_ONLY)
    other = await make_user()
    wrong = await http.post(
        "/auth/sign-in", json={"email": other.email, "password": "wrong " + PASSWORD}
    )
    refused = await http.post(
        "/auth/sign-in", json={"email": passkey_only.email, "password": PASSWORD}
    )
    assert_refused(wrong)
    assert_refused(refused)
    assert refused.content == wrong.content
    assert dict(refused.headers) == dict(wrong.headers)
    assert (await _last_sign_in_failure(db))["details"]["reason"] == "passkey_only"


async def test_a_passkey_only_user_cannot_reset_or_change_a_password(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    admin = await make_user(roles=("admin",))
    user, key = await _passkey_user(identity, make_user, SignInMethod.PASSKEY_ONLY)
    # The public request: answered as always, nothing sent, the reason audited.
    answer = await http.post("/auth/password-reset", json={"email": user.email})
    assert answer.status_code == 202
    assert mail.sent == []
    (requested,) = await audit_rows(db, "warden.identity.password.reset_requested")
    assert requested["details"]["reason"] == "passkey_only"
    # The administrator's: a 409.
    signed_in = await http.post("/auth/sign-in", json={"email": admin.email, "password": PASSWORD})
    admin_bearer = {"authorization": f"Bearer {signed_in.json()['access_token']}"}
    sent = await http.post(f"/admin/users/{user.id}/password-reset", headers=admin_bearer)
    assert sent.status_code == 409
    assert mail.sent == []
    # A change of password, signed in with the passkey.
    session = await passkey_sign_in(http, await passkey_assertion(http, key))
    bearer = {"authorization": f"Bearer {session.json()['access_token']}"}
    changed = await http.post(
        "/auth/password",
        json={"current_password": PASSWORD, "new_password": "another long passphrase"},
        headers=bearer,
    )
    assert changed.status_code == 400
    assert changed.json() == {"detail": "password change refused"}


async def test_a_reset_link_issued_before_the_switch_is_refused_and_spent(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    assert await identity.resets.request(user.email) is None
    token = mail.token()
    await identity.users.set_sign_in_method(user.id, SignInMethod.PASSKEY_ONLY, actor="test")
    answer = await http.post(
        "/auth/password-reset/complete",
        json={"token": token, "new_password": "another long passphrase"},
    )
    assert_refused(answer)
    rows = await audit_rows(db, "warden.identity.password.reset")
    assert rows[-1]["details"]["reason"] == "passkey_only"


# The administrator's sign-in-method route (P5, Skuld question 25).


async def _admin(http: httpx.AsyncClient, make_user: UserFactory) -> dict[str, str]:
    admin = await make_user(roles=("admin",))
    signed_in = await http.post("/auth/sign-in", json={"email": admin.email, "password": PASSWORD})
    return {"authorization": f"Bearer {signed_in.json()['access_token']}"}


async def test_an_administrator_switches_a_user_to_passkey_only_and_is_told_of_no_passkey(
    http: httpx.AsyncClient, make_user: UserFactory
) -> None:
    bearer = await _admin(http, make_user)
    user = await make_user()
    answer = await http.post(
        f"/admin/users/{user.id}/sign-in-method",
        json={"sign_in_method": "passkey_only"},
        headers=bearer,
    )
    assert answer.status_code == 200, answer.text
    assert answer.json()["user"]["sign_in_method"] == "passkey_only"
    assert answer.json()["has_passkey"] is False


async def test_switching_to_passkey_only_reports_a_passkey_the_user_holds(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    bearer = await _admin(http, make_user)
    user, _ = await _passkey_user(identity, make_user)
    answer = await http.post(
        f"/admin/users/{user.id}/sign-in-method",
        json={"sign_in_method": "passkey_only"},
        headers=bearer,
    )
    assert answer.json()["has_passkey"] is True


async def test_a_second_factor_key_is_not_a_passkey_for_has_passkey(
    http: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    bearer = await _admin(http, make_user)
    user = await make_user()
    await give_passkey(
        identity,
        user,
        SoftwareAuthenticator(resident=False),
        purpose=WebAuthnPurpose.SECOND_FACTOR,
        report_rk=False,
    )
    answer = await http.post(
        f"/admin/users/{user.id}/sign-in-method",
        json={"sign_in_method": "passkey_only"},
        headers=bearer,
    )
    assert answer.json()["has_passkey"] is False


async def test_other_switches_answer_as_before(
    http: httpx.AsyncClient, make_user: UserFactory
) -> None:
    bearer = await _admin(http, make_user)
    user = await make_user()
    answer = await http.post(
        f"/admin/users/{user.id}/sign-in-method",
        json={"sign_in_method": "sso_only"},
        headers=bearer,
    )
    assert answer.status_code == 200
    assert set(answer.json()) == {"user"}


async def test_switching_a_user_holding_keys_to_sso_only_is_refused_until_reset(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    bearer = await _admin(http, make_user)
    user, _ = await _passkey_user(identity, make_user)
    path = f"/admin/users/{user.id}/sign-in-method"
    answer = await http.post(path, json={"sign_in_method": "sso_only"}, headers=bearer)
    assert answer.status_code == 409
    assert answer.json() == {
        "detail": "the user holds security keys or passkeys; reset their second factors first"
    }
    assert (await identity.users.get(user.id)).sign_in_method is SignInMethod.PASSWORD_AND_SSO  # type: ignore[union-attr]
    rows = await audit_rows(db, "warden.identity.user.sign_in_method_changed")
    assert rows[-1]["outcome"] == "failure"
    assert rows[-1]["details"] == {
        "from": "password_and_sso",
        "to": "sso_only",
        "reason": "webauthn_credentials",
    }
    assert (await http.delete(f"/admin/users/{user.id}/mfa", headers=bearer)).status_code == 204
    answer = await http.post(path, json={"sign_in_method": "sso_only"}, headers=bearer)
    assert answer.status_code == 200


async def test_a_key_registered_while_switching_to_sso_only_never_leaves_both(
    identity: Identity, make_user: UserFactory
) -> None:
    """The switch and a registration race: either the key or sso_only, never both."""
    assert identity.webauthn is not None
    for _ in range(4):
        user = await make_user()
        key = passkey_authenticator()
        options = await identity.webauthn.begin_registration(user.id, WebAuthnPurpose.PASSKEY)
        response = key.register(options.public_key)
        webauthn = identity.webauthn

        async def register(
            user: User = user, response: Any = response, webauthn: Any = webauthn
        ) -> Any:
            return await webauthn.finish_registration(user.id, response)

        async def switch(user: User = user) -> Any:
            return await identity.users.set_sign_in_method(
                user.id, SignInMethod.SSO_ONLY, actor="test"
            )

        await race(register, switch)
        final = await identity.users.get(user.id)
        assert final is not None
        keys = await identity.webauthn_credentials.list(user.id)
        assert not (final.sign_in_method is SignInMethod.SSO_ONLY and keys), (final, keys)


async def test_a_counterless_passkey_replayed_concurrently_gives_one_session(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """Synced passkeys keep no counter, so only the challenge's single use stops a replay."""
    user = await make_user()
    key, _ = await give_passkey(identity, user, passkey_authenticator(counter_step=0))
    credential = await passkey_assertion(http, key)
    answers = await race(*[lambda: passkey_sign_in(http, credential) for _ in range(6)])
    assert sorted(a.status_code for a in answers) == [200, 401, 401, 401, 401, 401], answers
    reasons = {
        r["details"]["reason"]
        for r in await audit_rows(db, "warden.identity.sign_in")
        if r["outcome"] == "failure"
    }
    assert reasons == {"challenge_used"}


async def test_a_user_suspended_during_the_ceremony_gets_no_session(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status is checked again in the transaction that issues the session."""
    user, key = await _passkey_user(identity, make_user)
    webauthn = identity.webauthn
    assert webauthn is not None
    finish = webauthn.finish_authentication

    async def finish_then_suspend(*args: Any, **kwargs: Any) -> Any:
        assertion = await finish(*args, **kwargs)
        await set_status(db, user.id, "suspended")
        return assertion

    monkeypatch.setattr(webauthn, "finish_authentication", finish_then_suspend)
    assert_refused(await passkey_sign_in(http, await passkey_assertion(http, key)))
    assert (await _last_sign_in_failure(db))["details"]["reason"] == "inactive_user"
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s", (user.id,)
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 0


async def test_a_user_moved_to_sso_only_during_the_ceremony_gets_no_session(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user, key = await _passkey_user(identity, make_user)
    webauthn = identity.webauthn
    assert webauthn is not None
    finish = webauthn.finish_authentication

    async def finish_then_switch(*args: Any, **kwargs: Any) -> Any:
        assertion = await finish(*args, **kwargs)
        await set_method(db, user.id, SignInMethod.SSO_ONLY)
        return assertion

    monkeypatch.setattr(webauthn, "finish_authentication", finish_then_switch)
    assert_refused(await passkey_sign_in(http, await passkey_assertion(http, key)))
    assert (await _last_sign_in_failure(db))["details"]["reason"] == "sso_only"
