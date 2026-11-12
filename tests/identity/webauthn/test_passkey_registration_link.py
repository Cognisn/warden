"""The administrator's passkey registration link (ruling P8).

An administrator mails a single-use, expiring link; the user registers a
passkey with it, without signing in. Paired with the administrator's reset
of second factors: reset, then link.
"""

from __future__ import annotations

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
    give_passkey,
    http_client,
    passkey_assertion,
    passkey_authenticator,
    passkey_config,
    passkey_sign_in,
    set_method,
    set_status,
)
from soft_authenticator import SoftwareAuthenticator

from warden.config import MailConfig, WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry, SignInMethod, User
from warden.identity.mail import Mailer, MailKind
from warden.keys import KeyStore

pytestmark = pytest.mark.db

LINK_SENT = "warden.identity.passkey.link_sent"
REGISTERED = "warden.identity.passkey.registered"


@pytest.fixture
def config() -> WardenConfig:
    return passkey_config(sign_in_attempt_limit=1000)


@pytest.fixture
async def http(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(identity) as client:
        yield client


@pytest.fixture
async def admin(http: httpx.AsyncClient, make_user: UserFactory) -> dict[str, str]:
    user = await make_user(roles=("admin",))
    answer = await http.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    return {"authorization": f"Bearer {answer.json()['access_token']}"}


async def _send(http: httpx.AsyncClient, admin: dict[str, str], user: User | str) -> httpx.Response:
    user_id = user if isinstance(user, str) else user.id
    return await http.post(f"/admin/users/{user_id}/passkey-registration", headers=admin)


async def _link(
    http: httpx.AsyncClient, admin: dict[str, str], mail: RecordingSender, user: User
) -> str:
    answer = await _send(http, admin, user)
    assert answer.status_code == 202, answer.text
    return mail.token()


async def _options(http: httpx.AsyncClient, token: str) -> httpx.Response:
    return await http.post("/auth/passkey-registration/options", json={"token": token})


async def _register(
    http: httpx.AsyncClient,
    token: str,
    key: SoftwareAuthenticator | None = None,
    *,
    nickname: str | None = None,
    **tamper: Any,
) -> httpx.Response:
    options = await _options(http, token)
    assert options.status_code == 200, options.text
    response = (key or passkey_authenticator()).register(options.json()["public_key"], **tamper)
    body: dict[str, Any] = {"token": token, "credential": response}
    if nickname is not None:
        body["nickname"] = nickname
    return await http.post("/auth/passkey-registration", json=body)


async def _credential_count(db: Database, user: User) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.webauthn_credentials WHERE user_id = %s", (user.id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


# Sending the link.


async def test_an_administrator_mails_a_single_use_registration_link(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user(display_name="Pat Example")
    answer = await _send(http, admin, user)
    assert answer.status_code == 202, answer.text
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert set(body) == {"status", "expires_at"} and body["status"] == "sent"
    (message,) = mail.sent
    assert message.kind is MailKind.PASSKEY_REGISTRATION
    assert message.to == user.email
    assert "https://app.example.com/passkey?t=" in message.text
    assert "Pat Example" in message.text
    token = mail.token()
    (event,) = await audit_rows(db, LINK_SENT)
    assert event["outcome"] == "success"
    assert event["resource_id"] == str(user.id)
    assert set(event["details"]) == {"expires_at", "previous_links_revoked"}
    assert token not in str(await audit_rows(db))
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT purpose, created_by FROM warden.single_use_tokens WHERE user_id = %s",
            (user.id,),
        )
        rows = await cur.fetchall()
    assert [row[0] for row in rows] == ["passkey_registration"]


async def test_sending_again_replaces_the_live_link(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    first = await _link(http, admin, mail, user)
    second = await _link(http, admin, mail, user)
    assert first != second
    assert_refused(await _options(http, first))
    assert (await _options(http, second)).status_code == 200
    events = await audit_rows(db, LINK_SENT)
    assert events[-1]["details"]["previous_links_revoked"] == 1


@pytest.mark.parametrize(
    ("method", "status"),
    [
        (SignInMethod.SSO_ONLY, "active"),
        (SignInMethod.PASSWORD_AND_SSO, "suspended"),
        (SignInMethod.PASSKEY_ONLY, "deactivated"),
    ],
)
async def test_no_link_for_an_sso_only_or_inactive_user(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
    method: SignInMethod,
    status: str,
) -> None:
    user = await make_user()
    await set_method(db, user.id, method)
    await set_status(db, user.id, status)
    answer = await _send(http, admin, user)
    assert answer.status_code == 409
    assert answer.json() == {"detail": "a passkey registration link cannot be sent to this user"}
    assert mail.sent == []
    (event,) = await audit_rows(db, LINK_SENT)
    assert event["outcome"] == "failure"
    expected = "sso_only" if status == "active" else f"user_{status}"
    assert event["details"] == {"reason": expected}


async def test_an_unknown_user_is_a_404(
    http: httpx.AsyncClient, admin: dict[str, str], mail: RecordingSender
) -> None:
    answer = await _send(http, admin, "6f0c8b55-0000-4000-8000-000000000000")
    assert answer.status_code == 404
    assert (await _send(http, admin, "not-a-uuid")).status_code == 404
    assert mail.sent == []


async def test_a_failed_delivery_leaves_no_link(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    mail.fail = True
    answer = await _send(http, admin, user)
    assert answer.status_code == 502
    assert answer.json() == {"detail": "the message could not be delivered"}
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.single_use_tokens WHERE user_id = %s", (user.id,)
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 0
    events = await audit_rows(db, LINK_SENT)
    assert events[-1]["outcome"] == "failure"
    assert events[-1]["details"] == {"reason": "delivery_failed"}


async def _identity(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender | None,
) -> Identity:
    return Identity(
        config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER, mail_sender=mail
    )


async def test_without_a_link_template_mail_or_relying_party_nothing_is_sent(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
) -> None:
    without_link = parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "identity": {"require_mfa": False},
        }
    )
    cases = [
        (without_link, mail, 503, "the passkey registration link is not configured"),
        (passkey_config(), None, 503, "mail is not configured"),
        (passkey_config("https://192.0.2.1"), mail, 409, "WebAuthn is not configured"),
    ]
    for config, sender, status, message in cases:
        identity = await _identity(config, db, keys, permissions, secrets, sender)
        admin = await identity.users.create(
            f"admin-{status}-{len(message)}@example.com", actor="t", password=PASSWORD
        )
        await identity.roles.assign(admin.id, "admin", actor="t")
        user = await identity.users.create(
            f"user-{status}-{len(message)}@example.com", actor="t", password=PASSWORD
        )
        async with http_client(identity) as http:
            signed_in = await http.post(
                "/auth/sign-in", json={"email": admin.email, "password": PASSWORD}
            )
            bearer = {"authorization": f"Bearer {signed_in.json()['access_token']}"}
            answer = await _send(http, bearer, user)
        assert answer.status_code == status, (message, answer.text)
        assert answer.json() == {"detail": message}
    assert mail.sent == []


async def test_a_product_can_override_the_registration_message() -> None:
    mailer = Mailer(MailConfig(template_package="passkey_mail_overrides"), None)
    message = mailer.render(
        MailKind.PASSKEY_REGISTRATION,
        email="pat@example.com",
        display_name=None,
        link="https://app.example.com/passkey?t=abc",
        expires_at=None,
    )
    assert message.subject == "Set up your Example passkey"
    assert message.text.startswith("Hello pat@example.com. Register a passkey for pat@example.com")


# Registering with the link.


async def test_the_options_ask_for_a_passkey(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    answer = await _options(http, await _link(http, admin, mail, user))
    assert answer.status_code == 200, answer.text
    public_key = answer.json()["public_key"]
    assert public_key["authenticatorSelection"]["residentKey"] == "required"
    assert public_key["authenticatorSelection"]["userVerification"] == "required"
    assert public_key["user"]["name"] == user.email


async def test_a_passkey_only_user_registers_a_passkey_and_then_signs_in_with_it(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user(password=None)
    await identity.users.set_sign_in_method(user.id, SignInMethod.PASSKEY_ONLY, actor="test")
    key = passkey_authenticator()
    answer = await _register(http, await _link(http, admin, mail, user), key, nickname="Laptop")
    assert answer.status_code == 200, answer.text
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert set(body) == {"status", "credential", "recovery_codes"}
    assert body["status"] == "registered"
    assert body["credential"]["nickname"] == "Laptop"
    assert body["credential"]["discoverable"] is True
    assert len(body["recovery_codes"]) == 10
    assert "access_token" not in answer.text  # it does not sign in
    (credential,) = await identity.webauthn_credentials.list(user.id)
    assert credential.user_verified and credential.discoverable
    (event,) = [r for r in await audit_rows(db, REGISTERED) if r["outcome"] == "success"]
    assert event["resource_id"] == str(user.id)
    assert event["details"] == {"credential_id": str(credential.id), "first_factor": True}
    signed_in = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert signed_in.status_code == 200, signed_in.text


async def test_reset_then_link_replaces_a_lost_passkey(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    lost, _ = await give_passkey(identity, user)
    await identity.users.set_sign_in_method(user.id, SignInMethod.PASSKEY_ONLY, actor="test")
    assert (await http.delete(f"/admin/users/{user.id}/mfa", headers=admin)).status_code == 204
    assert_refused(await passkey_sign_in(http, await passkey_assertion(http, lost)))
    replacement = passkey_authenticator()
    answer = await _register(http, await _link(http, admin, mail, user), replacement)
    assert answer.status_code == 200, answer.text
    signed_in = await passkey_sign_in(http, await passkey_assertion(http, replacement))
    assert signed_in.status_code == 200


async def test_a_user_holding_codes_gets_none_with_a_linked_passkey(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    async with db.transaction() as tx:
        await identity.mfa.lock_user(tx, user.id)
        assert await identity.mfa.issue_codes_if_none(tx, user.id)
    answer = await _register(http, await _link(http, admin, mail, user))
    assert answer.status_code == 200
    assert answer.json()["recovery_codes"] == []


async def test_a_used_link_is_refused(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    token = await _link(http, admin, mail, user)
    options = (await _options(http, token)).json()["public_key"]
    assert (await _register(http, token)).status_code == 200
    assert_refused(await _options(http, token))
    late = passkey_authenticator().register(options)
    assert_refused(
        await http.post("/auth/passkey-registration", json={"token": token, "credential": late})
    )
    assert await _credential_count(db, user) == 1


async def test_an_expired_link_is_refused(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    token = await _link(http, admin, mail, user)
    options = (await _options(http, token)).json()["public_key"]
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.single_use_tokens SET created_at = now() - interval '2 days',"
            " expires_at = now() - interval '1 day' WHERE user_id = %s",
            (user.id,),
        )
    assert_refused(await _options(http, token))
    response = passkey_authenticator().register(options)
    assert_refused(
        await http.post("/auth/passkey-registration", json={"token": token, "credential": response})
    )
    assert await _credential_count(db, user) == 0
    reasons = [r["details"]["reason"] for r in await audit_rows(db, REGISTERED)]
    assert reasons[-2:] == ["token_not_live", "token_not_live"]


@pytest.mark.parametrize("token", ["", "short", "A" * 43 + "\n", 42, None])
async def test_a_malformed_token_is_refused(http: httpx.AsyncClient, token: object) -> None:
    assert_refused(await http.post("/auth/passkey-registration/options", json={"token": token}))
    assert_refused(
        await http.post("/auth/passkey-registration", json={"token": token, "credential": {}})
    )


async def test_a_link_whose_user_became_inactive_is_refused_and_spent(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    token = await _link(http, admin, mail, user)
    options = (await _options(http, token)).json()["public_key"]
    await set_status(db, user.id, "suspended")
    response = passkey_authenticator().register(options)
    assert_refused(
        await http.post("/auth/passkey-registration", json={"token": token, "credential": response})
    )
    await set_status(db, user.id, "active")
    assert_refused(await _options(http, token))  # spent by the refusal
    assert await _credential_count(db, user) == 0
    reasons = [r["details"]["reason"] for r in await audit_rows(db, REGISTERED)]
    assert "user_suspended" in reasons


async def test_a_link_whose_user_became_sso_only_is_refused(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    token = await _link(http, admin, mail, user)
    await set_method(db, user.id, SignInMethod.SSO_ONLY)
    assert_refused(await _options(http, token))
    assert await _credential_count(db, user) == 0


async def test_an_answer_that_is_not_a_passkey_is_a_400_and_the_link_still_works(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    token = await _link(http, admin, mail, user)
    answer = await _register(http, token, SoftwareAuthenticator(), resident=False, report_rk=False)
    assert answer.status_code == 400
    assert answer.json() == {"detail": "credential not accepted"}
    answer = await _register(http, token, passkey_authenticator(user_verifying=False))
    assert answer.status_code == 400
    assert await _credential_count(db, user) == 0
    assert (await _register(http, token)).status_code == 200
    rows = await audit_rows(db, REGISTERED)
    assert [r["details"].get("reason") for r in rows] == [
        "not_discoverable",
        "user_verification",
        None,
    ]


async def test_a_bad_nickname_is_a_400(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    make_user: UserFactory,
) -> None:
    user = await make_user()
    token = await _link(http, admin, mail, user)
    answer = await _register(http, token, nickname="bad\nname")
    assert answer.status_code == 400
    assert answer.json() == {"detail": "the nickname is not valid"}


async def test_the_same_link_used_twice_at_once_registers_one_credential(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
    make_user: UserFactory,
) -> None:
    for _ in range(3):
        user = await make_user()
        token = await _link(http, admin, mail, user)
        responses = []
        for _ in range(2):
            options = (await _options(http, token)).json()["public_key"]
            responses.append(passkey_authenticator().register(options))
        answers = await race(
            *[
                lambda r=r, token=token: http.post(
                    "/auth/passkey-registration", json={"token": token, "credential": r}
                )
                for r in responses
            ]
        )
        assert sorted(a.status_code for a in answers) == [200, 401], answers
        assert await _credential_count(db, user) == 1
