"""Invitations accepted by registering a passkey (ruling P9, wave 9 question 20).

An administrator invites with ``passkey_only``; the invitee registers a
passkey, which activates them with their staged roles and uses the
invitation up in one transaction. Every other way of accepting such an
invitation is the method mismatch, and the WebAuthn ceremony admits an
invited user only through its explicit invitation keyword.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows, race
from passkey_support import (
    assert_refused,
    http_client,
    passkey_assertion,
    passkey_authenticator,
    passkey_config,
    passkey_sign_in,
    set_status,
)
from soft_authenticator import SoftwareAuthenticator
from webauthn_support import refusal

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import (
    Identity,
    InvitationMismatch,
    SignInMethod,
    StagedGrant,
    UserStatus,
    VerifiedIdentity,
)
from warden.identity.webauthn import WebAuthnPurpose, WebAuthnRefusal

pytestmark = pytest.mark.db

ACCEPTED = "warden.identity.invitation.accepted"
USE_A_PASSKEY = {"detail": "use a passkey to accept this invitation"}
USE_A_PASSWORD = {"detail": "accept this invitation with a password"}
USE_SSO = {"detail": "use single sign-on to accept this invitation"}


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


async def _invite(
    http: httpx.AsyncClient,
    admin: dict[str, str],
    mail: RecordingSender,
    email: str,
    method: str = "passkey_only",
) -> str:
    answer = await http.post(
        "/admin/invitations",
        json={"email": email, "sign_in_method": method, "roles": [{"role": "analyst"}]},
        headers=admin,
    )
    assert answer.status_code == 201, answer.text
    return mail.token()


async def _options(http: httpx.AsyncClient, token: str) -> httpx.Response:
    return await http.post("/auth/invitations/accept/passkey/options", json={"token": token})


async def _accept(
    http: httpx.AsyncClient,
    token: str,
    key: SoftwareAuthenticator | None = None,
    **tamper: Any,
) -> httpx.Response:
    options = await _options(http, token)
    assert options.status_code == 200, options.text
    response = (key or passkey_authenticator()).register(options.json()["public_key"], **tamper)
    return await http.post(
        "/auth/invitations/accept/passkey", json={"token": token, "credential": response}
    )


async def _status(identity: Identity, email: str) -> UserStatus:
    user = await identity.users.get_by_email(email)
    assert user is not None
    return user.status


async def test_an_administrator_invites_with_passkey_only(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
) -> None:
    await _invite(http, admin, mail, "pia@example.com")
    user = await identity.users.get_by_email("pia@example.com")
    assert user is not None
    assert user.sign_in_method is SignInMethod.PASSKEY_ONLY
    assert user.status is UserStatus.INVITED


async def test_the_invitee_registers_a_passkey_is_activated_and_signs_in_with_it(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
) -> None:
    token = await _invite(http, admin, mail, "pia@example.com")
    options = await _options(http, token)
    assert options.status_code == 200, options.text
    public_key = options.json()["public_key"]
    assert public_key["authenticatorSelection"]["residentKey"] == "required"
    assert public_key["authenticatorSelection"]["userVerification"] == "required"
    assert public_key["user"]["name"] == "pia@example.com"
    key = passkey_authenticator()
    answer = await http.post(
        "/auth/invitations/accept/passkey",
        json={"token": token, "credential": key.register(public_key), "nickname": "Phone"},
    )
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert set(body) == {"status", "email", "credential", "recovery_codes"}
    assert body["status"] == "accepted" and body["email"] == "pia@example.com"
    assert body["credential"]["nickname"] == "Phone"
    assert len(body["recovery_codes"]) == 10
    assert "access_token" not in answer.text  # accepting does not sign in
    user = await identity.users.get_by_email("pia@example.com")
    assert user is not None and user.status is UserStatus.ACTIVE
    assert await identity.roles.roles_of(user.id) == ["analyst"]
    (credential,) = await identity.webauthn_credentials.list(user.id)
    (event,) = [r for r in await audit_rows(db, ACCEPTED) if r["outcome"] == "success"]
    assert event["details"] == {
        "method": "passkey",
        "roles": ["analyst"],
        "credential_id": str(credential.id),
    }
    # Used up, and the passkey signs in.
    assert_refused(await _options(http, token))
    signed_in = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert signed_in.status_code == 200, signed_in.text


async def test_a_passkey_only_invitation_cannot_be_accepted_with_a_password(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
) -> None:
    token = await _invite(http, admin, mail, "pia@example.com")
    answer = await http.post(
        "/auth/invitations/accept", json={"token": token, "password": "a long enough password"}
    )
    assert answer.status_code == 409
    assert answer.json() == USE_A_PASSKEY
    assert await _status(identity, "pia@example.com") is UserStatus.INVITED
    rows = await audit_rows(db, ACCEPTED)
    assert rows[-1]["details"] == {"reason": "method_mismatch", "method": "password"}
    assert (await _accept(http, token)).status_code == 200  # still usable


async def test_a_passkey_only_invitation_cannot_be_accepted_through_single_sign_on(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
) -> None:
    token = await _invite(http, admin, mail, "pia@example.com")

    async def pin(*_: Any) -> None:
        raise AssertionError("nothing may be pinned")

    with pytest.raises(InvitationMismatch):
        await identity.invitations.accept_with_sso(
            token,
            VerifiedIdentity("https://idp.example.com", "subject-1", "pia@example.com"),
            pin=pin,
        )
    assert await _status(identity, "pia@example.com") is UserStatus.INVITED
    assert (await _accept(http, token)).status_code == 200


@pytest.mark.parametrize(
    ("method", "expected"),
    [("password_and_sso", USE_A_PASSWORD), ("sso_only", USE_SSO)],
)
async def test_another_invitation_cannot_be_accepted_with_a_passkey(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    method: str,
    expected: dict[str, str],
) -> None:
    token = await _invite(http, admin, mail, "sam@example.com", method)
    answer = await _options(http, token)
    assert answer.status_code == 409
    assert answer.json() == expected
    # Nor by sending an answer without options from this route.
    response = passkey_authenticator().register(
        {"rp": {"id": "app.example.com"}, "user": {"id": "AAAA"}, "challenge": "AAAA"}
    )
    answer = await http.post(
        "/auth/invitations/accept/passkey", json={"token": token, "credential": response}
    )
    assert answer.status_code == 409
    assert answer.json() == expected
    assert await _status(identity, "sam@example.com") is UserStatus.INVITED


async def test_a_used_or_expired_invitation_is_refused(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
) -> None:
    used = await _invite(http, admin, mail, "used@example.com")
    options = (await _options(http, used)).json()["public_key"]
    assert (await _accept(http, used)).status_code == 200
    late = passkey_authenticator().register(options)
    assert_refused(
        await http.post(
            "/auth/invitations/accept/passkey", json={"token": used, "credential": late}
        )
    )
    expired = await _invite(http, admin, mail, "expired@example.com")
    options = (await _options(http, expired)).json()["public_key"]
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.single_use_tokens SET created_at = now() - interval '30 days',"
            " expires_at = now() - interval '1 day'"
            " WHERE user_id = (SELECT id FROM warden.users WHERE email = %s)",
            ("expired@example.com",),
        )
    assert_refused(await _options(http, expired))
    response = passkey_authenticator().register(options)
    assert_refused(
        await http.post(
            "/auth/invitations/accept/passkey", json={"token": expired, "credential": response}
        )
    )
    assert await _status(identity, "expired@example.com") is UserStatus.INVITED


async def test_an_answer_that_is_not_a_passkey_is_a_400_and_the_invitation_stays(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
) -> None:
    token = await _invite(http, admin, mail, "pia@example.com")
    answer = await _accept(http, token, SoftwareAuthenticator(), resident=False, report_rk=False)
    assert answer.status_code == 400
    assert answer.json() == {"detail": "credential not accepted"}
    assert await _status(identity, "pia@example.com") is UserStatus.INVITED
    user = await identity.users.get_by_email("pia@example.com")
    assert user is not None and await identity.webauthn_credentials.list(user.id) == []
    rows = await audit_rows(db, ACCEPTED)
    assert rows[-1]["details"] == {"reason": "not_discoverable", "method": "passkey"}
    assert (await _accept(http, token)).status_code == 200


async def test_an_invitee_whose_status_changed_uses_the_invitation_up(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
) -> None:
    token = await _invite(http, admin, mail, "pia@example.com")
    options = (await _options(http, token)).json()["public_key"]
    user = await identity.users.get_by_email("pia@example.com")
    assert user is not None
    await set_status(db, user.id, "suspended")
    response = passkey_authenticator().register(options)
    assert_refused(
        await http.post(
            "/auth/invitations/accept/passkey", json={"token": token, "credential": response}
        )
    )
    assert await identity.webauthn_credentials.list(user.id) == []
    rows = await audit_rows(db, ACCEPTED)
    assert rows[-1]["details"] == {"reason": "user_suspended", "method": "passkey"}


async def test_a_passkey_only_invitation_needs_a_relying_party(
    http: httpx.AsyncClient, identity: Identity, admin: dict[str, str], mail: RecordingSender
) -> None:
    identity.webauthn = None
    answer = await http.post(
        "/admin/invitations",
        json={"email": "pia@example.com", "sign_in_method": "passkey_only"},
        headers=admin,
    )
    assert answer.status_code == 409
    assert answer.json() == {"detail": "WebAuthn is not configured"}
    assert mail.sent == []


# Concurrency.


async def test_one_invitation_accepted_by_password_and_by_passkey_at_once_activates_once(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
    db: Database,
) -> None:
    for n in range(3):
        email = f"race-{n}@example.com"
        token = await _invite(http, admin, mail, email)
        options = (await _options(http, token)).json()["public_key"]
        response = passkey_authenticator().register(options)
        answers = await race(
            lambda token=token: http.post(
                "/auth/invitations/accept",
                json={"token": token, "password": "a long enough password"},
            ),
            lambda token=token, response=response: http.post(
                "/auth/invitations/accept/passkey",
                json={"token": token, "credential": response},
            ),
        )
        # The password is the wrong way (409) or, once the passkey won, too late (401).
        statuses = sorted(a.status_code for a in answers)
        assert statuses in ([200, 401], [200, 409]), answers
        user = await identity.users.get_by_email(email)
        assert user is not None and user.status is UserStatus.ACTIVE
        accepted = [
            r
            for r in await audit_rows(db, ACCEPTED)
            if r["outcome"] == "success" and r["resource_id"] == str(user.id)
        ]
        assert len(accepted) == 1 and accepted[0]["details"]["method"] == "passkey"
        assert len(await identity.webauthn_credentials.list(user.id)) == 1


async def test_one_invitation_accepted_by_two_passkeys_at_once_registers_one(
    http: httpx.AsyncClient,
    identity: Identity,
    admin: dict[str, str],
    mail: RecordingSender,
) -> None:
    for n in range(3):
        email = f"twice-{n}@example.com"
        token = await _invite(http, admin, mail, email)
        responses = []
        for _ in range(2):
            options = (await _options(http, token)).json()["public_key"]
            responses.append(passkey_authenticator().register(options))
        answers = await race(
            *[
                lambda r=r, token=token: http.post(
                    "/auth/invitations/accept/passkey", json={"token": token, "credential": r}
                )
                for r in responses
            ]
        )
        assert sorted(a.status_code for a in answers) == [200, 401], answers
        user = await identity.users.get_by_email(email)
        assert user is not None
        assert len(await identity.webauthn_credentials.list(user.id)) == 1


# The ceremony's invitation keyword (wave 9 question 20).


async def test_only_the_invitation_keyword_admits_an_invited_user(
    identity: Identity, admin: dict[str, str], http: httpx.AsyncClient, mail: RecordingSender
) -> None:
    webauthn = identity.webauthn
    assert webauthn is not None
    await _invite(http, admin, mail, "pia@example.com")
    invited = await identity.users.get_by_email("pia@example.com")
    assert invited is not None
    for purpose in WebAuthnPurpose:
        with pytest.raises(Exception) as caught:
            await webauthn.begin_registration(invited.id, purpose)
        assert refusal(caught.value) is WebAuthnRefusal.INACTIVE_USER
    options = await webauthn.begin_registration(
        invited.id, WebAuthnPurpose.PASSKEY, for_invitation=True
    )
    response = passkey_authenticator().register(options.public_key)
    with pytest.raises(Exception) as caught:
        await webauthn.finish_registration(invited.id, response)
    assert refusal(caught.value) is WebAuthnRefusal.INACTIVE_USER


async def test_the_invitation_keyword_refuses_an_active_user(
    identity: Identity, make_user: UserFactory
) -> None:
    webauthn = identity.webauthn
    assert webauthn is not None
    user = await make_user()
    with pytest.raises(Exception) as caught:
        await webauthn.begin_registration(user.id, WebAuthnPurpose.PASSKEY, for_invitation=True)
    assert refusal(caught.value) is WebAuthnRefusal.INACTIVE_USER
    options = await webauthn.begin_registration(user.id, WebAuthnPurpose.PASSKEY)
    response = passkey_authenticator().register(options.public_key)
    with pytest.raises(Exception) as caught:
        await webauthn.finish_registration(user.id, response, for_invitation=True)
    assert refusal(caught.value) is WebAuthnRefusal.INACTIVE_USER


async def test_staged_grants_with_expiry_are_applied_on_passkey_acceptance(
    http: httpx.AsyncClient, identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    invitation = await identity.invitations.create(
        "grant@example.com",
        actor="test",
        sign_in_method=SignInMethod.PASSKEY_ONLY,
        grants=(StagedGrant("viewer"),),
    )
    answer = await _accept(http, mail.token())
    assert answer.status_code == 200, answer.text
    assert await identity.roles.roles_of(invitation.user_id) == ["viewer"]
