"""Sign-in methods: the instance default, ``password``, and pending changes (CS13 to CS18).

Every user follows the instance default unless they have a method of their
own. A change that needs a credential the user lacks waits for it, with the
method in force still working and a set-up link mailed; with no way to mail
the link, the change is refused, never made silently.
"""

from __future__ import annotations

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
    RecordingSender,
    UserFactory,
    audit_rows,
    race,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, PermissionRegistry, SignInMethod
from warden.identity.mail import MailKind
from warden.identity.sign_in_settings import (
    SecondFactorKind,
    SetupLink,
    SignInMethodChangeRefused,
    SignInSettingsError,
)
from warden.keys import KeyStore

pytestmark = pytest.mark.db

NEW_PASSWORD = "a different horse battery staple"
PENDING = "warden.identity.user.sign_in_method_pending"
CHANGED = "warden.identity.user.sign_in_method_changed"
CANCELLED = "warden.identity.user.sign_in_method_pending_cancelled"
LINK_SENT = "warden.identity.user.sign_in_method_link_sent"
SETTINGS_CHANGED = "warden.identity.sign_in_settings_changed"


async def source_ips(db: Database, action: str) -> list[str | None]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT host(source_ip) FROM warden.audit_events WHERE action = %s ORDER BY id",
            (action,),
        )
        return [row[0] for row in await cur.fetchall()]


async def has_password(db: Database, user_id: uuid.UUID) -> bool:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT password_hash IS NOT NULL FROM warden.users WHERE id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return bool(row[0])


async def assert_consistent(identity: Identity) -> None:
    """Every user's pending change, or the method in force, is what their setting resolves to."""
    default = (await identity.sign_in_methods.read_now()).default_sign_in_method
    for user in await identity.users.list():
        state = await identity.sign_in_method(user.id)
        target = default if state.setting is None else state.setting
        if state.pending is None:
            assert state.effective is target, (user.email, state)
        else:
            assert state.pending.to_method is target, (user.email, state)
            assert state.pending.from_method is state.effective, (user.email, state)


# The settings


async def test_the_settings_start_as_every_user_signed_in_before(identity: Identity) -> None:
    settings = await identity.sign_in_settings()
    assert settings.default_sign_in_method is SignInMethod.PASSWORD_AND_SSO
    assert settings.allowed_second_factors == {SecondFactorKind.TOTP, SecondFactorKind.PASSKEY}


async def test_a_new_user_follows_the_default(identity: Identity, make_user: UserFactory) -> None:
    user = await make_user()
    assert user.own_sign_in_method is None
    assert user.sign_in_method is SignInMethod.PASSWORD_AND_SSO
    assert user.pending_sign_in_method is None
    state = await identity.sign_in_method(user.id)
    assert (state.setting, state.effective, state.pending) == (
        None,
        SignInMethod.PASSWORD_AND_SSO,
        None,
    )


async def test_allowed_second_factors_are_stored_and_audited(
    identity: Identity, db: Database
) -> None:
    before = await identity.sign_in_settings()
    change = await identity.update_sign_in_settings(
        actor="admin-1", source_ip="192.0.2.7", allowed_second_factors=["passkey"]
    )
    assert change.settings.allowed_second_factors == {SecondFactorKind.PASSKEY}
    assert change.settings.updated_by == "admin-1"
    # The cached copy was invalidated by the change.
    assert (await identity.sign_in_settings()).allowed_second_factors == {SecondFactorKind.PASSKEY}
    assert before.allowed_second_factors != change.settings.allowed_second_factors
    rows = await audit_rows(db, SETTINGS_CHANGED)
    assert rows[-1]["outcome"] == "success"
    assert rows[-1]["actor"] == "admin-1"
    assert rows[-1]["details"]["allowed_second_factors_from"] == ["totp", "passkey"]
    assert rows[-1]["details"]["allowed_second_factors_to"] == ["passkey"]
    assert await source_ips(db, SETTINGS_CHANGED) == ["192.0.2.7"]


@pytest.mark.parametrize(
    "change",
    [
        {"default_sign_in_method": "magic_link"},
        {"default_sign_in_method": None},
        {"default_sign_in_method": 3},
        {"allowed_second_factors": []},
        {"allowed_second_factors": ["sms"]},
        {"allowed_second_factors": "totp"},
        {"allowed_second_factors": [1]},
        {"allowed_second_factors": None},
    ],
)
async def test_invalid_settings_are_refused(identity: Identity, change: dict[str, Any]) -> None:
    with pytest.raises(SignInSettingsError):
        await identity.update_sign_in_settings(actor="admin-1", **change)
    settings = await identity.sign_in_methods.read_now()
    assert settings.default_sign_in_method is SignInMethod.PASSWORD_AND_SSO
    assert len(settings.allowed_second_factors) == 2


async def test_sso_only_as_the_default_needs_single_sign_on(
    identity: Identity, db: Database
) -> None:
    with pytest.raises(SignInMethodChangeRefused) as refused:
        await identity.update_sign_in_settings(
            actor="admin-1", source_ip="192.0.2.7", default_sign_in_method="sso_only"
        )
    assert refused.value.reason == "sso_not_configured"
    settings = await identity.sign_in_methods.read_now()
    assert settings.default_sign_in_method is SignInMethod.PASSWORD_AND_SSO
    rows = await audit_rows(db, SETTINGS_CHANGED)
    assert [(r["outcome"], r["details"]["reason"]) for r in rows] == [
        ("failure", "sso_not_configured")
    ]
    assert await source_ips(db, SETTINGS_CHANGED) == ["192.0.2.7"]


async def test_sso_only_as_a_users_own_method_needs_single_sign_on(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    with pytest.raises(SignInMethodChangeRefused) as refused:
        await identity.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="admin-1")
    assert refused.value.reason == "sso_not_configured"
    state = await identity.sign_in_method(user.id)
    assert (state.setting, state.pending) == (None, None)
    rows = await audit_rows(db, CHANGED)
    assert rows[-1]["outcome"] == "failure"
    assert rows[-1]["details"]["reason"] == "sso_not_configured"


# Changes that take effect at once


async def test_a_new_default_moves_its_followers_holding_its_credential_at_once(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    follower = await make_user()
    own = await make_user(sign_in_method=SignInMethod.PASSWORD_AND_SSO)
    change = await identity.update_sign_in_settings(
        actor="admin-1", source_ip="192.0.2.7", default_sign_in_method="password"
    )
    assert change.settings.default_sign_in_method is SignInMethod.PASSWORD
    assert (change.changed, change.pending, change.links_failed) == ((follower.id,), (), ())
    moved = await identity.users.get(follower.id)
    kept = await identity.users.get(own.id)
    assert moved is not None and moved.sign_in_method is SignInMethod.PASSWORD
    assert moved.own_sign_in_method is None
    assert kept is not None and kept.sign_in_method is SignInMethod.PASSWORD_AND_SSO
    rows = [r for r in await audit_rows(db, CHANGED) if r["resource_id"] == str(follower.id)]
    assert rows[-1]["details"]["from"] == "password_and_sso"
    assert rows[-1]["details"]["to"] == "password"
    assert rows[-1]["details"]["cause"] == "default"
    assert await source_ips(db, CHANGED) == ["192.0.2.7"]
    await assert_consistent(identity)


async def test_a_users_own_method_takes_effect_at_once_with_its_credential(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    updated = await identity.users.set_sign_in_method(
        user.id, SignInMethod.PASSWORD, actor="admin-1", source_ip="192.0.2.7"
    )
    assert updated.sign_in_method is SignInMethod.PASSWORD
    assert updated.own_sign_in_method is SignInMethod.PASSWORD
    assert updated.pending_sign_in_method is None
    rows = await audit_rows(db, CHANGED)
    assert rows[-1]["details"]["from"] == "password_and_sso"
    assert rows[-1]["details"]["to"] == "password"
    assert rows[-1]["details"]["setting_from"] is None
    assert rows[-1]["details"]["setting_to"] == "password"
    assert await source_ips(db, CHANGED) == ["192.0.2.7"]
    # Back to the default.
    back = await identity.users.set_sign_in_method(user.id, None, actor="admin-1")
    assert (back.own_sign_in_method, back.sign_in_method) == (None, SignInMethod.PASSWORD_AND_SSO)


async def test_a_password_user_signs_in_with_a_password_and_must_take_a_second_factor(
    identity: Identity, make_user: UserFactory
) -> None:
    # Password + MFA asks for a second factor even where the policy does not.
    assert not (await identity.policy.current()).require_mfa
    user = await make_user(sign_in_method=SignInMethod.PASSWORD)
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is None
    assert result.challenge is not None and result.challenge.purpose == "enrol"
    both = await make_user()
    assert (await identity.sign_in(both.email, PASSWORD)).tokens is not None


# Pending changes and set-password links


async def test_a_move_needing_a_password_waits_for_the_set_password_link(
    identity: Identity, make_user: UserFactory, mail: RecordingSender, db: Database
) -> None:
    user = await make_user(password=None)
    change = await identity.update_sign_in_settings(
        actor="admin-1", source_ip="192.0.2.7", default_sign_in_method="password"
    )
    assert (change.changed, change.pending, change.links_failed) == ((), (user.id,), ())
    state = await identity.sign_in_method(user.id)
    assert state.effective is SignInMethod.PASSWORD_AND_SSO
    assert state.pending is not None
    assert state.pending.to_method is SignInMethod.PASSWORD
    assert state.pending.link is SetupLink.SET_PASSWORD
    assert state.pending.link_sent_at is not None
    assert [m.kind for m in mail.sent] == [MailKind.PASSWORD_SETUP]
    assert mail.sent[-1].to == user.email
    assert "https://app.example.com/reset?t=" in mail.sent[-1].text
    assert (await audit_rows(db, PENDING))[-1]["details"] == {
        "from": "password_and_sso",
        "to": "password",
        "cause": "default",
        "link": "set_password",
        "link_sent": True,
    }
    assert await source_ips(db, LINK_SENT) == ["192.0.2.7"]
    # The link sets the password and completes the change.
    await identity.resets.complete(mail.token(), NEW_PASSWORD, source_ip="192.0.2.8")
    state = await identity.sign_in_method(user.id)
    assert (state.effective, state.pending) == (SignInMethod.PASSWORD, None)
    rows = await audit_rows(db, CHANGED)
    assert rows[-1]["details"]["cause"] == "completed"
    assert rows[-1]["details"]["to"] == "password"
    result = await identity.sign_in(user.email, NEW_PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "enrol"
    await assert_consistent(identity)


async def test_resend_replaces_the_link_and_cancel_keeps_the_method_in_force(
    identity: Identity, make_user: UserFactory, mail: RecordingSender, db: Database
) -> None:
    # A user without a password, moving to a method that needs one.
    user = await make_user(password=None)
    await identity.set_sign_in_method(user.id, SignInMethod.PASSWORD, actor="admin-1")
    first = mail.token()
    expires = await identity.resend_sign_in_method_link(
        user.id, actor="admin-1", source_ip="192.0.2.7"
    )
    second = mail.token()
    assert first != second
    state = await identity.sign_in_method(user.id)
    assert state.pending is not None and expires > state.pending.requested_at
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(first, NEW_PASSWORD)
    cancelled = await identity.cancel_sign_in_method_change(
        user.id, actor="admin-1", source_ip="192.0.2.7"
    )
    # Back on what they had: the default, which is still in force.
    assert (cancelled.setting, cancelled.effective, cancelled.pending) == (
        None,
        SignInMethod.PASSWORD_AND_SSO,
        None,
    )
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(second, NEW_PASSWORD)
    rows = await audit_rows(db, CANCELLED)
    assert rows[-1]["details"]["reason"] == "cancelled"
    assert await source_ips(db, CANCELLED) == ["192.0.2.7"]
    for call in (identity.resend_sign_in_method_link, identity.cancel_sign_in_method_change):
        with pytest.raises(SignInMethodChangeRefused) as refused:
            await call(user.id, actor="admin-1")
        assert refused.value.reason == "not_pending"


async def test_cancelling_a_default_change_pins_the_user_to_the_method_in_force(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user(password=None)
    await identity.update_sign_in_settings(actor="admin-1", default_sign_in_method="password")
    state = await identity.cancel_sign_in_method_change(user.id, actor="admin-1")
    assert (state.setting, state.effective, state.pending) == (
        SignInMethod.PASSWORD_AND_SSO,
        SignInMethod.PASSWORD_AND_SSO,
        None,
    )
    await assert_consistent(identity)


async def test_choosing_the_method_in_force_again_drops_the_pending_change(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user(password=None)
    await identity.set_sign_in_method(user.id, SignInMethod.PASSWORD, actor="admin-1")
    state = await identity.set_sign_in_method(
        user.id, SignInMethod.PASSWORD_AND_SSO, actor="admin-1"
    )
    assert (state.setting, state.pending) == (SignInMethod.PASSWORD_AND_SSO, None)
    assert (await audit_rows(db, CANCELLED))[-1]["details"]["reason"] == "superseded"


async def test_a_default_change_back_drops_its_pending_changes(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user(password=None)
    await identity.update_sign_in_settings(actor="admin-1", default_sign_in_method="password")
    change = await identity.update_sign_in_settings(
        actor="admin-1", default_sign_in_method="password_and_sso"
    )
    assert (change.changed, change.pending) == ((), ())
    assert (await identity.sign_in_method(user.id)).pending is None


async def test_invited_users_take_the_new_method_at_once(
    identity: Identity, mail: RecordingSender
) -> None:
    invitation = await identity.invitations.create("ivy@example.com", actor="admin-1")
    await identity.update_sign_in_settings(actor="admin-1", default_sign_in_method="password")
    state = await identity.sign_in_method(invitation.user_id)
    assert (state.effective, state.pending) == (SignInMethod.PASSWORD, None)
    # Only the invitation was mailed: an invitee needs no set-up link.
    assert [m.kind for m in mail.sent] == [MailKind.INVITATION]


# No silent fall-back without mail


@pytest.fixture
def mailless(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> Identity:
    return Identity(config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)


async def test_a_change_needing_a_link_is_refused_without_a_mail_sender(
    mailless: Identity, db: Database
) -> None:
    user = await mailless.users.create("nopass@example.com", actor="test")
    with pytest.raises(SignInMethodChangeRefused) as refused:
        await mailless.set_sign_in_method(user.id, SignInMethod.PASSWORD, actor="admin-1")
    assert refused.value.reason == "mail_sender"
    assert "mail_sender" in str(refused.value)
    assert (await mailless.sign_in_method(user.id)).setting is None
    with pytest.raises(SignInMethodChangeRefused) as refused:
        await mailless.update_sign_in_settings(actor="admin-1", default_sign_in_method="password")
    assert refused.value.reason == "mail_sender"
    settings = await mailless.sign_in_methods.read_now()
    assert settings.default_sign_in_method is SignInMethod.PASSWORD_AND_SSO
    assert (await mailless.sign_in_method(user.id)).pending is None
    reasons = [r["details"]["reason"] for r in await audit_rows(db) if r["outcome"] == "failure"]
    assert reasons == ["mail_sender", "mail_sender"]


async def test_a_change_needing_no_link_is_made_without_a_mail_sender(mailless: Identity) -> None:
    user = await mailless.users.create("pw@example.com", actor="test", password=PASSWORD)
    change = await mailless.update_sign_in_settings(
        actor="admin-1", default_sign_in_method="password"
    )
    assert change.changed == (user.id,)


async def test_a_failed_delivery_undoes_a_users_change(
    identity: Identity, make_user: UserFactory, mail: RecordingSender, db: Database
) -> None:
    user = await make_user(password=None)
    mail.fail = True
    with pytest.raises(Exception, match="not delivered"):
        await identity.set_sign_in_method(user.id, SignInMethod.PASSWORD, actor="admin-1")
    state = await identity.sign_in_method(user.id)
    assert (state.setting, state.pending) == (None, None)
    assert (await audit_rows(db, LINK_SENT))[-1]["details"]["reason"] == "delivery_failed"


async def test_a_failed_delivery_after_a_default_change_is_listed_for_a_resend(
    identity: Identity, make_user: UserFactory, mail: RecordingSender
) -> None:
    user = await make_user(password=None)
    mail.fail = True
    change = await identity.update_sign_in_settings(
        actor="admin-1", default_sign_in_method="password"
    )
    assert change.pending == (user.id,)
    assert change.links_failed == (user.id,)
    mail.fail = False
    await identity.resend_sign_in_method_link(user.id, actor="admin-1")
    assert [m.kind for m in mail.sent] == [MailKind.PASSWORD_SETUP]


# A default change racing a user's own change


async def test_a_default_change_racing_a_users_own_change_ends_consistent(
    identity: Identity, make_user: UserFactory
) -> None:
    for _ in range(6):
        await identity.update_sign_in_settings(
            actor="admin-1", default_sign_in_method="password_and_sso"
        )
        # Pinned now, following the default once the race is over.
        joining = await make_user(password=None, sign_in_method=SignInMethod.PASSWORD_AND_SSO)
        # Following now, pinned to the method in force once the race is over.
        leaving = await make_user(password=None)
        outcomes = await race(
            lambda: identity.update_sign_in_settings(
                actor="admin-1", default_sign_in_method="password"
            ),
            lambda j=joining.id: identity.set_sign_in_method(j, None, actor="admin-2"),
            lambda u=leaving.id: identity.set_sign_in_method(
                u, SignInMethod.PASSWORD_AND_SSO, actor="admin-3"
            ),
        )
        assert not [o for o in outcomes if isinstance(o, BaseException)], outcomes
        joined = await identity.sign_in_method(joining.id)
        assert joined.setting is None
        assert joined.pending is not None and joined.pending.to_method is SignInMethod.PASSWORD
        left = await identity.sign_in_method(leaving.id)
        assert (left.setting, left.pending) == (SignInMethod.PASSWORD_AND_SSO, None)
        await assert_consistent(identity)


# The administrator's route


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def admin(client: httpx.AsyncClient, make_user: UserFactory) -> AsyncIterator[dict[str, str]]:
    user = await make_user(roles=("admin",))
    answer = await client.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    yield {"authorization": f"Bearer {answer.json()['access_token']}"}


async def test_the_route_takes_password_and_null_and_reports_the_pending_change(
    client: httpx.AsyncClient, admin: dict[str, str], make_user: UserFactory
) -> None:
    user = await make_user()
    path = f"/admin/users/{user.id}/sign-in-method"
    answer = await client.post(path, json={"sign_in_method": "password"}, headers=admin)
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["user"]["sign_in_method"] == "password"
    assert body["sign_in_method"] == {
        "setting": "password",
        "effective": "password",
        "pending": None,
    }
    answer = await client.post(path, json={"sign_in_method": None}, headers=admin)
    assert answer.json()["sign_in_method"] == {
        "setting": None,
        "effective": "password_and_sso",
        "pending": None,
    }
    waiting = await make_user(password=None)
    answer = await client.post(
        f"/admin/users/{waiting.id}/sign-in-method",
        json={"sign_in_method": "password"},
        headers=admin,
    )
    assert answer.status_code == 200, answer.text
    state = answer.json()["sign_in_method"]
    assert state["effective"] == "password_and_sso"
    assert state["pending"]["from"] == "password_and_sso"
    assert state["pending"]["to"] == "password"
    assert state["pending"]["link"] == "set_password"
    assert state["pending"]["link_sent_at"] is not None
    for body in ({}, {"sign_in_method": "magic_link"}, {"sign_in_method": 3}):
        answer = await client.post(path, json=body, headers=admin)
        assert answer.status_code == 400, body
    answer = await client.post(path, json={"sign_in_method": "sso_only"}, headers=admin)
    assert answer.status_code == 409
    assert "single sign-on" in answer.json()["detail"]


async def test_the_set_password_link_works_while_the_method_in_force_has_no_password(
    identity: Identity, make_user: UserFactory, mail: RecordingSender, db: Database
) -> None:
    user = await make_user(password=None, sign_in_method=SignInMethod.PASSKEY_ONLY)
    state = await identity.set_sign_in_method(user.id, SignInMethod.PASSWORD, actor="admin-1")
    assert state.effective is SignInMethod.PASSKEY_ONLY
    assert state.pending is not None and state.pending.link is SetupLink.SET_PASSWORD
    await identity.resets.complete(mail.token(), NEW_PASSWORD)
    state = await identity.sign_in_method(user.id)
    assert (state.effective, state.pending) == (SignInMethod.PASSWORD, None)
    assert await has_password(db, user.id)
