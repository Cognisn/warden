"""Moving users to ``passkey_only`` (ruling CS18): pending until the passkey exists.

Without a passkey, the method in force keeps working and the user is mailed
the passkey registration link. Registering the passkey completes the change
and removes what passkey-only does not allow: the password hash and every
session signed in with a password.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows
from passkey_support import (
    assert_refused,
    give_passkey,
    http_client,
    passkey_assertion,
    passkey_authenticator,
    passkey_config,
    passkey_sign_in,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, SignInMethod
from warden.identity.mail import MailKind
from warden.identity.sign_in_settings import SetupLink

pytestmark = pytest.mark.db

CHANGED = "warden.identity.user.sign_in_method_changed"


@pytest.fixture
def config() -> WardenConfig:
    return passkey_config(sign_in_attempt_limit=1000)


@pytest.fixture
async def http(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(identity) as client:
        yield client


async def has_password(db: Database, user_id: uuid.UUID) -> bool:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT password_hash IS NOT NULL FROM warden.users WHERE id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return bool(row[0])


async def live_sessions(db: Database, user_id: uuid.UUID) -> list[list[str]]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT amr FROM warden.sessions WHERE user_id = %s AND revoked_at IS NULL"
            " ORDER BY created_at",
            (user_id,),
        )
        return [list(row[0]) for row in await cur.fetchall()]


async def test_a_default_change_to_passkey_only_waits_for_the_passkey(
    identity: Identity,
    http: httpx.AsyncClient,
    make_user: UserFactory,
    mail: RecordingSender,
    db: Database,
) -> None:
    user = await make_user()
    assert (await identity.sign_in(user.email, PASSWORD)).tokens is not None
    change = await identity.update_sign_in_settings(
        actor="admin-1", default_sign_in_method="passkey_only"
    )
    assert change.pending == (user.id,)
    state = await identity.sign_in_method(user.id)
    assert state.effective is SignInMethod.PASSWORD_AND_SSO
    assert state.pending is not None and state.pending.link is SetupLink.PASSKEY_REGISTRATION
    assert [m.kind for m in mail.sent] == [MailKind.PASSKEY_REGISTRATION]
    assert "https://app.example.com/passkey?t=" in mail.sent[-1].text
    # The method in force keeps working meanwhile.
    assert (await identity.sign_in(user.email, PASSWORD)).tokens is not None
    assert await live_sessions(db, user.id) == [["pwd"], ["pwd"]]

    token = mail.token()
    key = passkey_authenticator()
    options = await http.post("/auth/passkey-registration/options", json={"token": token})
    assert options.status_code == 200, options.text
    answer = await http.post(
        "/auth/passkey-registration",
        json={"token": token, "credential": key.register(options.json()["public_key"])},
    )
    assert answer.status_code == 200, answer.text

    state = await identity.sign_in_method(user.id)
    assert (state.setting, state.effective, state.pending) == (
        None,
        SignInMethod.PASSKEY_ONLY,
        None,
    )
    assert not await has_password(db, user.id)
    assert await live_sessions(db, user.id) == []
    rows = await audit_rows(db, CHANGED)
    assert rows[-1]["details"]["cause"] == "completed"
    assert rows[-1]["details"]["password_removed"] is True
    assert rows[-1]["details"]["sessions_ended"] == 2
    with pytest.raises(AuthenticationRefused):
        await identity.sign_in(user.email, PASSWORD)
    signed_in = await passkey_sign_in(http, await passkey_assertion(http, key))
    assert signed_in.status_code == 200, signed_in.text


async def test_a_user_holding_a_passkey_moves_at_once_and_loses_the_password(
    identity: Identity, make_user: UserFactory, mail: RecordingSender, db: Database
) -> None:
    user = await make_user()
    password_session = await identity.sign_in(user.email, PASSWORD)
    assert password_session.tokens is not None
    await give_passkey(identity, user)
    state = await identity.set_sign_in_method(user.id, SignInMethod.PASSKEY_ONLY, actor="admin-1")
    assert (state.effective, state.pending) == (SignInMethod.PASSKEY_ONLY, None)
    assert mail.sent == []
    assert not await has_password(db, user.id)
    assert await live_sessions(db, user.id) == []
    rows = await audit_rows(db, CHANGED)
    assert rows[-1]["details"]["password_removed"] is True
    assert rows[-1]["details"]["sessions_ended"] == 1


async def test_a_passkey_registered_as_a_second_factor_completes_the_move(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    await identity.set_sign_in_method(user.id, SignInMethod.PASSKEY_ONLY, actor="admin-1")
    assert (await identity.sign_in_method(user.id)).pending is not None
    signed_in = await identity.sign_in(user.email, PASSWORD)
    assert signed_in.tokens is not None
    principal = await identity.authenticate(signed_in.tokens.access_token)
    key = passkey_authenticator()
    options = await identity.begin_webauthn_registration(principal=principal)
    await identity.finish_webauthn_registration(
        key.register(options.public_key), principal=principal
    )
    state = await identity.sign_in_method(user.id)
    assert (state.effective, state.pending) == (SignInMethod.PASSKEY_ONLY, None)
    assert not await has_password(db, user.id)


async def test_a_security_key_that_is_not_a_passkey_leaves_the_move_pending(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    await identity.set_sign_in_method(user.id, SignInMethod.PASSKEY_ONLY, actor="admin-1")
    signed_in = await identity.sign_in(user.email, PASSWORD)
    assert signed_in.tokens is not None
    principal = await identity.authenticate(signed_in.tokens.access_token)
    key = passkey_authenticator(resident=False)
    options = await identity.begin_webauthn_registration(principal=principal)
    await identity.finish_webauthn_registration(
        key.register(options.public_key), principal=principal
    )
    state = await identity.sign_in_method(user.id)
    assert state.effective is SignInMethod.PASSWORD_AND_SSO
    assert state.pending is not None
    assert await has_password(db, user.id)


async def test_the_old_link_refusal_still_applies_to_sso_only_users_with_nothing_pending(
    identity: Identity, http: httpx.AsyncClient, make_user: UserFactory, mail: RecordingSender
) -> None:
    user = await make_user(password=None, sign_in_method=SignInMethod.SSO_ONLY)
    from warden.identity.service import PasskeyLinkRefused

    with pytest.raises(PasskeyLinkRefused):
        await identity.send_passkey_registration(user.id, actor="admin-1")
    assert mail.sent == []
    assert_refused(await http.post("/auth/passkey-registration/options", json={"token": "x" * 43}))
