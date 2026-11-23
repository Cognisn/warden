"""Single sign-on and the sign-in methods (rulings CS13, CS17 and CS18).

A ``password`` user is refused single sign-on, as an ``sso_only`` user is
refused a password. A move to ``sso_only`` waits for the account's first
single sign-on, which completes it. Single sign-on cannot be turned off or
cleared while anyone signs in with it alone.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_SECRET, FakeIdp
from fastapi import FastAPI
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows, race
from sso_support import CLIENT_SECRET_NAME, sign_in, sso_config

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import (
    AuthenticationRefused,
    Identity,
    SignInMethod,
    SignInMethodConflict,
    UserStatus,
)
from warden.identity.sign_in_settings import SignInMethodChangeRefused
from warden.identity.sso.provider import ProviderHttp
from warden.identity.sso.service import SingleSignOn
from warden.identity.sso.settings import SsoSettingsError, SsoSettingsStore, SsoStillRequired

pytestmark = pytest.mark.db

ALICE = "alice@example.com"
SSO_SETTINGS = "warden.identity.sso.settings_changed"


@pytest.fixture
def config() -> WardenConfig:
    return sso_config()


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    return secrets


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def sso(identity: Identity, idp: FakeIdp, secrets: Any) -> SingleSignOn:
    identity.sso = SingleSignOn(
        identity.config,
        identity.db,
        identity.sessions,
        identity.policy,
        secrets,
        http=ProviderHttp(idp.client()),
        settings_max_age=0,
    )
    identity.sso.use_sign_in_methods(identity.sign_in_methods)
    return identity.sso


@pytest.fixture
def app(identity: Identity, sso: SingleSignOn) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


async def refusals(db: Database) -> list[str]:
    return [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sso.sign_in")]


async def live_sessions(db: Database, user_id: uuid.UUID) -> list[list[str]]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT amr FROM warden.sessions WHERE user_id = %s AND revoked_at IS NULL"
            " ORDER BY created_at",
            (user_id,),
        )
        return [list(row[0]) for row in await cur.fetchall()]


async def enabled(db: Database, store: SsoSettingsStore) -> bool:
    async with db.connection() as conn:
        return (await store.read(conn)).enabled


async def has_password(db: Database, user_id: uuid.UUID) -> bool:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT password_hash IS NOT NULL FROM warden.users WHERE id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return bool(row[0])


# A password user and single sign-on


async def test_a_password_user_is_refused_single_sign_on_as_others_are(
    client: httpx.AsyncClient, idp: FakeIdp, make_user: UserFactory, db: Database
) -> None:
    password_user = await make_user(ALICE, sign_in_method=SignInMethod.PASSWORD)
    passkey_user = await make_user("pia@example.com", sign_in_method=SignInMethod.PASSKEY_ONLY)
    first = await sign_in(client, idp, email=ALICE, sub="alice-sub")
    second = await sign_in(client, idp, email=passkey_user.email, sub="pia-sub")
    # The browser sees the same fixed failure for both; only the trail says why.
    assert first.status_code == second.status_code == 401
    assert first.json() == second.json()
    assert await refusals(db) == ["password", "passkey_only"]
    assert await live_sessions(db, password_user.id) == []


async def test_a_password_user_pinned_earlier_is_refused_too(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    make_user: UserFactory,
    db: Database,
    identity: Identity,
) -> None:
    user = await make_user(ALICE)
    assert (await sign_in(client, idp, email=ALICE, sub="alice-sub")).status_code == 200
    await identity.set_sign_in_method(user.id, SignInMethod.PASSWORD, actor="admin-1")
    # Moving to password ended the single sign-on session.
    assert await live_sessions(db, user.id) == []
    refused = await sign_in(client, idp, email=ALICE, sub="alice-sub")
    assert refused.status_code == 401
    assert (await refusals(db))[-1] == "password"


async def test_a_default_change_to_password_ends_single_sign_on_sessions(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    make_user: UserFactory,
    db: Database,
    identity: Identity,
) -> None:
    user = await make_user(ALICE)
    assert (await sign_in(client, idp, email=ALICE, sub="alice-sub")).status_code == 200
    assert (await identity.sign_in(ALICE, PASSWORD)).tokens is not None
    change = await identity.update_sign_in_settings(
        actor="admin-1", default_sign_in_method="password"
    )
    assert change.changed == (user.id,)
    assert await live_sessions(db, user.id) == [["pwd"]]


# Moving to sso_only


async def test_a_move_to_sso_only_completes_at_the_first_single_sign_on(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    make_user: UserFactory,
    mail: RecordingSender,
    db: Database,
    identity: Identity,
) -> None:
    user = await make_user(ALICE)
    assert (await identity.sign_in(ALICE, PASSWORD)).tokens is not None
    state = await identity.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="admin-1")
    assert state.effective is SignInMethod.PASSWORD_AND_SSO
    assert state.pending is not None and state.pending.link is None
    assert mail.sent == []
    # The password keeps working until then.
    assert (await identity.sign_in(ALICE, PASSWORD)).tokens is not None
    answer = await sign_in(client, idp, email=ALICE, sub="alice-sub")
    assert answer.status_code == 200, answer.text
    state = await identity.sign_in_method(user.id)
    assert (state.effective, state.pending) == (SignInMethod.SSO_ONLY, None)
    assert not await has_password(db, user.id)
    # Only the single sign-on session that completed the move is left.
    assert await live_sessions(db, user.id) == [["sso"]]
    with pytest.raises(AuthenticationRefused):
        await identity.sign_in(ALICE, PASSWORD)
    rows = await audit_rows(db, "warden.identity.user.sign_in_method_changed")
    assert rows[-1]["details"]["cause"] == "completed"
    assert rows[-1]["details"]["password_removed"] is True


async def test_a_move_to_sso_only_from_password_admits_the_first_single_sign_on(
    client: httpx.AsyncClient, idp: FakeIdp, make_user: UserFactory, identity: Identity
) -> None:
    user = await make_user(ALICE, sign_in_method=SignInMethod.PASSWORD)
    await identity.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="admin-1")
    answer = await sign_in(client, idp, email=ALICE, sub="alice-sub")
    assert answer.status_code == 200, answer.text
    assert (await identity.sign_in_method(user.id)).effective is SignInMethod.SSO_ONLY


async def test_sso_only_as_the_default_when_single_sign_on_is_set_up(
    make_user: UserFactory, identity: Identity, mail: RecordingSender
) -> None:
    user = await make_user(ALICE)
    change = await identity.update_sign_in_settings(
        actor="admin-1", default_sign_in_method="sso_only"
    )
    assert change.pending == (user.id,)
    assert mail.sent == []


# No lock-out by turning single sign-on off (ruling CS17)


async def test_turning_sso_off_is_refused_while_a_user_signs_in_with_it_alone(
    make_user: UserFactory, identity: Identity, db: Database, sso: SingleSignOn
) -> None:
    sso_user = await make_user(
        "bob@example.com", password=None, sign_in_method=SignInMethod.SSO_ONLY
    )
    await make_user(ALICE)
    with pytest.raises(SsoStillRequired) as refused:
        await sso.settings.update(actor="admin-1", source_ip="192.0.2.7", enabled=False)
    assert refused.value.users == ((sso_user.id, "bob@example.com"),)
    assert not refused.value.default_sso_only
    assert "1 active users" in str(refused.value)
    assert "bob@example.com" not in str(refused.value)
    assert isinstance(refused.value, SsoSettingsError)
    with pytest.raises(SsoStillRequired):
        await sso.settings.update(actor="admin-1", client_id=None, enabled=False)
    assert await enabled(db, sso.settings)
    rows = [r for r in await audit_rows(db, SSO_SETTINGS) if r["outcome"] == "failure"]
    assert rows[0]["details"]["reason"] == "sso_still_required"
    assert rows[0]["details"]["user_ids"] == [str(sso_user.id)]
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT host(source_ip) FROM warden.audit_events WHERE action = %s"
            " AND outcome = 'failure' ORDER BY id",
            (SSO_SETTINGS,),
        )
        assert [r[0] for r in await cur.fetchall()] == ["192.0.2.7", None]


async def test_turning_sso_off_is_refused_while_the_default_is_sso_only(
    identity: Identity, sso: SingleSignOn
) -> None:
    await identity.update_sign_in_settings(actor="admin-1", default_sign_in_method="sso_only")
    with pytest.raises(SsoStillRequired) as refused:
        await sso.settings.update(actor="admin-1", enabled=False)
    assert refused.value.default_sso_only
    assert refused.value.users == ()


async def test_clearing_run_time_sso_settings_is_refused_while_someone_needs_them(
    db: Database, make_user: UserFactory, sso: SingleSignOn
) -> None:
    # Configuration leaves single sign-on off; an administrator turned it on.
    store = SsoSettingsStore(db, sso_config(enabled=False), max_age=0)
    await store.update(actor="admin-1", enabled=True)
    user = await make_user(password=None, sign_in_method=SignInMethod.SSO_ONLY)
    with pytest.raises(SsoStillRequired) as refused:
        await store.reset(actor="admin-1")
    assert refused.value.users == ((user.id, user.email),)
    assert await enabled(db, store)


async def test_a_pending_move_to_sso_only_also_holds_single_sign_on(
    make_user: UserFactory, identity: Identity, sso: SingleSignOn
) -> None:
    user = await make_user(ALICE)
    await identity.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="admin-1")
    with pytest.raises(SsoStillRequired) as refused:
        await sso.settings.update(actor="admin-1", enabled=False)
    assert refused.value.users == ((user.id, ALICE),)


async def test_password_and_sso_and_inactive_users_do_not_hold_single_sign_on(
    make_user: UserFactory, identity: Identity, db: Database, sso: SingleSignOn
) -> None:
    await make_user(ALICE)
    gone = await make_user("bob@example.com", password=None, sign_in_method=SignInMethod.SSO_ONLY)
    await identity.users.set_status(gone.id, UserStatus.SUSPENDED, actor="admin-1")
    settings = await sso.settings.update(actor="admin-1", enabled=False)
    assert not settings.enabled
    assert (await identity.sign_in(ALICE, PASSWORD)).tokens is not None


async def test_turning_sso_off_racing_a_move_to_sso_only_never_does_both(
    make_user: UserFactory, identity: Identity, db: Database, sso: SingleSignOn
) -> None:
    for index in range(6):
        await sso.settings.update(actor="admin-1", enabled=True)
        user = await make_user(f"user-{index}@example.com")
        outcomes = await race(
            lambda: sso.settings.update(actor="admin-1", enabled=False),
            lambda u=user: identity.set_sign_in_method(u.id, SignInMethod.SSO_ONLY, actor="a"),
        )
        disabled, moved = outcomes
        assert isinstance(disabled, SsoStillRequired) != isinstance(
            moved, SignInMethodChangeRefused
        ), outcomes
        if isinstance(moved, SignInMethodChangeRefused):
            assert moved.reason == "sso_not_configured"
            assert not await enabled(db, sso.settings)
        else:
            assert not isinstance(moved, BaseException), outcomes
            assert await enabled(db, sso.settings)
            # Leave the next round free to turn it off.
            await identity.cancel_sign_in_method_change(user.id, actor="admin-1")


async def add_key(db: Database, user_id: uuid.UUID) -> None:
    """A security key on the user's account, written straight to its table."""
    async with db.connection() as conn:
        await conn.execute(
            "INSERT INTO warden.webauthn_credentials (user_id, credential_id, public_key,"
            " algorithm, aaguid, backup_eligible, backup_state, discoverable, user_verified,"
            " attestation_verified) VALUES (%s, %s, %s, -7, %s, false, false, true, true, false)",
            (user_id, uuid.uuid4().bytes, uuid.uuid4().bytes, uuid.UUID(int=0)),
        )


async def keys_of(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.webauthn_credentials WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def test_a_default_move_to_sso_only_removes_keys_when_it_completes(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    make_user: UserFactory,
    db: Database,
    identity: Identity,
) -> None:
    user = await make_user(ALICE)
    await add_key(db, user.id)
    # A user's own move is refused while they hold keys (Skuld question 25)...
    with pytest.raises(SignInMethodConflict):
        await identity.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="admin-1")
    # ...but a move of the default waits, and its completion removes them.
    change = await identity.update_sign_in_settings(
        actor="admin-1", default_sign_in_method="sso_only"
    )
    assert change.pending == (user.id,)
    assert await keys_of(db, user.id) == 1
    answer = await sign_in(client, idp, email=ALICE, sub="alice-sub")
    assert answer.status_code == 200, answer.text
    assert await keys_of(db, user.id) == 0
    rows = await audit_rows(db, "warden.identity.user.sign_in_method_changed")
    assert rows[-1]["details"]["webauthn_removed"] == 1
