"""Single sign-on settings: configuration defaults, audited run-time overrides,
and disabling revoking SSO sessions."""

from __future__ import annotations

import uuid

import pytest
from identity_support import UserFactory, audit_rows
from sso_support import sso_config

from warden.audit import ActionRegistry
from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity
from warden.identity.sso.actions import register_sso_actions
from warden.identity.sso.settings import SsoSettingsError, SsoSettingsStore

pytestmark = pytest.mark.db


@pytest.fixture
def config() -> WardenConfig:
    return sso_config(allowed_email_domains="example.com")


@pytest.fixture
def store(db: Database, config: WardenConfig, audit_registry: ActionRegistry) -> SsoSettingsStore:
    register_sso_actions(audit_registry)
    return SsoSettingsStore(db, config, max_age=0)


async def test_defaults_come_from_configuration(store: SsoSettingsStore) -> None:
    settings = await store.current()
    assert settings.enabled is True
    assert settings.issuer_url == "https://idp.example.com/tenant"
    assert settings.client_id == "warden-client"
    assert settings.allowed_email_domains == ("example.com",)
    assert settings.provider_preset == "generic"


async def test_an_override_is_shared_by_every_replica(
    db: Database, config: WardenConfig, store: SsoSettingsStore
) -> None:
    await store.update(actor="admin", allowed_email_domains=["Example.ORG"], provider_preset="okta")
    other = SsoSettingsStore(db, config, max_age=0)
    settings = await other.current()
    assert settings.allowed_email_domains == ("example.org",)
    assert settings.provider_preset == "okta"


@pytest.mark.parametrize(
    "changes",
    [
        {"issuer_url": "http://idp.example.com"},
        {"allowed_email_domains": ["not a domain"]},
        {"scopes": ["email"]},
        {"provider_preset": "auth0"},
        {"enabled": "yes"},
        {"client_secret": "another-name"},
        {"allowed_algorithms": ["HS256"]},
        {"colour": "blue"},
    ],
)
async def test_an_invalid_change_is_refused_and_not_written(
    store: SsoSettingsStore, changes: dict[str, object]
) -> None:
    before = await store.current()
    with pytest.raises(SsoSettingsError):
        await store.update(actor="admin", **changes)
    assert await store.current() == before


async def test_enabling_needs_a_completion_link(db: Database) -> None:
    config = sso_config(completion=None, enabled=False)
    store = SsoSettingsStore(db, config, max_age=0)
    with pytest.raises(SsoSettingsError, match="sso_completion_link"):
        await store.update(actor="admin", enabled=True)


async def test_enabling_needs_an_issuer_and_client(db: Database) -> None:
    config = sso_config(enabled=False, issuer_url=None, client_id=None)
    store = SsoSettingsStore(db, config, max_age=0)
    with pytest.raises(SsoSettingsError, match="issuer_url"):
        await store.update(actor="admin", enabled=True)


async def test_a_change_is_audited_with_the_fields_changed(
    db: Database, store: SsoSettingsStore
) -> None:
    await store.update(actor="admin", provider_preset="entra")
    rows = await audit_rows(db, "warden.identity.sso.settings_changed")
    assert len(rows) == 1
    assert rows[0]["actor"] == "admin"
    assert rows[0]["details"] == {"changed": ["provider_preset"], "enabled": True}


async def _session(identity: Identity, user_id: uuid.UUID, amr: list[str]) -> uuid.UUID:
    policy = await identity.policy.current()
    async with identity.db.transaction() as tx:
        new = await identity.sessions.start(tx, user_id, amr, policy)
    return new.session_id


async def _revoked(db: Database, session_id: object) -> str | None:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT revoked_reason FROM warden.sessions WHERE id = %s", (session_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return None if row[0] is None else str(row[0])


async def test_disabling_revokes_sso_sessions_only(
    db: Database, store: SsoSettingsStore, identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    sso = await _session(identity, user.id, ["sso"])
    password = await _session(identity, user.id, ["pwd", "otp"])

    await store.update(actor="admin", enabled=False)

    assert await _revoked(db, sso) == "sso_disabled"
    assert await _revoked(db, password) is None
    rows = await audit_rows(db, "warden.identity.sso.disabled")
    assert rows[0]["details"] == {"sessions_revoked": 1}
    assert (await store.current()).enabled is False


async def test_a_change_that_keeps_sso_enabled_revokes_nothing(
    db: Database, store: SsoSettingsStore
) -> None:
    await store.update(actor="admin", provider_preset="google")
    assert await audit_rows(db, "warden.identity.sso.disabled") == []


async def test_reset_returns_to_configuration(store: SsoSettingsStore) -> None:
    await store.update(actor="admin", provider_preset="google")
    await store.reset(actor="admin")
    assert (await store.current()).provider_preset == "generic"
