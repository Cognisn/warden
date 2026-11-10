"""The password policy store (rulings PW1, PW2 and PW11): policies, priorities,
role mappings, pins, the effective policy, seeding and the replica cache."""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from typing import Any

import pytest
from identity_support import audit_rows, race

from warden.db import Database
from warden.identity import PermissionRegistry, SignInMethod, User
from warden.identity.password_policy import (
    PasswordPolicyConflict,
    PasswordPolicyError,
    PasswordPolicyNotFound,
    PasswordRules,
    Tier,
)
from warden.identity.password_policy.store import (
    EffectivePolicy,
    PasswordPolicies,
    PolicySettings,
    resolve,
)

pytestmark = pytest.mark.db


def _store(
    db: Database,
    permissions: PermissionRegistry,
    *,
    max_age: float = 30.0,
    fingerprint: bool = False,
    seed_min_length: int = 12,
) -> PasswordPolicies:
    return PasswordPolicies(
        db,
        permissions,
        seed_min_length=seed_min_length,
        fingerprint_available=fingerprint,
        max_age=max_age,
    )


def _settings(name: str = "Analysts", **overrides: Any) -> PolicySettings:
    values: dict[str, Any] = {"name": name, "rules": PasswordRules(min_length=14)}
    values.update(overrides)
    return PolicySettings(**values)


def _who(effective: EffectivePolicy) -> tuple[uuid.UUID, str, str | None]:
    return effective.policy.id, effective.source, effective.role


@pytest.fixture
def store(db: Database, permissions: PermissionRegistry) -> PasswordPolicies:
    return _store(db, permissions)


async def test_the_default_is_seeded_from_configuration(
    db: Database, permissions: PermissionRegistry
) -> None:
    store = _store(db, permissions, seed_min_length=15)
    default = await store.default()
    assert default.is_default and default.priority is None
    assert default.settings.rules == PasswordRules(min_length=15)
    assert default.settings.history_count == 0
    assert default.settings.include_builtin
    assert not default.settings.hibp_enabled and not default.settings.fingerprint_enabled
    assert default.settings.rules.tiers == ()
    (row,) = await audit_rows(db, "warden.identity.password_policy.created")
    assert row["details"] == {"seeded": True, "version": 1}
    # Once stored, the stored value governs: configuration no longer changes it.
    assert (await _store(db, permissions, seed_min_length=20).default()).id == default.id
    assert (await _store(db, permissions, seed_min_length=20).default()).settings.rules == (
        PasswordRules(min_length=15)
    )


async def test_two_replicas_seeding_together_create_one_default(
    db: Database, permissions: PermissionRegistry
) -> None:
    replicas = [_store(db, permissions) for _ in range(4)]
    results = await race(*(r.ensure_default for r in replicas))
    assert len({r.id for r in results}) == 1, results
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.password_policies")
        assert await cur.fetchone() == (1,)
    assert len(await audit_rows(db, "warden.identity.password_policy.created")) == 1


async def test_create_read_update_and_delete(store: PasswordPolicies, db: Database) -> None:
    created = await store.create(_settings(), priority=10, actor="admin")
    assert created.version == 1 and created.priority == 10 and not created.is_default
    assert await store.get(created.id) == created
    changed = await store.update(
        created.id,
        dataclasses.replace(created.settings, history_count=5),
        expected_version=1,
        actor="admin",
    )
    assert changed.version == 2 and changed.settings.history_count == 5
    (row,) = await audit_rows(db, "warden.identity.password_policy.updated")
    assert row["details"] == {"fields": ["history_count"], "version": 2}
    assert row["resource_id"] == str(created.id)
    await store.delete(created.id, actor="admin")
    with pytest.raises(PasswordPolicyNotFound):
        await store.get(created.id)
    assert len(await audit_rows(db, "warden.identity.password_policy.deleted")) == 1


async def test_a_stale_version_is_refused(store: PasswordPolicies) -> None:
    created = await store.create(_settings(), priority=1, actor="admin")
    await store.update(created.id, created.settings, expected_version=1, actor="a")
    with pytest.raises(PasswordPolicyConflict):
        await store.update(created.id, created.settings, expected_version=1, actor="b")


async def test_the_default_cannot_be_deleted(store: PasswordPolicies) -> None:
    default = await store.default()
    with pytest.raises(PasswordPolicyConflict):
        await store.delete(default.id, actor="admin")
    assert (await store.default()).id == default.id


async def test_names_and_priorities_are_unique(store: PasswordPolicies) -> None:
    await store.create(_settings("Admins"), priority=1, actor="a")
    with pytest.raises(PasswordPolicyConflict):
        await store.create(_settings("admins"), priority=2, actor="a")
    with pytest.raises(PasswordPolicyConflict):
        await store.create(_settings("Others"), priority=1, actor="a")


async def test_two_concurrent_priority_changes_cannot_leave_duplicates(
    store: PasswordPolicies, db: Database
) -> None:
    first = await store.create(_settings("First"), priority=1, actor="a")
    second = await store.create(_settings("Second"), priority=2, actor="a")
    outcomes = await race(
        lambda: store.set_priority(first.id, 7, actor="a"),
        lambda: store.set_priority(second.id, 7, actor="a"),
    )
    assert sum(isinstance(o, PasswordPolicyConflict) for o in outcomes) == 1, outcomes
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT priority, count(*) FROM warden.password_policies"
            " WHERE priority IS NOT NULL GROUP BY priority HAVING count(*) > 1"
        )
        assert await cur.fetchall() == []


async def test_reorder_swaps_priorities_in_one_change(store: PasswordPolicies) -> None:
    first = await store.create(_settings("First"), priority=1, actor="a")
    second = await store.create(_settings("Second"), priority=2, actor="a")
    await store.reorder([second.id, first.id], actor="a")
    assert (await store.get(second.id)).priority == 1
    assert (await store.get(first.id)).priority == 2
    with pytest.raises(PasswordPolicyError):
        await store.reorder([second.id], actor="a")


async def test_the_fingerprint_is_refused_on_save_without_a_key(
    db: Database, permissions: PermissionRegistry
) -> None:
    without = _store(db, permissions)
    with pytest.raises(PasswordPolicyError, match="fingerprint"):
        await without.create(_settings(fingerprint_enabled=True), priority=1, actor="a")
    with_key = _store(db, permissions, fingerprint=True)
    created = await with_key.create(_settings(fingerprint_enabled=True), priority=1, actor="a")
    assert created.settings.fingerprint_enabled


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"name": "x" * 65},
        {"name": "bad\nname"},
        {"description": "x" * 501},
        {"history_count": 25},
        {"history_count": -1},
        {"min_age_hours": 8761},
        {"hibp_on_unavailable": "ignore"},
        {"rules": PasswordRules(min_length=7)},
        {"rules": PasswordRules(min_length=12, tiers=(Tier(name="long", min_length=20),))},
    ],
)
async def test_invalid_settings_are_refused_before_any_write(
    store: PasswordPolicies, db: Database, overrides: dict[str, Any]
) -> None:
    with pytest.raises(PasswordPolicyError):
        await store.create(_settings(**overrides), priority=1, actor="a")
    assert await audit_rows(db, "warden.identity.password_policy.created") == []


async def test_effective_policy_pin_over_role_over_default(
    store: PasswordPolicies, make_user: Any, db: Database
) -> None:
    default = await store.default()
    strict = await store.create(_settings("Strict"), priority=1, actor="a")
    loose = await store.create(_settings("Loose"), priority=5, actor="a")
    pinned = await store.create(_settings("Pinned"), priority=9, actor="a")
    await store.map_role("analyst", loose.id, actor="a")
    await store.map_role("admin", strict.id, actor="a")

    plain: User = await make_user()
    assert _who(await store.effective(plain.id)) == (default.id, "default", None)

    analyst: User = await make_user(roles=("analyst",))
    assert _who(await store.effective(analyst.id)) == (loose.id, "role", "analyst")

    # Several mapped roles: the highest priority (the lowest number) wins.
    both: User = await make_user(roles=("analyst", "admin"))
    assert _who(await store.effective(both.id)) == (strict.id, "role", "admin")

    # A pin overrides every role mapping.
    await store.pin(both.id, pinned.id, actor="a")
    assert _who(await store.effective(both.id)) == (pinned.id, "pin", None)
    assert await store.unpin(both.id, actor="a")
    assert not await store.unpin(both.id, actor="a")
    assert (await store.effective(both.id)).source == "role"

    assigned = await audit_rows(db, "warden.identity.password_policy.assigned")
    assert [r["details"] for r in assigned] == [
        {"role": "analyst", "policy_id": str(loose.id)},
        {"role": "admin", "policy_id": str(strict.id)},
    ]
    (pin_row,) = await audit_rows(db, "warden.identity.password_policy.pinned")
    assert pin_row["resource_id"] == str(both.id)
    assert pin_row["details"] == {"policy_id": str(pinned.id)}
    assert len(await audit_rows(db, "warden.identity.password_policy.unpinned")) == 1


async def test_a_role_the_product_no_longer_declares_grants_nothing(
    db: Database, make_user: Any
) -> None:
    registry = PermissionRegistry()
    registry.register_permission("cases.read", "Read cases")
    registry.define_role("viewer", {"cases.read"})
    registry.define_role("retired", {"cases.read"})
    old = _store(db, registry)
    policy = await old.create(_settings("Retired"), priority=1, actor="a")
    await old.map_role("retired", policy.id, actor="a")
    user: User = await make_user(roles=())
    async with db.transaction() as tx:
        await tx.execute(
            "INSERT INTO warden.role_assignments (user_id, role) VALUES (%s, 'retired')",
            (user.id,),
        )
    assert (await old.effective(user.id)).source == "role"
    # The product stops declaring the role: its mapping has no effect.
    current = PermissionRegistry()
    current.register_permission("cases.read", "Read cases")
    current.define_role("viewer", {"cases.read"})
    assert (await _store(db, current).effective(user.id)).source == "default"
    with pytest.raises(PasswordPolicyError):
        await _store(db, current).map_role("retired", policy.id, actor="a")


async def test_unmapping_a_role(store: PasswordPolicies, make_user: Any) -> None:
    policy = await store.create(_settings(), priority=1, actor="a")
    await store.map_role("viewer", policy.id, actor="a")
    user: User = await make_user(roles=("viewer",))
    assert (await store.effective(user.id)).source == "role"
    await store.map_role("viewer", None, actor="a")
    assert (await store.effective(user.id)).source == "default"
    assert (await store.get(policy.id)).roles == ()


async def test_deleting_a_policy_returns_its_users_to_the_default(
    store: PasswordPolicies, make_user: Any, db: Database
) -> None:
    policy = await store.create(_settings(), priority=1, actor="a")
    await store.map_role("viewer", policy.id, actor="a")
    user: User = await make_user(roles=("viewer",))
    pinned: User = await make_user()
    await store.pin(pinned.id, policy.id, actor="a")
    # A policy pinned on a user is refused (wave 17): unpin first, deliberately.
    with pytest.raises(PasswordPolicyConflict, match="pinned on 1 user"):
        await store.delete(policy.id, actor="a")
    assert (await store.effective(pinned.id)).source == "pin"
    assert await audit_rows(db, "warden.identity.password_policy.deleted") == []
    await store.unpin(pinned.id, actor="a")
    await store.delete(policy.id, actor="a")
    assert (await store.effective(user.id)).source == "default"
    assert (await store.effective(pinned.id)).source == "default"
    (row,) = await audit_rows(db, "warden.identity.password_policy.deleted")
    assert row["details"] == {"roles_unmapped": 1, "pins_removed": 0}


async def test_pinning_an_unknown_user_or_policy_is_refused(
    store: PasswordPolicies, make_user: Any
) -> None:
    policy = await store.create(_settings(), priority=1, actor="a")
    with pytest.raises(PasswordPolicyError):
        await store.pin(uuid.uuid4(), policy.id, actor="a")
    user: User = await make_user()
    with pytest.raises(PasswordPolicyNotFound):
        await store.pin(user.id, uuid.uuid4(), actor="a")


async def test_affected_users_counts_people_with_passwords_under_the_policy(
    store: PasswordPolicies, make_user: Any
) -> None:
    default = await store.default()
    policy = await store.create(_settings(), priority=1, actor="a")
    await store.map_role("viewer", policy.id, actor="a")
    viewers = [await make_user(roles=("viewer",)) for _ in range(3)]
    others = [await make_user() for _ in range(2)]
    await make_user(roles=("viewer",), sign_in_method=SignInMethod.SSO_ONLY, password=None)
    await store.pin(others[0].id, policy.id, actor="a")
    await store.pin(viewers[0].id, default.id, actor="a")
    assert await store.affected_users(policy.id) == 3  # two viewers and one pin
    assert await store.affected_users(default.id) == 2  # one plain user and one pin
    # A user holding two mapped roles counts under the higher-priority policy only.
    lower = await store.create(_settings("Lower"), priority=50, actor="a")
    await store.map_role("analyst", lower.id, actor="a")
    await make_user(roles=("viewer", "analyst"))
    await make_user(roles=("analyst",))
    assert await store.affected_users(policy.id) == 4
    assert await store.affected_users(lower.id) == 1


async def test_a_change_on_one_replica_reaches_a_listening_replica(
    db: Database, permissions: PermissionRegistry, make_user: Any
) -> None:
    writer = _store(db, permissions)
    reader = _store(db, permissions, max_age=3600)
    user: User = await make_user(roles=("viewer",))
    assert (await reader.effective(user.id)).source == "default"
    ready = asyncio.Event()
    task = asyncio.create_task(reader.listen(ready=ready))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        assert reader.listening
        policy = await writer.create(_settings(), priority=1, actor="a")
        await writer.map_role("viewer", policy.id, actor="a")
        for _ in range(100):
            if (await reader.effective(user.id)).source == "role":
                break
            await asyncio.sleep(0.05)
        assert (await reader.effective(user.id)).policy.id == policy.id
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


async def test_without_a_listener_the_cache_expires(
    db: Database, permissions: PermissionRegistry, make_user: Any
) -> None:
    writer = _store(db, permissions)
    reader = _store(db, permissions, max_age=0.2)
    user: User = await make_user(roles=("viewer",))
    await reader.effective(user.id)
    policy = await writer.create(_settings(), priority=1, actor="a")
    await writer.map_role("viewer", policy.id, actor="a")
    await asyncio.sleep(0.3)
    assert (await reader.effective(user.id)).source == "role"


async def test_a_change_notifies_in_its_own_transaction(
    store: PasswordPolicies, db: Database
) -> None:
    async with db.connection() as conn:
        await conn.set_autocommit(True)
        await conn.execute("LISTEN warden_identity_policy")
        await store.create(_settings(), priority=1, actor="a")
        notify = await anext(conn.notifies(timeout=5))
        assert notify.payload == "password_policy"


def test_resolution_order_is_pin_then_highest_priority_role_then_default() -> None:
    def policy(name: str, priority: int | None) -> Any:
        return dataclasses.make_dataclass("P", ["id", "priority", "name"])(
            uuid.uuid4(), priority, name
        )

    default, high, low, pinned = policy("d", None), policy("h", 1), policy("l", 9), policy("p", 5)
    policies = {p.id: p for p in (default, high, low, pinned)}
    roles = {"admin": high.id, "viewer": low.id, "gone": high.id}
    declared = {"admin", "viewer"}
    assert resolve(policies, roles, default.id, None, ["viewer"], declared) == (
        low,
        "role",
        "viewer",
    )
    assert resolve(policies, roles, default.id, None, ["viewer", "admin"], declared) == (
        high,
        "role",
        "admin",
    )
    assert resolve(policies, roles, default.id, pinned.id, ["admin"], declared) == (
        pinned,
        "pin",
        None,
    )
    assert resolve(policies, roles, default.id, None, ["gone"], declared) == (
        default,
        "default",
        None,
    )
    assert resolve(policies, roles, default.id, None, [], declared) == (default, "default", None)
