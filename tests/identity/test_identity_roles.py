"""Role assignments: audited, expiring, and never leaving no administrator."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from identity_support import UserFactory, audit_rows, race

from warden.db import Database
from warden.identity import Identity, LastAdministratorError, RoleError, UserStatus

pytestmark = pytest.mark.db


async def test_assign_and_revoke_are_audited(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await identity.roles.assign(user.id, "viewer", actor="admin-1")
    assert await identity.roles.roles_of(user.id) == ["viewer"]
    assert await identity.roles.revoke(user.id, "viewer", actor="admin-1")
    assert await identity.roles.roles_of(user.id) == []
    assert not await identity.roles.revoke(user.id, "viewer", actor="admin-1")
    actions = [(r["action"], r["outcome"], r["details"]) for r in await audit_rows(db)]
    assert (
        "identity.role.assigned",
        "success",
        {"role": "viewer", "expires_at": None},
    ) in actions
    assert ("identity.role.revoked", "success", {"role": "viewer"}) in actions


async def test_users_hold_several_roles(identity: Identity, make_user: UserFactory) -> None:
    user = await make_user(roles=("viewer", "analyst"))
    assert await identity.roles.roles_of(user.id) == ["analyst", "viewer"]
    assert await identity.permissions_of(user.id) == frozenset({"cases.read", "cases.write"})


async def test_an_expired_assignment_grants_nothing(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    soon = datetime.now(UTC) + timedelta(hours=1)
    await identity.roles.assign(user.id, "analyst", actor="t", expires_at=soon)
    assert await identity.permissions_of(user.id) == frozenset({"cases.read", "cases.write"})
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.role_assignments SET expires_at = now() - interval '1 second'"
            " WHERE user_id = %s",
            (user.id,),
        )
    assert await identity.roles.roles_of(user.id) == []
    assert await identity.permissions_of(user.id) == frozenset()


async def test_undefined_roles_cannot_be_assigned(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    with pytest.raises(KeyError):
        await identity.roles.assign(user.id, "superuser", actor="t")


async def test_an_administrator_role_cannot_expire(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    with pytest.raises(RoleError, match="expiry"):
        await identity.roles.assign(
            user.id, "admin", actor="t", expires_at=datetime.now(UTC) + timedelta(days=1)
        )


async def test_the_last_administrator_cannot_be_demoted(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    admin = await make_user(roles=("admin",))
    with pytest.raises(LastAdministratorError):
        await identity.roles.revoke(admin.id, "admin", actor=str(admin.id))
    assert await identity.roles.roles_of(admin.id) == ["admin"]
    rows = await audit_rows(db, "identity.role.revoked")
    assert rows[-1]["outcome"] == "failure"
    assert rows[-1]["details"] == {"role": "admin", "reason": "last_administrator"}


async def test_an_inactive_administrator_does_not_count(
    identity: Identity, make_user: UserFactory
) -> None:
    active = await make_user(roles=("admin",))
    other = await make_user(roles=("admin",))
    await identity.users.set_status(other.id, UserStatus.SUSPENDED, actor="t")
    with pytest.raises(LastAdministratorError):
        await identity.roles.revoke(active.id, "admin", actor="t")


async def test_concurrent_demotions_cannot_remove_every_administrator(
    identity: Identity, make_user: UserFactory
) -> None:
    """Two administrators demoting each other at once: exactly one demotion succeeds."""
    for _ in range(5):
        first = await make_user(roles=("admin",))
        second = await make_user(roles=("admin",))
        others = [
            u for u in await _admins(identity) if u not in {first.id, second.id}
        ]  # earlier rounds' survivors
        for user_id in others:
            await identity.users.set_status(user_id, UserStatus.DEACTIVATED, actor="t")
        results = await race(
            lambda f=first: identity.roles.revoke(f.id, "admin", actor="t"),
            lambda s=second: identity.roles.revoke(s.id, "admin", actor="t"),
        )
        assert sorted(type(r).__name__ for r in results) == ["LastAdministratorError", "bool"]
        assert len(await _admins(identity)) == 1


async def test_concurrent_suspension_and_demotion_cannot_remove_every_administrator(
    identity: Identity, make_user: UserFactory
) -> None:
    for _ in range(5):
        first = await make_user(roles=("admin",))
        second = await make_user(roles=("admin",))
        for user_id in [u for u in await _admins(identity) if u not in {first.id, second.id}]:
            await identity.users.set_status(user_id, UserStatus.DEACTIVATED, actor="t")
        results = await race(
            lambda f=first: identity.users.set_status(f.id, UserStatus.SUSPENDED, actor="t"),
            lambda s=second: identity.roles.revoke(s.id, "admin", actor="t"),
        )
        assert sum(isinstance(r, LastAdministratorError) for r in results) == 1
        assert len(await _admins(identity)) == 1


async def _admins(identity: Identity) -> list[object]:
    async with identity.db.connection() as conn:
        cur = await conn.execute(
            "SELECT a.user_id FROM warden.role_assignments a JOIN warden.users u"
            " ON u.id = a.user_id WHERE a.role = 'admin' AND u.status = 'active'"
        )
        return [row[0] for row in await cur.fetchall()]
