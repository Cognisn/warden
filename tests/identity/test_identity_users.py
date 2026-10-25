"""Users: creation, lookup, statuses, sign-in methods and passwords."""

from __future__ import annotations

import pytest
from identity_support import FAST_HASHER, PASSWORD, UserFactory, audit_rows

from warden.db import Database
from warden.identity import Identity, SignInMethod, UserError, UserStatus

pytestmark = pytest.mark.db


async def test_create_and_look_up(identity: Identity, db: Database) -> None:
    user = await identity.users.create("Alice@Example.com", actor="admin-1", display_name="Alice")
    assert user.status is UserStatus.ACTIVE
    assert user.sign_in_method is SignInMethod.PASSWORD_AND_SSO
    assert not user.has_password
    assert await identity.users.get(user.id) == user
    assert await identity.users.get_by_email("alice@example.COM") == user
    rows = await audit_rows(db, "identity.user.created")
    assert rows == [
        {
            "action": "identity.user.created",
            "outcome": "success",
            "actor": "admin-1",
            "resource_type": "user",
            "resource_id": str(user.id),
            "details": {"status": "active", "sign_in_method": "password_and_sso"},
        }
    ]


async def test_email_must_be_unique_ignoring_case(identity: Identity) -> None:
    await identity.users.create("bob@example.com", actor="t")
    with pytest.raises(UserError, match="already exists"):
        await identity.users.create("BOB@example.com", actor="t")


@pytest.mark.parametrize(
    "email",
    [
        "",
        "no-at-sign",
        "two@@example.com",
        "trailing@example.com\n",
        " lead@example.com",
        "a b@x.y",
    ],
)
async def test_malformed_email_is_refused(identity: Identity, email: str) -> None:
    with pytest.raises(UserError, match="email"):
        await identity.users.create(email, actor="t")


async def test_password_is_hashed_with_argon2id(identity: Identity, db: Database) -> None:
    user = await identity.users.create("carol@example.com", actor="t", password=PASSWORD)
    assert user.has_password
    async with db.connection() as conn:
        cur = await conn.execute("SELECT password_hash FROM warden.users WHERE id = %s", (user.id,))
        row = await cur.fetchone()
    assert row is not None and row[0].startswith("$argon2id$")
    assert (await FAST_HASHER.verify(row[0], PASSWORD)).ok


async def test_password_policy_is_enforced(identity: Identity, make_user: UserFactory) -> None:
    with pytest.raises(UserError, match="password"):
        await identity.users.create("dave@example.com", actor="t", password="short")
    user = await make_user()
    with pytest.raises(UserError, match="password"):
        await identity.users.set_password(user.id, "x" * 1025, actor="t")


async def test_status_change_is_audited(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    updated = await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="admin-1")
    assert updated.status is UserStatus.SUSPENDED
    rows = await audit_rows(db, "identity.user.status_changed")
    assert rows[-1]["details"] == {"from": "active", "to": "suspended"}
    assert rows[-1]["actor"] == "admin-1"


async def test_sign_in_method_change_is_audited(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    updated = await identity.users.set_sign_in_method(
        user.id, SignInMethod.SSO_ONLY, actor="admin-1"
    )
    assert updated.sign_in_method is SignInMethod.SSO_ONLY
    rows = await audit_rows(db, "identity.user.sign_in_method_changed")
    assert rows[-1]["details"] == {"from": "password_and_sso", "to": "sso_only"}


async def test_unknown_user_changes_are_refused(identity: Identity) -> None:
    import uuid

    with pytest.raises(UserError, match="does not exist"):
        await identity.users.set_status(uuid.uuid4(), UserStatus.SUSPENDED, actor="t")


@pytest.mark.parametrize("status", [UserStatus.SUSPENDED, UserStatus.DEACTIVATED])
async def test_the_last_administrator_cannot_be_suspended_or_deactivated(
    identity: Identity, db: Database, make_user: UserFactory, status: UserStatus
) -> None:
    from warden.identity import LastAdministratorError

    admin = await make_user(roles=("admin",))
    with pytest.raises(LastAdministratorError):
        await identity.users.set_status(admin.id, status, actor="admin-2")
    current = await identity.users.get(admin.id)
    assert current is not None and current.status is UserStatus.ACTIVE
    rows = await audit_rows(db, "identity.user.status_changed")
    assert rows[-1]["outcome"] == "failure"
    assert rows[-1]["details"]["reason"] == "last_administrator"


async def test_an_administrator_can_be_suspended_while_another_remains(
    identity: Identity, make_user: UserFactory
) -> None:
    first = await make_user(roles=("admin",))
    await make_user(roles=("admin",))
    updated = await identity.users.set_status(first.id, UserStatus.SUSPENDED, actor="t")
    assert updated.status is UserStatus.SUSPENDED
