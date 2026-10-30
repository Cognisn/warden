"""Users: creation, lookup, statuses, sign-in methods and passwords."""

from __future__ import annotations

import uuid

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
    rows = await audit_rows(db, "warden.identity.user.created")
    assert rows == [
        {
            "action": "warden.identity.user.created",
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
    rows = await audit_rows(db, "warden.identity.user.status_changed")
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
    rows = await audit_rows(db, "warden.identity.user.sign_in_method_changed")
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
    rows = await audit_rows(db, "warden.identity.user.status_changed")
    assert rows[-1]["outcome"] == "failure"
    assert rows[-1]["details"]["reason"] == "last_administrator"


async def test_an_administrator_can_be_suspended_while_another_remains(
    identity: Identity, make_user: UserFactory
) -> None:
    first = await make_user(roles=("admin",))
    await make_user(roles=("admin",))
    updated = await identity.users.set_status(first.id, UserStatus.SUSPENDED, actor="t")
    assert updated.status is UserStatus.SUSPENDED


# Listing


async def _set_created(db: Database, user_id: object, moment: str) -> None:
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.users SET created_at = %s::timestamptz WHERE id = %s", (moment, user_id)
        )


async def test_list_returns_every_user_oldest_first(identity: Identity, db: Database) -> None:
    first = await identity.users.create("first@example.com", actor="t")
    second = await identity.users.create("second@example.com", actor="t")
    third = await identity.users.create("third@example.com", actor="t")
    await _set_created(db, first.id, "2026-01-03T00:00:00Z")
    await _set_created(db, second.id, "2026-01-01T00:00:00Z")
    await _set_created(db, third.id, "2026-01-02T00:00:00Z")
    listed = await identity.users.list()
    assert [u.id for u in listed] == [second.id, third.id, first.id]
    assert listed == [await identity.users.get(u.id) for u in listed]


async def test_list_breaks_ties_by_id(identity: Identity, db: Database) -> None:
    made = [await identity.users.create(f"tie-{n}@example.com", actor="t") for n in range(4)]
    for user in made:
        await _set_created(db, user.id, "2026-01-01T00:00:00Z")
    listed = await identity.users.list()
    assert [u.id for u in listed] == sorted(u.id for u in made)
    assert await identity.users.list() == listed


async def test_list_filters_by_status(identity: Identity) -> None:
    active = await identity.users.create("active@example.com", actor="t")
    suspended = await identity.users.create("suspended@example.com", actor="t")
    deactivated = await identity.users.create("gone@example.com", actor="t")
    await identity.users.set_status(suspended.id, UserStatus.SUSPENDED, actor="t")
    await identity.users.set_status(deactivated.id, UserStatus.DEACTIVATED, actor="t")
    by_status = {s: [u.id for u in await identity.users.list(status=s)] for s in UserStatus}
    assert by_status == {
        UserStatus.ACTIVE: [active.id],
        UserStatus.SUSPENDED: [suspended.id],
        UserStatus.DEACTIVATED: [deactivated.id],
        UserStatus.INVITED: [],
    }
    assert len(await identity.users.list()) == 3


class _Undo(Exception):
    pass


async def test_list_reads_inside_a_callers_transaction(identity: Identity, db: Database) -> None:
    with pytest.raises(_Undo):
        async with db.transaction() as tx:
            await tx.execute(
                "INSERT INTO warden.users (email, status) VALUES ('inside@example.com', 'active')"
            )
            inside = await identity.users.list(conn=tx)
            assert [u.email for u in inside] == ["inside@example.com"]
            raise _Undo
    assert await identity.users.list() == []


# Paging


async def _paged(
    identity: Identity, limit: int, status: UserStatus | None = None
) -> list[list[uuid.UUID]]:
    pages: list[list[uuid.UUID]] = []
    after: str | None = None
    # Bounded, so a cursor that does not advance fails rather than hangs.
    for _ in range(20):
        page = await identity.users.list(status=status, limit=limit, after=after)
        assert len(page) <= limit
        if not page:
            return pages
        pages.append([u.id for u in page])
        after = identity.users.cursor(page[-1])
    raise AssertionError("paging did not reach the end")


async def test_pages_follow_the_full_order_across_ties(identity: Identity, db: Database) -> None:
    made = [await identity.users.create(f"page-{n}@example.com", actor="t") for n in range(7)]
    moments = ["2026-01-02", "2026-01-01", "2026-01-02", "2026-01-03", "2026-01-02", "2026-01-01"]
    for user, moment in zip(made, moments, strict=False):
        await _set_created(db, user.id, f"{moment}T00:00:00Z")
    everyone = [u.id for u in await identity.users.list()]
    pages = await _paged(identity, 2)
    assert [len(p) for p in pages] == [2, 2, 2, 1]
    assert [i for p in pages for i in p] == everyone


async def test_a_limit_alone_returns_the_oldest(identity: Identity, db: Database) -> None:
    made = [await identity.users.create(f"limit-{n}@example.com", actor="t") for n in range(4)]
    for user, day in zip(made, ["04", "02", "03", "01"], strict=True):
        await _set_created(db, user.id, f"2026-01-{day}T00:00:00Z")
    first = await identity.users.list(limit=3)
    assert [u.id for u in first] == [made[3].id, made[1].id, made[2].id]
    assert len(await identity.users.list(limit=10)) == 4


async def test_after_alone_returns_the_rest(identity: Identity, db: Database) -> None:
    made = [await identity.users.create(f"after-{n}@example.com", actor="t") for n in range(3)]
    for user, day in zip(made, ["03", "01", "02"], strict=True):
        await _set_created(db, user.id, f"2026-01-{day}T00:00:00Z")
    oldest = await identity.users.get(made[1].id)
    assert oldest is not None
    rest = await identity.users.list(after=identity.users.cursor(oldest))
    assert [u.id for u in rest] == [made[2].id, made[0].id]


async def test_pages_keep_the_status_filter(identity: Identity) -> None:
    made = [await identity.users.create(f"filter-{n}@example.com", actor="t") for n in range(5)]
    for user in made[1::2]:
        await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="t")
    pages = await _paged(identity, 1, status=UserStatus.ACTIVE)
    assert [i for p in pages for i in p] == [
        u.id for u in await identity.users.list(status=UserStatus.ACTIVE)
    ]
    assert len(pages) == 3


@pytest.mark.parametrize("limit", [0, -1])
async def test_a_limit_below_one_is_refused(identity: Identity, limit: int) -> None:
    with pytest.raises(UserError, match="limit"):
        await identity.users.list(limit=limit)


@pytest.mark.parametrize(
    "cursor",
    [
        "",
        "not a cursor",
        "MjAyNi0wMS0wMVQwMDowMDowMCswMDowMHxub3QtYS11dWlk",
        "MjAyNi0wMS0wMVQwMDowMDowMHwwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDA",
        "x" * 400,
    ],
)
async def test_a_malformed_cursor_is_refused(identity: Identity, cursor: str) -> None:
    with pytest.raises(UserError, match="cursor"):
        await identity.users.list(after=cursor)
