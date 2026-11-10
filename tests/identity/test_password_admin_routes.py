"""Password policy administration routes (rulings PW1, PW2, PW3 to PW6, PW8, PW11).

Policies, priorities, role mappings, pins, a user's effective policy, change
at next sign-in and affected-user counts, each behind the administration
permission and audited by the stores they call.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import PASSWORD, UserFactory, audit_rows, race
from password_admin_support import bearer, create_policy, policy_body

from warden.db import Database
from warden.identity import Identity, SignInMethod
from warden.identity.password_policy import ChangeReason

pytestmark = pytest.mark.db

ANY = "00000000-0000-4000-8000-000000000000"

# Every password policy route; {user}, {policy} and {list} are filled per test.
ROUTES = [
    ("GET", "/admin/password-policies"),
    ("POST", "/admin/password-policies"),
    ("GET", "/admin/password-policies/{policy}"),
    ("PUT", "/admin/password-policies/{policy}"),
    ("DELETE", "/admin/password-policies/{policy}"),
    ("PUT", "/admin/password-policies/{policy}/priority"),
    ("PUT", "/admin/password-policy-order"),
    ("PUT", "/admin/password-policies/{policy}/builtin-list"),
    ("PUT", "/admin/password-policies/{policy}/watch-lists/{list}"),
    ("DELETE", "/admin/password-policies/{policy}/watch-lists/{list}"),
    ("GET", "/admin/password-policies/{policy}/affected-users"),
    ("POST", "/admin/password-policies/affected-users"),
    ("PUT", "/admin/password-policy-roles/viewer"),
    ("DELETE", "/admin/password-policy-roles/viewer"),
    ("GET", "/admin/users/{user}/password-policy"),
    ("PUT", "/admin/users/{user}/password-policy"),
    ("DELETE", "/admin/users/{user}/password-policy"),
    ("PUT", "/admin/users/{user}/password-change-required"),
    pytest.param(
        "DELETE",
        "/admin/users/{user}/password-change-required",
        marks=pytest.mark.xfail(
            strict=True, reason="clearing waits on Skuld question 36 (its audit action)"
        ),
    ),
    ("GET", "/admin/watch-lists"),
    ("POST", "/admin/watch-lists"),
    ("GET", "/admin/watch-lists/{list}"),
    ("PUT", "/admin/watch-lists/{list}"),
    ("DELETE", "/admin/watch-lists/{list}"),
    ("POST", "/admin/watch-lists/{list}/entries"),
    ("POST", "/admin/watch-lists/{list}/entries/removal"),
    ("POST", "/admin/watch-lists/{list}/terms"),
    ("POST", "/admin/watch-lists/{list}/terms/removal"),
    ("GET", "/admin/password-exposures"),
]


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


@pytest.fixture
async def headers(identity: Identity, make_user: UserFactory) -> dict[str, str]:
    admin = await make_user("admin@example.com", roles=("admin",))
    return await bearer(identity, admin)


# Authorisation


@pytest.mark.parametrize(("method", "path"), ROUTES)
async def test_every_route_needs_the_permission(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory, method: str, path: str
) -> None:
    viewer = await make_user(roles=("viewer",))
    url = path.format(user=viewer.id, policy=ANY, list=ANY)
    anonymous = await client.request(method, url, json={})
    assert anonymous.status_code == 401
    forbidden = await client.request(method, url, json={}, headers=await bearer(identity, viewer))
    assert forbidden.status_code == 403
    assert forbidden.json() == {"detail": "forbidden"}


# Policies


async def test_create_read_list_and_the_seeded_default(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    listed = await client.get("/admin/password-policies", headers=headers)
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "no-store"
    (default,) = listed.json()["policies"]
    assert default["is_default"] is True and default["priority"] is None
    assert default["min_length"] == 12 and default["include_builtin"] is True

    created = await create_policy(
        client,
        headers,
        description="For administrators",
        max_repeat=3,
        passphrase={"min_length": 20, "min_words": 4, "relaxes_classes": True},
        tiers=[
            {"name": "phrase", "passphrase": True},
            {"name": "standard", "min_length": 14, "max_age_days": 365},
        ],
        history_count=5,
        min_age_hours=24,
        enforce_on_sign_in=True,
    )
    assert created["name"] == "Strict" and created["priority"] == 1 and created["version"] == 1
    assert created["passphrase"] == {"min_length": 20, "min_words": 4, "relaxes_classes": True}
    assert [t["name"] for t in created["tiers"]] == ["phrase", "standard"]
    assert created["tiers"][1] == {
        "name": "standard",
        "passphrase": False,
        "min_length": 14,
        "min_classes": 0,
        "max_age_days": 365,
    }
    assert created["roles"] == [] and created["watch_list_ids"] == []
    shown = await client.get(f"/admin/password-policies/{created['id']}", headers=headers)
    assert shown.status_code == 200 and shown.json()["policy"] == created
    listed = await client.get("/admin/password-policies", headers=headers)
    assert [p["name"] for p in listed.json()["policies"]] == ["Strict", "Default"]
    (row,) = [
        r
        for r in await audit_rows(db, "warden.identity.password_policy.created")
        if r["resource_id"] == created["id"]
    ]
    assert row["actor"] is not None and row["details"] == {"seeded": False, "version": 1}


async def test_unknown_or_malformed_policy_ids_are_404(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    for url in (f"/admin/password-policies/{uuid.uuid4()}", "/admin/password-policies/nope"):
        response = await client.get(url, headers=headers)
        assert response.status_code == 404 and response.json() == {"detail": "not found"}


@pytest.mark.parametrize(
    ("overrides", "fields"),
    [
        ({"max_length": 10}, {"max_length"}),
        ({"min_length": 4}, {"min_length"}),
        ({"min_classes": 9}, {"min_classes"}),
        (
            {
                "tiers": [
                    {"name": "standard", "min_length": 14, "max_age_days": 90},
                    {"name": "long", "min_length": 20, "min_classes": 3, "max_age_days": 365},
                    {"name": "last", "min_length": 14},
                ]
            },
            {"tiers[1]", "tiers[2]"},
        ),
        ({"tiers": [{"name": "phrase", "passphrase": True}]}, {"tiers[0].passphrase", "tiers"}),
        ({"fingerprint_enabled": True}, {"fingerprint_enabled"}),
        ({"history_count": 30, "name": ""}, {"history_count", "name"}),
        ({"hibp_on_unavailable": "sometimes"}, {"hibp_on_unavailable"}),
        ({"min_length": "fourteen"}, {"min_length"}),
        ({"priority": 0}, {"priority"}),
        ({"watch_list_ids": ["not-a-uuid"]}, {"watch_list_ids"}),
    ],
)
async def test_inconsistent_rules_are_refused_field_by_field(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    overrides: dict[str, Any],
    fields: set[str],
) -> None:
    response = await client.post(
        "/admin/password-policies", json=policy_body(**overrides), headers=headers
    )
    assert response.status_code == 400
    body = response.json()
    assert body["detail"] == "the password policy is not valid"
    assert {e["field"] for e in body["errors"]} == fields
    assert all(isinstance(e["message"], str) and e["message"] for e in body["errors"])
    listed = await client.get("/admin/password-policies", headers=headers)
    assert [p["name"] for p in listed.json()["policies"]] == ["Default"]


async def test_a_body_that_is_not_a_policy_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    for body in (b"[]", b"not json", b'{"name": "x", "min_length": 14, "colour": "blue"}'):
        response = await client.post(
            "/admin/password-policies",
            content=body,
            headers={**headers, "content-type": "application/json"},
        )
        assert response.status_code == 400
        assert "blue" not in response.text and "colour" not in response.text


async def test_a_watch_list_that_does_not_exist_cannot_be_attached_at_creation(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.post(
        "/admin/password-policies",
        json=policy_body(watch_list_ids=[str(uuid.uuid4())]),
        headers=headers,
    )
    assert response.status_code == 400
    assert [e["field"] for e in response.json()["errors"]] == ["watch_list_ids"]


async def test_a_name_or_priority_in_use_is_a_409(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await create_policy(client, headers)
    for body in (policy_body(priority=2), policy_body(name="Other")):
        response = await client.post("/admin/password-policies", json=body, headers=headers)
        assert response.status_code == 409
        assert response.json() == {"detail": "that name or priority is already in use"}


async def test_update_round_trip_keeps_omitted_settings(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    made = await client.post(
        "/admin/watch-lists",
        json={"name": "Local", "reason": "r", "kind": "manual"},
        headers=headers,
    )
    list_id = made.json()["watch_list"]["id"]
    created = await create_policy(client, headers, history_count=3, watch_list_ids=[list_id])
    response = await client.put(
        f"/admin/password-policies/{created['id']}",
        json={"version": 1, "min_length": 16, "description": "Longer"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    updated = response.json()["policy"]
    assert updated["version"] == 2 and updated["min_length"] == 16
    assert updated["description"] == "Longer"
    assert updated["history_count"] == 3 and updated["min_classes"] == 2
    assert updated["priority"] == 1
    # Settings left out are kept: above all, the lists a policy checks.
    assert updated["watch_list_ids"] == [list_id]
    (row,) = await audit_rows(db, "warden.identity.password_policy.updated")
    assert row["resource_id"] == created["id"]
    assert row["details"] == {"fields": ["rules", "description"], "version": 2}


async def test_a_stale_update_is_a_409_and_changes_nothing(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    created = await create_policy(client, headers)
    url = f"/admin/password-policies/{created['id']}"
    first = await client.put(url, json={"version": 1, "min_length": 15}, headers=headers)
    assert first.status_code == 200
    stale = await client.put(url, json={"version": 1, "min_length": 20}, headers=headers)
    assert stale.status_code == 409
    assert stale.json() == {"detail": "the policy changed since it was read"}
    assert (await client.get(url, headers=headers)).json()["policy"]["min_length"] == 15
    missing = await client.put(url, json={"min_length": 20}, headers=headers)
    assert missing.status_code == 400
    assert [e["field"] for e in missing.json()["errors"]] == ["version"]


async def test_the_default_can_be_updated_but_not_deleted_or_prioritised(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    (default,) = (await client.get("/admin/password-policies", headers=headers)).json()["policies"]
    url = f"/admin/password-policies/{default['id']}"
    updated = await client.put(url, json={"version": 1, "min_length": 13}, headers=headers)
    assert updated.status_code == 200 and updated.json()["policy"]["is_default"] is True
    refused = await client.delete(url, headers=headers)
    assert refused.status_code == 409
    assert refused.json() == {"detail": "the default policy cannot be deleted"}
    assert (await client.get(url, headers=headers)).status_code == 200
    assert await audit_rows(db, "warden.identity.password_policy.deleted") == []
    moved = await client.put(f"{url}/priority", json={"priority": 3}, headers=headers)
    assert moved.status_code == 409
    assert moved.json() == {"detail": "the default policy has no priority"}
    given = await client.put(url, json={"version": 2, "priority": 4}, headers=headers)
    assert given.status_code == 400


async def test_delete_round_trip_and_a_pinned_policy_is_refused(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    make_user: UserFactory,
    identity: Identity,
    db: Database,
) -> None:
    created = await create_policy(client, headers)
    url = f"/admin/password-policies/{created['id']}"
    user = await make_user()
    pinned = await client.put(
        f"/admin/users/{user.id}/password-policy",
        json={"policy_id": created["id"]},
        headers=headers,
    )
    assert pinned.status_code == 200
    refused = await client.delete(url, headers=headers)
    assert refused.status_code == 409
    assert refused.json() == {"detail": "the policy is pinned on 1 user; unpin them first"}
    assert (await identity.password_policies.effective(user.id)).source == "pin"
    unpinned = await client.delete(f"/admin/users/{user.id}/password-policy", headers=headers)
    assert unpinned.status_code == 204
    deleted = await client.delete(url, headers=headers)
    assert deleted.status_code == 204
    assert (await client.get(url, headers=headers)).status_code == 404
    assert (await client.delete(url, headers=headers)).status_code == 404
    (row,) = await audit_rows(db, "warden.identity.password_policy.deleted")
    assert row["resource_id"] == created["id"]


async def test_priority_round_trip_and_reorder(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    first = await create_policy(client, headers, name="First", priority=1)
    second = await create_policy(client, headers, name="Second", priority=2)
    moved = await client.put(
        f"/admin/password-policies/{second['id']}/priority", json={"priority": 5}, headers=headers
    )
    assert moved.status_code == 200 and moved.json()["policy"]["priority"] == 5
    taken = await client.put(
        f"/admin/password-policies/{second['id']}/priority", json={"priority": 1}, headers=headers
    )
    assert taken.status_code == 409
    assert taken.json() == {"detail": "that priority is already in use"}
    for bad in ({"priority": 0}, {"priority": "1"}, {}):
        response = await client.put(
            f"/admin/password-policies/{second['id']}/priority", json=bad, headers=headers
        )
        assert response.status_code == 400
    order = await client.put(
        "/admin/password-policy-order",
        json={"policy_ids": [second["id"], first["id"]]},
        headers=headers,
    )
    assert order.status_code == 200
    assert [(p["name"], p["priority"]) for p in order.json()["policies"]] == [
        ("Second", 1),
        ("First", 2),
    ]
    partial = await client.put(
        "/admin/password-policy-order", json={"policy_ids": [first["id"]]}, headers=headers
    )
    assert partial.status_code == 400


async def test_concurrent_priority_changes_leave_distinct_priorities(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    first = await create_policy(client, headers, name="First", priority=1)
    second = await create_policy(client, headers, name="Second", priority=2)

    async def move(policy: dict[str, Any]) -> int:
        response = await client.put(
            f"/admin/password-policies/{policy['id']}/priority",
            json={"priority": 7},
            headers=headers,
        )
        return response.status_code

    statuses = await race(lambda: move(first), lambda: move(second))
    assert sorted(statuses) == [200, 409]
    policies = (await client.get("/admin/password-policies", headers=headers)).json()["policies"]
    priorities = [p["priority"] for p in policies if not p["is_default"]]
    assert len(set(priorities)) == len(priorities) == 2 and 7 in priorities


# Role mappings


async def test_only_declared_roles_can_be_mapped(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    created = await create_policy(client, headers)
    body = {"policy_id": created["id"]}
    mapped = await client.put("/admin/password-policy-roles/viewer", json=body, headers=headers)
    assert mapped.status_code == 204
    shown = await client.get(f"/admin/password-policies/{created['id']}", headers=headers)
    assert shown.json()["policy"]["roles"] == ["viewer"]
    undeclared = await client.put(
        "/admin/password-policy-roles/auditor", json=body, headers=headers
    )
    assert undeclared.status_code == 400
    assert undeclared.json() == {"detail": "the product declares no such role"}
    (row,) = await audit_rows(db, "warden.identity.password_policy.assigned")
    assert row["details"] == {"role": "viewer", "policy_id": created["id"]}
    unmapped = await client.delete("/admin/password-policy-roles/viewer", headers=headers)
    assert unmapped.status_code == 204
    shown = await client.get(f"/admin/password-policies/{created['id']}", headers=headers)
    assert shown.json()["policy"]["roles"] == []


async def test_a_role_cannot_be_mapped_to_the_default_or_a_missing_policy(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    (default,) = (await client.get("/admin/password-policies", headers=headers)).json()["policies"]
    to_default = await client.put(
        "/admin/password-policy-roles/viewer", json={"policy_id": default["id"]}, headers=headers
    )
    assert to_default.status_code == 409
    for body in ({"policy_id": str(uuid.uuid4())}, {"policy_id": "x"}, {}):
        response = await client.put(
            "/admin/password-policy-roles/viewer", json=body, headers=headers
        )
        assert response.status_code == 400


# Users: pins, the effective policy and change at next sign-in


async def test_pin_overrides_the_role_and_the_reason_is_shown(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    make_user: UserFactory,
    db: Database,
) -> None:
    by_role = await create_policy(client, headers, name="Analysts", priority=2)
    pinned_policy = await create_policy(client, headers, name="Pinned", priority=3)
    await client.put(
        "/admin/password-policy-roles/analyst", json={"policy_id": by_role["id"]}, headers=headers
    )
    user = await make_user(roles=("analyst",))
    url = f"/admin/users/{user.id}/password-policy"

    shown = (await client.get(url, headers=headers)).json()
    assert shown["applies"] is True
    assert shown["policy"] == {"id": by_role["id"], "name": "Analysts"}
    assert shown["source"] == "role" and shown["role"] == "analyst"

    pinned = await client.put(url, json={"policy_id": pinned_policy["id"]}, headers=headers)
    assert pinned.status_code == 200
    assert pinned.json()["policy"] == {"id": pinned_policy["id"], "name": "Pinned"}
    assert pinned.json()["source"] == "pin" and pinned.json()["role"] is None
    (row,) = await audit_rows(db, "warden.identity.password_policy.pinned")
    assert row["resource_id"] == str(user.id)
    assert row["details"] == {"policy_id": pinned_policy["id"]}

    assert (await client.delete(url, headers=headers)).status_code == 204
    assert (await client.delete(url, headers=headers)).status_code == 404
    assert (await client.get(url, headers=headers)).json()["source"] == "role"
    other = await make_user()
    assert (await client.get(f"/admin/users/{other.id}/password-policy", headers=headers)).json()[
        "source"
    ] == "default"


async def test_pinning_needs_a_known_user_and_policy(
    client: httpx.AsyncClient, headers: dict[str, str], make_user: UserFactory
) -> None:
    created = await create_policy(client, headers)
    missing_user = await client.put(
        f"/admin/users/{uuid.uuid4()}/password-policy",
        json={"policy_id": created["id"]},
        headers=headers,
    )
    assert missing_user.status_code == 404
    user = await make_user()
    for body in ({"policy_id": str(uuid.uuid4())}, {"policy_id": 3}, {}):
        response = await client.put(
            f"/admin/users/{user.id}/password-policy", json=body, headers=headers
        )
        assert response.status_code == 400
    assert (
        await client.get(f"/admin/users/{uuid.uuid4()}/password-policy", headers=headers)
    ).status_code == 404


async def test_the_effective_view_shows_tier_expiry_and_change(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    make_user: UserFactory,
    identity: Identity,
) -> None:
    from datetime import UTC, datetime, timedelta

    user = await make_user()
    set_at = datetime(2026, 11, 1, tzinfo=UTC)
    await identity.password_states.record_set(
        user.id, tier="standard", set_at=set_at, expires_at=set_at + timedelta(days=90),
        fingerprint=None,
    )  # fmt: skip
    shown = (await client.get(f"/admin/users/{user.id}/password-policy", headers=headers)).json()
    assert shown["tier"] == "standard"
    assert shown["password_set_at"] == set_at.isoformat()
    assert shown["expires_at"] == (set_at + timedelta(days=90)).isoformat()
    assert shown["change_required"] is False and shown["change_reason"] is None
    sso = await make_user(password=None, sign_in_method=SignInMethod.SSO_ONLY)
    shown = (await client.get(f"/admin/users/{sso.id}/password-policy", headers=headers)).json()
    assert shown["applies"] is False and shown["policy"] is None and shown["source"] is None


async def test_change_at_next_sign_in_sets_the_flag_with_reason_administrator(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    make_user: UserFactory,
    identity: Identity,
    db: Database,
) -> None:
    user = await make_user()
    url = f"/admin/users/{user.id}/password-change-required"
    response = await client.put(url, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"change_required": True, "change_reason": "administrator"}
    state = await identity.password_states.get(user.id)
    assert state is not None and state.change_reason is ChangeReason.ADMINISTRATOR
    (row,) = await audit_rows(db, "warden.identity.password.change_required")
    assert row["resource_id"] == str(user.id) and row["actor"] is not None
    assert row["details"] == {
        "reason": "administrator",
        "trigger": "administrator",
        "already_required": False,
    }
    # An earlier reason stands; the answer says which.
    await identity.password_states.clear_change(user.id)
    await identity.password_states.require_change(user.id, ChangeReason.EXPIRED)
    again = await client.put(url, headers=headers)
    assert again.json() == {"change_required": True, "change_reason": "expired"}
    shown = (await client.get(f"/admin/users/{user.id}/password-policy", headers=headers)).json()
    assert shown["change_required"] is True and shown["change_reason"] == "expired"


async def test_change_at_next_sign_in_needs_a_password_user(
    client: httpx.AsyncClient, headers: dict[str, str], make_user: UserFactory
) -> None:
    sso = await make_user(password=None, sign_in_method=SignInMethod.SSO_ONLY)
    response = await client.put(f"/admin/users/{sso.id}/password-change-required", headers=headers)
    assert response.status_code == 409
    assert response.json() == {"detail": "the user does not sign in with a password"}
    missing = await client.put(
        f"/admin/users/{uuid.uuid4()}/password-change-required", headers=headers
    )
    assert missing.status_code == 404


async def test_the_user_view_gains_the_password_fields(
    client: httpx.AsyncClient, headers: dict[str, str], make_user: UserFactory
) -> None:
    user = await make_user(roles=("viewer",))
    body = (await client.get(f"/admin/users/{user.id}", headers=headers)).json()
    assert set(body) == {"user", "roles", "webauthn_credentials", "password"}
    assert body["password"]["source"] == "default"
    assert body["password"]["change_required"] is False


# Affected users


async def test_affected_users_now_and_for_a_proposed_change(
    client: httpx.AsyncClient, headers: dict[str, str], make_user: UserFactory
) -> None:
    analysts = await create_policy(client, headers, name="Analysts", priority=2)
    await client.put(
        "/admin/password-policy-roles/analyst", json={"policy_id": analysts["id"]}, headers=headers
    )
    for _ in range(2):
        await make_user(roles=("analyst",))
    for _ in range(3):
        await make_user(roles=("viewer",))
    await make_user(roles=("viewer", "analyst"))
    await make_user(password=None, sign_in_method=SignInMethod.SSO_ONLY, roles=("analyst",))

    now = await client.get(
        f"/admin/password-policies/{analysts['id']}/affected-users", headers=headers
    )
    assert now.status_code == 200 and now.json() == {"affected_users": 3}

    async def propose(body: dict[str, Any]) -> httpx.Response:
        return await client.post(
            "/admin/password-policies/affected-users", json=body, headers=headers
        )

    widened = await propose({"policy_id": analysts["id"], "roles": ["analyst", "viewer"]})
    assert widened.json() == {"current": 3, "proposed": 6}
    # A new policy mapped from viewer at a higher priority than Analysts takes
    # the user holding both roles too.
    new = await propose({"priority": 1, "roles": ["viewer"]})
    assert new.json() == {"current": 0, "proposed": 4}
    lower = await propose({"priority": 9, "roles": ["viewer"]})
    assert lower.json() == {"current": 0, "proposed": 3}
    for bad in (
        {"priority": 1, "roles": ["auditor"]},
        {"roles": ["viewer"]},
        {"policy_id": str(uuid.uuid4()), "roles": []},
        {"policy_id": analysts["id"], "roles": "viewer"},
    ):
        assert (await propose(bad)).status_code == 400


# Watch lists on a policy


async def test_attach_detach_and_the_builtin_list(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    created = await create_policy(client, headers)
    made = await client.post(
        "/admin/watch-lists",
        json={"name": "Local", "reason": "This password is banned here", "kind": "manual"},
        headers=headers,
    )
    list_id = made.json()["watch_list"]["id"]
    url = f"/admin/password-policies/{created['id']}/watch-lists/{list_id}"
    attached = await client.put(url, headers=headers)
    assert attached.status_code == 200
    assert attached.json()["policy"]["watch_list_ids"] == [list_id]
    assert attached.json()["policy"]["version"] == 2
    missing = await client.put(
        f"/admin/password-policies/{created['id']}/watch-lists/{uuid.uuid4()}", headers=headers
    )
    assert missing.status_code == 404
    detached = await client.delete(url, headers=headers)
    assert detached.status_code == 200 and detached.json()["policy"]["watch_list_ids"] == []

    builtin = f"/admin/password-policies/{created['id']}/builtin-list"
    off = await client.put(builtin, json={"include": False}, headers=headers)
    assert off.status_code == 200 and off.json()["policy"]["include_builtin"] is False
    on = await client.put(builtin, json={"include": True}, headers=headers)
    assert on.json()["policy"]["include_builtin"] is True
    assert (await client.put(builtin, json={"include": "no"}, headers=headers)).status_code == 400
    updated = await audit_rows(db, "warden.identity.password_policy.updated")
    assert [r["details"]["fields"] for r in updated] == [
        ["watch_list_ids"],
        ["watch_list_ids"],
        ["include_builtin"],
        ["include_builtin"],
    ]


async def test_responses_hold_nothing_secret(
    client: httpx.AsyncClient, headers: dict[str, str], make_user: UserFactory
) -> None:
    user = await make_user()
    texts = [
        (await client.get("/admin/password-policies", headers=headers)).text,
        (await client.get(f"/admin/users/{user.id}/password-policy", headers=headers)).text,
        (await client.get(f"/admin/users/{user.id}", headers=headers)).text,
    ]
    for text in texts:
        for fragment in (PASSWORD, "password_hash", "fingerprint_sealed", "$argon2"):
            assert fragment not in text
