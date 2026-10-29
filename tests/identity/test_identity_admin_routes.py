"""Administration routes: users, roles, invitations and API keys, each behind a permission."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows

from warden.db import Database
from warden.identity import Identity, PermissionRegistry, User, UserStatus

pytestmark = pytest.mark.db

ROUTES = [
    ("GET", "/admin/users"),
    ("GET", "/admin/users/{user}"),
    ("POST", "/admin/users/{user}/status"),
    ("POST", "/admin/users/{user}/sign-in-method"),
    ("POST", "/admin/users/{user}/password-reset"),
    ("GET", "/admin/roles"),
    ("PUT", "/admin/users/{user}/roles/viewer"),
    ("DELETE", "/admin/users/{user}/roles/viewer"),
    ("GET", "/admin/invitations"),
    ("POST", "/admin/invitations"),
    ("POST", "/admin/invitations/{user}/resend"),
    ("DELETE", "/admin/invitations/{user}"),
    ("GET", "/admin/api-keys"),
    ("POST", "/admin/api-keys"),
    ("DELETE", "/admin/api-keys/{user}"),
]


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


async def _bearer(identity: Identity, user: User) -> dict[str, str]:
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is not None
    return {"authorization": f"Bearer {result.tokens.access_token}"}


@pytest.fixture
async def admin(identity: Identity, make_user: UserFactory) -> tuple[User, dict[str, str]]:
    user = await make_user("admin@example.com", roles=("admin",))
    return user, await _bearer(identity, user)


# Authorisation


@pytest.mark.parametrize(("method", "path"), ROUTES)
async def test_every_route_needs_the_permission(
    identity: Identity,
    client: httpx.AsyncClient,
    make_user: UserFactory,
    method: str,
    path: str,
) -> None:
    viewer = await make_user(roles=("viewer",))
    url = path.format(user=viewer.id)
    anonymous = await client.request(method, url)
    assert anonymous.status_code == 401
    forbidden = await client.request(method, url, headers=await _bearer(identity, viewer))
    assert forbidden.status_code == 403


def test_the_permission_must_be_registered(identity: Identity) -> None:
    with pytest.raises(ValueError, match="registered"):
        identity.admin_router(permission="no.such")


async def test_separate_permissions_per_area(
    identity: Identity, permissions: PermissionRegistry, make_user: UserFactory
) -> None:
    permissions.register_permission("keys.manage", "Manage API keys")
    permissions.define_role("key-admin", {"keys.manage", "cases.read"})
    app = FastAPI()
    identity.install(app)
    app.include_router(
        identity.admin_router(permission="users.manage", api_keys="keys.manage"), prefix="/admin"
    )
    key_admin = await make_user(roles=("key-admin",))
    headers = await _bearer(identity, key_admin)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        assert (await c.get("/admin/api-keys", headers=headers)).status_code == 200
        assert (await c.get("/admin/users", headers=headers)).status_code == 403


# Users


async def test_listing_users_keeps_its_response(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    identity: Identity,
) -> None:
    # Pins the whole response, oldest first, so moving the query into
    # Users.list cannot change what the route returns.
    admin_user, headers = admin
    olive = await make_user("olive@example.com", display_name="Olive")
    sam = await make_user("sam@example.com")
    await identity.users.set_status(sam.id, UserStatus.SUSPENDED, actor="test")
    sam_now = await identity.users.get(sam.id)
    assert sam_now is not None

    def view(user: User) -> dict[str, object]:
        return {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "status": user.status.value,
            "sign_in_method": user.sign_in_method.value,
            "has_password": user.has_password,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat(),
        }

    listed = await client.get("/admin/users", headers=headers)
    assert listed.status_code == 200
    assert listed.json() == {"users": [view(admin_user), view(olive), view(sam_now)]}
    suspended = await client.get("/admin/users?status=suspended", headers=headers)
    assert suspended.json() == {"users": [view(sam_now)]}
    active = await client.get("/admin/users?status=active", headers=headers)
    assert active.json() == {"users": [view(admin_user), view(olive)]}
    assert (await client.get("/admin/users?status=invited", headers=headers)).json() == {
        "users": []
    }


async def test_list_and_show_users(
    client: httpx.AsyncClient, admin: tuple[User, dict[str, str]], make_user: UserFactory
) -> None:
    _, headers = admin
    other = await make_user("other@example.com", roles=("viewer",), display_name="Olive")
    listed = await client.get("/admin/users", headers=headers)
    assert listed.status_code == 200
    emails = [u["email"] for u in listed.json()["users"]]
    assert "other@example.com" in emails and "admin@example.com" in emails
    assert "password_hash" not in listed.text
    shown = await client.get(f"/admin/users/{other.id}", headers=headers)
    body = shown.json()
    assert body["user"]["display_name"] == "Olive"
    assert body["user"]["status"] == "active"
    assert [a["role"] for a in body["roles"]] == ["viewer"]
    suspended = await client.get("/admin/users?status=suspended", headers=headers)
    assert suspended.json()["users"] == []
    assert (await client.get(f"/admin/users/{uuid.uuid4()}", headers=headers)).status_code == 404
    assert (await client.get("/admin/users/not-a-uuid", headers=headers)).status_code == 404
    assert (await client.get("/admin/users?status=bogus", headers=headers)).status_code == 400


async def test_change_status_and_method(
    client: httpx.AsyncClient,
    db: Database,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
) -> None:
    me, headers = admin
    other = await make_user()
    suspended = await client.post(
        f"/admin/users/{other.id}/status", headers=headers, json={"status": "suspended"}
    )
    assert suspended.status_code == 200 and suspended.json()["user"]["status"] == "suspended"
    method = await client.post(
        f"/admin/users/{other.id}/sign-in-method",
        headers=headers,
        json={"sign_in_method": "sso_only"},
    )
    assert method.json()["user"]["sign_in_method"] == "sso_only"
    bad = await client.post(
        f"/admin/users/{other.id}/status", headers=headers, json={"status": "deleted"}
    )
    assert bad.status_code == 400
    # The last administrator cannot suspend themselves.
    last = await client.post(
        f"/admin/users/{me.id}/status", headers=headers, json={"status": "suspended"}
    )
    assert last.status_code == 409
    changes = await audit_rows(db, "warden.identity.user.status_changed")
    assert [(r["actor"], r["outcome"]) for r in changes] == [
        (str(me.id), "success"),
        (str(me.id), "failure"),
    ]


async def test_send_a_password_reset(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    mail: RecordingSender,
    identity: Identity,
) -> None:
    _, headers = admin
    user = await make_user()
    sent = await client.post(f"/admin/users/{user.id}/password-reset", headers=headers)
    assert sent.status_code == 202
    assert [m.to for m in mail.sent] == [user.email]
    await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="t")
    refused = await client.post(f"/admin/users/{user.id}/password-reset", headers=headers)
    assert refused.status_code == 409
    mail.fail = True
    await identity.users.set_status(user.id, UserStatus.ACTIVE, actor="t")
    failed = await client.post(f"/admin/users/{user.id}/password-reset", headers=headers)
    assert failed.status_code == 502


# Roles


async def test_roles_are_listed_assigned_and_revoked(
    client: httpx.AsyncClient,
    db: Database,
    identity: Identity,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
) -> None:
    me, headers = admin
    listed = (await client.get("/admin/roles", headers=headers)).json()
    assert {r["name"] for r in listed["roles"]} == {"viewer", "analyst", "admin"}
    assert listed["permissions"]["cases.read"] == "Read cases"
    user = await make_user()
    expiry = (datetime.now(UTC) + timedelta(days=3)).isoformat()
    assigned = await client.put(
        f"/admin/users/{user.id}/roles/analyst", headers=headers, json={"expires_at": expiry}
    )
    assert assigned.status_code == 204
    [assignment] = await identity.roles.assignments_of(user.id)
    assert assignment.role == "analyst" and assignment.granted_by == str(me.id)
    assert assignment.expires_at == datetime.fromisoformat(expiry)
    assert (
        await client.put(f"/admin/users/{user.id}/roles/nope", headers=headers, json={})
    ).status_code == 400
    assert (
        await client.put(
            f"/admin/users/{user.id}/roles/analyst",
            headers=headers,
            json={"expires_at": "tomorrow"},
        )
    ).status_code == 400
    revoked = await client.delete(f"/admin/users/{user.id}/roles/analyst", headers=headers)
    assert revoked.status_code == 204
    gone = await client.delete(f"/admin/users/{user.id}/roles/analyst", headers=headers)
    assert gone.status_code == 404
    last = await client.delete(f"/admin/users/{me.id}/roles/admin", headers=headers)
    assert last.status_code == 409
    rows = await audit_rows(db, "warden.identity.role.assigned")
    assert rows[-1]["actor"] == str(me.id)


# Invitations


async def test_invitations_are_created_listed_resent_and_revoked(
    client: httpx.AsyncClient,
    db: Database,
    admin: tuple[User, dict[str, str]],
    mail: RecordingSender,
) -> None:
    me, headers = admin
    expiry = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    created = await client.post(
        "/admin/invitations",
        headers=headers,
        json={
            "email": "guest@example.com",
            "display_name": "Guest",
            "roles": [{"role": "viewer"}, {"role": "analyst", "expires_at": expiry}],
        },
    )
    assert created.status_code == 201
    body = created.json()
    user_id = body["user_id"]
    assert body["email"] == "guest@example.com"
    assert body["roles"] == [
        {"role": "analyst", "expires_at": expiry},
        {"role": "viewer", "expires_at": None},
    ]
    assert "token" not in created.text and mail.token() not in created.text
    pending = (await client.get("/admin/invitations", headers=headers)).json()["invitations"]
    assert [p["user"]["id"] for p in pending] == [user_id]
    resent = await client.post(f"/admin/invitations/{user_id}/resend", headers=headers)
    assert resent.status_code == 200 and len(mail.sent) == 2
    revoked = await client.delete(f"/admin/invitations/{user_id}", headers=headers)
    assert revoked.status_code == 204
    again = await client.delete(f"/admin/invitations/{user_id}", headers=headers)
    assert again.status_code == 409
    for action in ("created", "resent", "revoked"):
        rows = await audit_rows(db, f"warden.identity.invitation.{action}")
        assert rows[0]["actor"] == str(me.id), action


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"email": "admin@example.com"}, 409),
        ({"email": "not an email"}, 400),
        ({"email": "x@example.com", "roles": [{"role": "nope"}]}, 400),
        ({"email": "x@example.com", "roles": "viewer"}, 400),
        ({"email": "x@example.com", "sign_in_method": "magic"}, 400),
        ({}, 400),
    ],
)
async def test_bad_invitations_are_refused(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    body: dict[str, object],
    status: int,
) -> None:
    _, headers = admin
    assert (await client.post("/admin/invitations", headers=headers, json=body)).status_code == (
        status
    )


async def test_an_undeliverable_invitation_is_a_502(
    client: httpx.AsyncClient, admin: tuple[User, dict[str, str]], mail: RecordingSender
) -> None:
    _, headers = admin
    mail.fail = True
    response = await client.post(
        "/admin/invitations", headers=headers, json={"email": "lost@example.com"}
    )
    assert response.status_code == 502
    assert "mail.example.com" not in response.text


# API keys


async def test_api_keys_are_created_listed_and_revoked(
    client: httpx.AsyncClient,
    db: Database,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
) -> None:
    me, headers = admin
    user = await make_user(roles=("analyst",))
    created = await client.post(
        "/admin/api-keys",
        headers=headers,
        json={"user_id": str(user.id), "name": "ci", "scopes": ["cases.read"]},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["key"].startswith("wdn_")
    key_id = body["api_key"]["id"]
    assert body["api_key"]["scopes"] == ["cases.read"]
    listed = (await client.get(f"/admin/api-keys?user_id={user.id}", headers=headers)).json()
    assert [k["id"] for k in listed["api_keys"]] == [key_id]
    assert body["key"] not in str(listed)
    # The new key authenticates against the admin routes too, limited to its scope.
    key_headers = {"authorization": f"Bearer {body['key']}"}
    assert (await client.get("/admin/users", headers=key_headers)).status_code == 403
    assert (await client.delete(f"/admin/api-keys/{key_id}", headers=headers)).status_code == 204
    assert (await client.delete(f"/admin/api-keys/{key_id}", headers=headers)).status_code == 404
    rows = await audit_rows(db, "warden.identity.api_key.created")
    assert rows[0]["actor"] == str(me.id)


@pytest.mark.parametrize(
    "body",
    [
        {"name": "ci", "scopes": ["cases.read"]},
        {"user_id": "nope", "name": "ci", "scopes": ["cases.read"]},
        {"user_id": "{user}", "name": "ci", "scopes": ["users.manage"]},
        {"user_id": "{user}", "name": "ci", "scopes": "cases.read"},
        {"user_id": "{user}", "name": "ci", "scopes": ["cases.read"], "expires_at": "soon"},
    ],
)
async def test_bad_api_keys_are_refused(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    body: dict[str, object],
) -> None:
    _, headers = admin
    user = await make_user(roles=("viewer",))
    filled = {k: (v.format(user=user.id) if isinstance(v, str) else v) for k, v in body.items()}
    response = await client.post("/admin/api-keys", headers=headers, json=filled)
    assert response.status_code == 400
