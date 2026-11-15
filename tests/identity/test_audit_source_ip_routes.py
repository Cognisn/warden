"""Every audit row a route writes carries the client address the router resolves (GitHub #3).

Each test notes the last audit row, calls one route as a client at a
documentation address, and checks every row the call wrote: the expected
events are there and each carries that address. Checking every row, not only
the route's own event, catches an event recorded further down (a role applied
when an invitation is accepted, the password recorded with a new user) that
loses the address on the way. The tripwire
``tests/test_audit_source_ip_tripwire.py`` keeps new events honest.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator, Awaitable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import PASSWORD, RecordingSender, UserFactory, current_code

from warden.db import Database
from warden.identity import Identity, User

pytestmark = pytest.mark.db

ADDRESSES = ["192.0.2.10", "2001:db8::10"]
NEW_PASSWORD = "a brand new passphrase for this test"


@pytest.fixture(params=ADDRESSES, ids=["ipv4", "ipv6"])
def address(request: pytest.FixtureRequest) -> str:
    value: str = request.param
    return value


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.lifecycle_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def client(app: FastAPI, address: str) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=(address, 50000))
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


async def _last_id(db: Database) -> int:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT coalesce(max(id), 0) FROM warden.audit_events")
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def _rows_after(db: Database, marker: int) -> list[tuple[str, str, str | None]]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT action, outcome, host(source_ip) FROM warden.audit_events"
            " WHERE id > %s ORDER BY id",
            (marker,),
        )
        return [(r[0], r[1], r[2]) for r in await cur.fetchall()]


async def recorded(
    db: Database,
    call: Awaitable[httpx.Response],
    address: str,
    *expected: str,
    status: int,
) -> httpx.Response:
    """Run ``call``; check its status, that it wrote ``expected``, all at ``address``."""
    marker = await _last_id(db)
    response = await call
    assert response.status_code == status, response.text
    rows = await _rows_after(db, marker)
    actions = [action for action, _, _ in rows]
    for action in expected:
        assert f"warden.identity.{action}" in actions, (action, rows)
    unaddressed = [row for row in rows if row[2] != address]
    assert not unaddressed, f"rows without the client address {address}: {unaddressed}"
    return response


# Users and roles


async def test_a_status_change_records_the_address(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    _, headers = admin
    user = await make_user()
    await recorded(
        db,
        client.post(
            f"/admin/users/{user.id}/status", json={"status": "suspended"}, headers=headers
        ),
        address,
        "user.status_changed",
        status=200,
    )


async def test_a_refused_status_change_records_the_address(
    client: httpx.AsyncClient, admin: tuple[User, dict[str, str]], db: Database, address: str
) -> None:
    admin_user, headers = admin
    await recorded(
        db,
        client.post(
            f"/admin/users/{admin_user.id}/status", json={"status": "suspended"}, headers=headers
        ),
        address,
        "user.status_changed",
        status=409,
    )


async def test_a_sign_in_method_change_records_the_address(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    _, headers = admin
    user = await make_user()
    await recorded(
        db,
        client.post(
            f"/admin/users/{user.id}/sign-in-method",
            json={"sign_in_method": "sso_only"},
            headers=headers,
        ),
        address,
        "user.sign_in_method_changed",
        status=200,
    )


async def test_assigning_and_revoking_a_role_record_the_address(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    _, headers = admin
    user = await make_user()
    await recorded(
        db,
        client.put(f"/admin/users/{user.id}/roles/viewer", headers=headers),
        address,
        "role.assigned",
        status=204,
    )
    await recorded(
        db,
        client.delete(f"/admin/users/{user.id}/roles/viewer", headers=headers),
        address,
        "role.revoked",
        status=204,
    )


async def test_a_refused_role_revocation_records_the_address(
    client: httpx.AsyncClient, admin: tuple[User, dict[str, str]], db: Database, address: str
) -> None:
    admin_user, headers = admin
    await recorded(
        db,
        client.delete(f"/admin/users/{admin_user.id}/roles/admin", headers=headers),
        address,
        "role.revoked",
        status=409,
    )


# Invitations: the staged roles and the password are recorded at acceptance.


async def test_accepting_an_invitation_records_the_address_on_every_row(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    mail: RecordingSender,
    db: Database,
    address: str,
) -> None:
    _, headers = admin
    await recorded(
        db,
        client.post(
            "/admin/invitations",
            json={"email": "invitee@example.com", "roles": [{"role": "viewer"}]},
            headers=headers,
        ),
        address,
        "invitation.created",
        status=201,
    )
    await recorded(
        db,
        client.post(
            "/auth/invitations/accept", json={"token": mail.token(), "password": NEW_PASSWORD}
        ),
        address,
        "invitation.accepted",
        "role.assigned",
        "password.changed",
        status=200,
    )


# TOTP enrolment


async def test_enrolling_totp_while_signed_in_records_the_address(
    client: httpx.AsyncClient,
    identity: Identity,
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    user = await make_user()
    headers = await _bearer(identity, user)
    began = await recorded(
        db,
        client.post("/auth/totp/enrolment", headers=headers),
        address,
        "mfa.enrolment_started",
        status=200,
    )
    secret = _secret(began.json())
    await recorded(
        db,
        client.post(
            "/auth/totp/enrolment/confirm",
            json={"code": current_code(secret)},
            headers=headers,
        ),
        address,
        "mfa.enrolled",
        status=200,
    )


async def test_a_forced_enrolment_records_the_address(
    client: httpx.AsyncClient,
    identity: Identity,
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    user = await make_user()
    await identity.policy.update(actor="test", require_mfa=True)
    signed = await client.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    assert signed.json()["status"] == "mfa_enrolment_required"
    challenge = signed.json()["challenge"]
    began = await recorded(
        db,
        client.post("/auth/totp/enrolment", json={"challenge": challenge}),
        address,
        "mfa.enrolment_started",
        status=200,
    )
    await recorded(
        db,
        client.post(
            "/auth/totp/enrolment/confirm",
            json={"challenge": challenge, "code": current_code(_secret(began.json()))},
        ),
        address,
        "mfa.enrolled",
        status=200,
    )


def _secret(body: dict[str, Any]) -> bytes:
    text: str = body["secret"]
    return base64.b32decode(text + "=" * (-len(text) % 8))


# Password policies, pins and required changes


async def test_password_policy_routes_record_the_address(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    _, headers = admin
    created = await recorded(
        db,
        client.post(
            "/admin/password-policies",
            json={"name": "Strict", "min_length": 14, "min_classes": 2, "priority": 1},
            headers=headers,
        ),
        address,
        "password_policy.created",
        status=201,
    )
    policy = created.json()["policy"]
    pid = policy["id"]
    await recorded(
        db,
        client.put(
            f"/admin/password-policies/{pid}",
            json={"version": policy["version"], "min_length": 15},
            headers=headers,
        ),
        address,
        "password_policy.updated",
        status=200,
    )
    await recorded(
        db,
        client.put(
            f"/admin/password-policies/{pid}/builtin-list",
            json={"include": False},
            headers=headers,
        ),
        address,
        "password_policy.updated",
        status=200,
    )
    second = await client.post(
        "/admin/password-policies",
        json={"name": "Second", "min_length": 12, "priority": 2},
        headers=headers,
    )
    other = second.json()["policy"]["id"]
    await recorded(
        db,
        client.put(
            f"/admin/password-policies/{pid}/priority", json={"priority": 3}, headers=headers
        ),
        address,
        "password_policy.updated",
        status=200,
    )
    await recorded(
        db,
        client.put(
            "/admin/password-policy-order", json={"policy_ids": [pid, other]}, headers=headers
        ),
        address,
        "password_policy.updated",
        status=200,
    )
    await recorded(
        db,
        client.put("/admin/password-policy-roles/viewer", json={"policy_id": pid}, headers=headers),
        address,
        "password_policy.assigned",
        status=204,
    )
    await recorded(
        db,
        client.delete("/admin/password-policy-roles/viewer", headers=headers),
        address,
        "password_policy.assigned",
        status=204,
    )
    user = await make_user()
    await recorded(
        db,
        client.put(
            f"/admin/users/{user.id}/password-policy", json={"policy_id": pid}, headers=headers
        ),
        address,
        "password_policy.pinned",
        status=200,
    )
    await recorded(
        db,
        client.delete(f"/admin/users/{user.id}/password-policy", headers=headers),
        address,
        "password_policy.unpinned",
        status=204,
    )
    await recorded(
        db,
        client.delete(f"/admin/password-policies/{other}", headers=headers),
        address,
        "password_policy.deleted",
        status=204,
    )


async def test_requiring_and_clearing_a_password_change_record_the_address(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    _, headers = admin
    user = await make_user()
    await recorded(
        db,
        client.put(f"/admin/users/{user.id}/password-change-required", headers=headers),
        address,
        "password.change_required",
        status=200,
    )
    await recorded(
        db,
        client.delete(f"/admin/users/{user.id}/password-change-required", headers=headers),
        address,
        "password.change_cleared",
        status=204,
    )


async def test_watch_list_routes_record_the_address(
    client: httpx.AsyncClient, admin: tuple[User, dict[str, str]], db: Database, address: str
) -> None:
    _, headers = admin
    created = await recorded(
        db,
        client.post(
            "/admin/watch-lists",
            json={"name": "Breached", "reason": "on a breach list", "kind": "manual"},
            headers=headers,
        ),
        address,
        "watch_list.created",
        status=201,
    )
    lid = created.json()["watch_list"]["id"]
    await recorded(
        db,
        client.put(f"/admin/watch-lists/{lid}", json={"reason": "breached"}, headers=headers),
        address,
        "watch_list.updated",
        status=200,
    )
    for path, field, value in (
        ("entries", "passwords", "example-password-1"),
        ("entries/removal", "passwords", "example-password-1"),
        ("terms", "terms", "examplecorp"),
        ("terms/removal", "terms", "examplecorp"),
    ):
        await recorded(
            db,
            client.post(f"/admin/watch-lists/{lid}/{path}", json={field: [value]}, headers=headers),
            address,
            "watch_list.entries_changed",
            status=200,
        )
    policies = await client.get("/admin/password-policies", headers=headers)
    default = policies.json()["policies"][0]["id"]
    await recorded(
        db,
        client.put(f"/admin/password-policies/{default}/watch-lists/{lid}", headers=headers),
        address,
        "password_policy.updated",
        status=200,
    )
    await recorded(
        db,
        client.delete(f"/admin/password-policies/{default}/watch-lists/{lid}", headers=headers),
        address,
        "password_policy.updated",
        status=200,
    )
    await recorded(
        db,
        client.delete(f"/admin/watch-lists/{lid}", headers=headers),
        address,
        "watch_list.deleted",
        status=204,
    )


# Routes that already passed the address keep doing so on every row.


async def test_resets_keys_and_second_factor_resets_record_the_address(
    client: httpx.AsyncClient,
    admin: tuple[User, dict[str, str]],
    make_user: UserFactory,
    db: Database,
    address: str,
) -> None:
    _, headers = admin
    user = await make_user(roles=("viewer",))
    await recorded(
        db,
        client.post(f"/admin/users/{user.id}/password-reset", headers=headers),
        address,
        "password.reset_requested",
        status=202,
    )
    await recorded(
        db,
        client.delete(f"/admin/users/{user.id}/mfa", headers=headers),
        address,
        "mfa.reset",
        status=204,
    )
    created = await recorded(
        db,
        client.post(
            "/admin/api-keys",
            json={"user_id": str(user.id), "name": "ci", "scopes": ["cases.read"]},
            headers=headers,
        ),
        address,
        "api_key.created",
        status=201,
    )
    await recorded(
        db,
        client.delete(f"/admin/api-keys/{created.json()['api_key']['id']}", headers=headers),
        address,
        "api_key.revoked",
        status=204,
    )


# The Python API a product's own routes call: first-run setup creates the
# first administrator from a request, so every row it writes carries the address.


async def test_first_run_setup_through_the_python_api_records_the_address(
    identity: Identity, db: Database, address: str
) -> None:
    import ipaddress

    source = ipaddress.ip_address(address)
    # The default password policy is seeded by warden on first read, with no
    # address (it is on the tripwire's allow-list); seed it first.
    await identity.password_policies.default()
    marker = await _last_id(db)
    user = await identity.users.create(
        "first-admin@example.com", actor="setup", password=NEW_PASSWORD, source_ip=source
    )
    await identity.roles.assign(user.id, "admin", actor="setup", source_ip=source)
    rows = await _rows_after(db, marker)
    assert [action for action, _, _ in rows] == [
        "warden.identity.user.created",
        "warden.identity.password.changed",
        "warden.identity.role.assigned",
    ]
    assert all(row[2] == address for row in rows), rows
