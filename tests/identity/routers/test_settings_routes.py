"""Administration and self-service routes over the 0.2.0 sign-in settings (ruling CS22).

The instance sign-in settings, a user's method with its pending change (read,
resend, cancel), the own-method read, and the session policy. Every route is
behind a permission (mutation-checked), every change carries the client
address, and every refusal answers with its reason.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import FAST_HASHER, PASSWORD, RecordingSender, UserFactory, complete_sign_in

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry, SignInMethod, User

pytestmark = pytest.mark.db

ADDRESS = "203.0.113.9"
DOMAIN = "https://app.example.com"
SETTINGS = "identity.settings"

SETTINGS_ROUTES = [
    ("GET", "/admin/sign-in-settings"),
    ("PUT", "/admin/sign-in-settings"),
    ("GET", "/admin/session-policy"),
    ("PUT", "/admin/session-policy"),
    ("POST", "/admin/session-policy/reset"),
]
USER_ROUTES = [
    ("GET", "/admin/users/{user}/sign-in-method"),
    ("POST", "/admin/users/{user}/sign-in-method/resend"),
    ("POST", "/admin/users/{user}/sign-in-method/cancel"),
]


@pytest.fixture
def permissions() -> PermissionRegistry:
    registry = PermissionRegistry()
    registry.register_permission("cases.read", "Read cases")
    registry.register_permission("users.manage", "Manage users")
    registry.register_permission(SETTINGS, "Change the instance sign-in settings")
    registry.define_role("viewer", {"cases.read"})
    registry.define_role("admin", {"users.manage", "cases.read"}, administrator=True)
    registry.define_role("settings_admin", {SETTINGS})
    return registry


@pytest.fixture
def config() -> WardenConfig:
    return parse_config(
        {
            "http": {
                "public_base_url": DOMAIN,
                "accept_invitation_link": f"{DOMAIN}/accept?t={{token}}",
                "reset_password_link": f"{DOMAIN}/reset?t={{token}}",
                "passkey_registration_link": f"{DOMAIN}/passkey?t={{token}}",
            },
            "identity": {},
        }
    )


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(
        identity.admin_router(permission="users.manage", settings=SETTINGS), prefix="/admin"
    )
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=(ADDRESS, 50000))
    async with httpx.AsyncClient(transport=transport, base_url=DOMAIN) as c:
        yield c


async def bearer(identity: Identity, user: User) -> dict[str, str]:
    result = await complete_sign_in(identity, user.email, PASSWORD)
    assert result.tokens is not None
    return {"authorization": f"Bearer {result.tokens.access_token}"}


@pytest.fixture
async def admin(identity: Identity, make_user: UserFactory) -> dict[str, str]:
    """Holds the user administration permission only."""
    return await bearer(identity, await make_user("admin@example.com", roles=("admin",)))


@pytest.fixture
async def owner(identity: Identity, make_user: UserFactory) -> dict[str, str]:
    """Holds the settings permission only."""
    return await bearer(identity, await make_user("owner@example.com", roles=("settings_admin",)))


async def _last_id(db: Database) -> int:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT coalesce(max(id), 0) FROM warden.audit_events")
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def recorded(
    db: Database, call: Awaitable[httpx.Response], *expected: str, status: int
) -> httpx.Response:
    """Run ``call``; check its status and that every row it wrote has the client address."""
    marker = await _last_id(db)
    response = await call
    assert response.status_code == status, response.text
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT action, host(source_ip) FROM warden.audit_events WHERE id > %s ORDER BY id",
            (marker,),
        )
        rows = [(r[0], r[1]) for r in await cur.fetchall()]
    actions = [action for action, _ in rows]
    for action in expected:
        assert f"warden.identity.{action}" in actions, (action, rows)
    assert all(ip == ADDRESS for _, ip in rows), rows
    return response


# Authorisation: each route needs its permission, and no other does


@pytest.mark.parametrize(("method", "path"), SETTINGS_ROUTES)
async def test_a_settings_route_needs_the_settings_permission(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    owner: dict[str, str],
    method: str,
    path: str,
) -> None:
    assert (await client.request(method, path)).status_code == 401
    # The user administration permission is not the settings permission.
    assert (await client.request(method, path, headers=admin)).status_code == 403
    allowed = await client.request(method, path, headers=owner)
    assert allowed.status_code not in (401, 403)


@pytest.mark.parametrize(("method", "path"), USER_ROUTES)
async def test_a_user_route_needs_the_user_administration_permission(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    owner: dict[str, str],
    make_user: UserFactory,
    method: str,
    path: str,
) -> None:
    user = await make_user()
    url = path.format(user=user.id)
    assert (await client.request(method, url)).status_code == 401
    assert (await client.request(method, url, headers=owner)).status_code == 403
    assert (await client.request(method, url, headers=admin)).status_code not in (401, 403)


async def test_the_settings_permission_defaults_to_the_user_one(
    identity: Identity, make_user: UserFactory
) -> None:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    headers = await bearer(identity, await make_user(roles=("admin",)))
    transport = httpx.ASGITransport(app=application, client=(ADDRESS, 1))
    async with httpx.AsyncClient(transport=transport, base_url=DOMAIN) as c:
        assert (await c.get("/admin/sign-in-settings", headers=headers)).status_code == 200
        assert (await c.get("/admin/session-policy", headers=headers)).status_code == 200


def test_the_settings_permission_must_be_registered(identity: Identity) -> None:
    with pytest.raises(ValueError, match="registered"):
        identity.admin_router(permission="users.manage", settings="no.such")


# The instance sign-in settings


async def test_the_settings_are_read(client: httpx.AsyncClient, owner: dict[str, str]) -> None:
    answer = await client.get("/admin/sign-in-settings", headers=owner)
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert body["default_sign_in_method"] == "password_and_sso"
    assert body["allowed_second_factors"] == ["totp", "passkey"]
    assert set(body) == {
        "default_sign_in_method",
        "allowed_second_factors",
        "updated_at",
        "updated_by",
    }


async def test_the_allowed_factors_change_with_the_client_address(
    client: httpx.AsyncClient, owner: dict[str, str], db: Database
) -> None:
    answer = await recorded(
        db,
        client.put(
            "/admin/sign-in-settings", json={"allowed_second_factors": ["totp"]}, headers=owner
        ),
        "sign_in_settings_changed",
        status=200,
    )
    body = answer.json()
    assert body["settings"]["allowed_second_factors"] == ["totp"]
    assert body["settings"]["default_sign_in_method"] == "password_and_sso"
    assert (body["changed"], body["pending"], body["links_failed"]) == ([], [], [])
    again = await client.get("/admin/sign-in-settings", headers=owner)
    assert again.json()["allowed_second_factors"] == ["totp"]


async def test_a_new_default_reports_who_moved_and_who_waits(
    client: httpx.AsyncClient,
    owner: dict[str, str],
    make_user: UserFactory,
    mail: RecordingSender,
    db: Database,
) -> None:
    holds_password = await make_user("pw@example.com")
    no_password = await make_user("none@example.com", password=None)
    answer = await recorded(
        db,
        client.put(
            "/admin/sign-in-settings", json={"default_sign_in_method": "password"}, headers=owner
        ),
        "sign_in_settings_changed",
        status=200,
    )
    body = answer.json()
    assert body["settings"]["default_sign_in_method"] == "password"
    assert str(holds_password.id) in body["changed"]
    assert str(no_password.id) in body["pending"]
    assert body["links_failed"] == []
    assert len(mail.sent) == 1


async def test_a_failed_link_delivery_is_listed(
    client: httpx.AsyncClient,
    owner: dict[str, str],
    make_user: UserFactory,
    mail: RecordingSender,
) -> None:
    no_password = await make_user("none@example.com", password=None)
    mail.fail = True
    answer = await client.put(
        "/admin/sign-in-settings", json={"default_sign_in_method": "password"}, headers=owner
    )
    assert answer.status_code == 200
    assert answer.json()["links_failed"] == [str(no_password.id)]


@pytest.mark.parametrize(
    "body",
    [
        {"allowed_second_factors": []},
        {"allowed_second_factors": ["sms"]},
        {"allowed_second_factors": "totp"},
        {"default_sign_in_method": "magic"},
        {"default_sign_in_method": None},
    ],
)
async def test_an_invalid_setting_is_a_400_naming_the_field(
    client: httpx.AsyncClient, owner: dict[str, str], body: dict[str, Any]
) -> None:
    answer = await client.put("/admin/sign-in-settings", json=body, headers=owner)
    assert answer.status_code == 400
    assert answer.json() == {"detail": f"invalid settings: {next(iter(body))}"}
    assert (await client.get("/admin/sign-in-settings", headers=owner)).json()[
        "allowed_second_factors"
    ] == ["totp", "passkey"]


@pytest.mark.parametrize(
    "body", [{}, {"surprise": 1}, {"allowed_second_factors": ["totp"], "actor": "x"}, [1]]
)
async def test_a_body_without_a_known_field_is_a_400(
    client: httpx.AsyncClient, owner: dict[str, str], body: Any
) -> None:
    answer = await client.put("/admin/sign-in-settings", json=body, headers=owner)
    assert answer.status_code == 400
    assert set(answer.json()) == {"detail"}
    assert "surprise" not in answer.text


async def test_an_unreadable_body_is_a_400(
    client: httpx.AsyncClient, owner: dict[str, str]
) -> None:
    answer = await client.put("/admin/sign-in-settings", content=b"{", headers=owner)
    assert answer.status_code == 400


async def test_sso_only_as_the_default_is_refused_with_its_reason(
    client: httpx.AsyncClient, owner: dict[str, str]
) -> None:
    answer = await client.put(
        "/admin/sign-in-settings", json={"default_sign_in_method": "sso_only"}, headers=owner
    )
    assert answer.status_code == 409
    body = answer.json()
    assert body["reason"] == "sso_not_configured"
    assert set(body) == {"detail", "reason"}
    assert (await client.get("/admin/sign-in-settings", headers=owner)).json()[
        "default_sign_in_method"
    ] == "password_and_sso"


async def test_passkeys_alone_are_refused_without_webauthn(
    identity: Identity, make_user: UserFactory, mail: RecordingSender, secrets: Any
) -> None:
    bare = Identity(
        parse_config(
            {
                "http": {
                    "public_base_url": "http://127.0.0.1:8000",
                    "accept_invitation_link": "http://127.0.0.1:8000/accept?t={token}",
                    "reset_password_link": "http://127.0.0.1:8000/reset?t={token}",
                },
                "identity": {},
            }
        ),
        identity.db,
        identity.keys,
        identity.permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        mail_sender=mail,
    )
    application = FastAPI()
    bare.install(application)
    application.include_router(
        bare.admin_router(permission="users.manage", settings=SETTINGS), prefix="/admin"
    )
    user = await make_user(roles=("settings_admin",))
    headers = await bearer(bare, user)
    transport = httpx.ASGITransport(app=application, client=(ADDRESS, 1))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
        answer = await c.put(
            "/admin/sign-in-settings", json={"allowed_second_factors": ["passkey"]}, headers=headers
        )
    assert answer.status_code == 409
    assert answer.json()["reason"] == "webauthn"


# A user's method, its pending change, resend and cancel


async def pending_user(identity: Identity, make_user: UserFactory) -> User:
    """A user moved to passkey_only without a passkey: the change is pending."""
    user = await make_user()
    state = await identity.set_sign_in_method(user.id, SignInMethod.PASSKEY_ONLY, actor="seed")
    assert state.pending is not None
    return user


async def test_a_users_method_is_read(
    client: httpx.AsyncClient, admin: dict[str, str], make_user: UserFactory
) -> None:
    user = await make_user("pat@example.com")
    answer = await client.get(f"/admin/users/{user.id}/sign-in-method", headers=admin)
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert body["user"]["email"] == "pat@example.com"
    assert body["sign_in_method"] == {
        "setting": None,
        "effective": "password_and_sso",
        "pending": None,
    }
    assert "has_passkey" not in body


async def test_a_pending_change_is_read(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    identity: Identity,
    make_user: UserFactory,
) -> None:
    user = await pending_user(identity, make_user)
    body = (await client.get(f"/admin/users/{user.id}/sign-in-method", headers=admin)).json()
    state = body["sign_in_method"]
    assert state["setting"] == "passkey_only"
    assert state["effective"] == "password_and_sso"
    assert state["pending"]["to"] == "passkey_only"
    assert state["pending"]["link"] == "passkey_registration"
    assert body["has_passkey"] is False


@pytest.mark.parametrize("path", ["", "/resend", "/cancel"])
async def test_an_unknown_user_is_a_404(
    client: httpx.AsyncClient, admin: dict[str, str], path: str
) -> None:
    for user in (str(uuid.uuid4()), "not-a-uuid"):
        method = "GET" if not path else "POST"
        answer = await client.request(
            method, f"/admin/users/{user}/sign-in-method{path}", headers=admin
        )
        assert answer.status_code == 404
        assert answer.json() == {"detail": "not found"}


async def test_resend_mails_a_fresh_link(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    identity: Identity,
    make_user: UserFactory,
    mail: RecordingSender,
    db: Database,
) -> None:
    user = await pending_user(identity, make_user)
    before = len(mail.sent)
    answer = await recorded(
        db,
        client.post(f"/admin/users/{user.id}/sign-in-method/resend", headers=admin),
        "user.sign_in_method_link_sent",
        status=202,
    )
    body = answer.json()
    assert body["status"] == "sent"
    assert "expires_at" in body
    assert len(mail.sent) == before + 1


async def test_resend_without_a_pending_change_is_refused_with_its_reason(
    client: httpx.AsyncClient, admin: dict[str, str], make_user: UserFactory
) -> None:
    user = await make_user()
    answer = await client.post(f"/admin/users/{user.id}/sign-in-method/resend", headers=admin)
    assert answer.status_code == 409
    assert answer.json() == {"detail": "no change is pending", "reason": "not_pending"}


async def test_resend_reports_a_delivery_failure(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    identity: Identity,
    make_user: UserFactory,
    mail: RecordingSender,
) -> None:
    user = await pending_user(identity, make_user)
    mail.fail = True
    answer = await client.post(f"/admin/users/{user.id}/sign-in-method/resend", headers=admin)
    assert answer.status_code == 502
    assert answer.json() == {"detail": "the message could not be delivered"}


async def test_cancel_returns_the_user_to_the_method_in_force(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    identity: Identity,
    make_user: UserFactory,
    db: Database,
) -> None:
    user = await pending_user(identity, make_user)
    answer = await recorded(
        db,
        client.post(f"/admin/users/{user.id}/sign-in-method/cancel", headers=admin),
        "user.sign_in_method_pending_cancelled",
        status=200,
    )
    state = answer.json()["sign_in_method"]
    assert state["pending"] is None
    assert state["effective"] == "password_and_sso"
    after = await identity.sign_in_method(user.id)
    assert after.pending is None


async def test_cancel_without_a_pending_change_is_refused_with_its_reason(
    client: httpx.AsyncClient, admin: dict[str, str], make_user: UserFactory
) -> None:
    user = await make_user()
    answer = await client.post(f"/admin/users/{user.id}/sign-in-method/cancel", headers=admin)
    assert answer.status_code == 409
    assert answer.json()["reason"] == "not_pending"


async def test_the_existing_set_route_names_its_refusal_reason(
    client: httpx.AsyncClient, admin: dict[str, str], make_user: UserFactory
) -> None:
    user = await make_user()
    answer = await client.post(
        f"/admin/users/{user.id}/sign-in-method", json={"sign_in_method": "sso_only"}, headers=admin
    )
    assert answer.status_code == 409
    assert answer.json()["reason"] == "sso_not_configured"


# The signed-in user's own method


async def test_a_user_reads_their_own_method_and_the_allowed_factors(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    user = await pending_user(identity, make_user)
    other = await make_user("other@example.com")
    await identity.set_sign_in_method(other.id, SignInMethod.PASSWORD, actor="seed")
    await identity.update_sign_in_settings(actor="seed", allowed_second_factors=["totp"])
    answer = await client.get("/auth/sign-in-method", headers=await bearer(identity, user))
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert set(body) == {"sign_in_method", "allowed_second_factors"}
    assert body["allowed_second_factors"] == ["totp"]
    assert body["sign_in_method"]["setting"] == "passkey_only"
    assert body["sign_in_method"]["pending"]["to"] == "passkey_only"
    assert "other@example.com" not in answer.text
    assert str(other.id) not in answer.text
    # Another user's answer is that user's own.
    theirs = await client.get("/auth/sign-in-method", headers=await bearer(identity, other))
    assert theirs.json()["sign_in_method"]["setting"] == "password"
    assert theirs.json()["sign_in_method"]["pending"] is None


async def test_the_own_method_needs_a_sign_in(client: httpx.AsyncClient) -> None:
    for headers in ({}, {"authorization": "Bearer nonsense"}):
        answer = await client.get("/auth/sign-in-method", headers=headers)
        assert answer.status_code == 401
        assert answer.json() == {"detail": "authentication failed"}


async def test_the_own_method_ignores_a_user_id_in_the_query(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    me = await make_user("me@example.com")
    other = await pending_user(identity, make_user)
    answer = await client.get(
        "/auth/sign-in-method",
        params={"user_id": str(other.id)},
        headers=await bearer(identity, me),
    )
    assert answer.json()["sign_in_method"]["pending"] is None


# The session policy


async def test_the_session_policy_is_read(
    client: httpx.AsyncClient, owner: dict[str, str], config: WardenConfig
) -> None:
    answer = await client.get("/admin/session-policy", headers=owner)
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert set(body) == {"policy", "defaults"}
    assert body["policy"] == body["defaults"]
    assert body["policy"]["require_mfa"] is True
    assert body["policy"]["access_token_ttl_seconds"] == config.identity.access_token_ttl_seconds


async def test_the_session_policy_changes_and_is_audited_with_the_address(
    client: httpx.AsyncClient, owner: dict[str, str], db: Database, config: WardenConfig
) -> None:
    answer = await recorded(
        db,
        client.put(
            "/admin/session-policy",
            json={"access_token_ttl_seconds": 600, "refresh_reuse_grace_seconds": 5},
            headers=owner,
        ),
        "policy.changed",
        status=200,
    )
    body = answer.json()
    assert body["policy"]["access_token_ttl_seconds"] == 600
    assert body["policy"]["refresh_reuse_grace_seconds"] == 5
    assert body["defaults"]["access_token_ttl_seconds"] == config.identity.access_token_ttl_seconds
    again = await client.get("/admin/session-policy", headers=owner)
    assert again.json()["policy"]["access_token_ttl_seconds"] == 600


async def test_a_session_policy_the_rules_refuse_is_a_400_and_changes_nothing(
    client: httpx.AsyncClient, owner: dict[str, str]
) -> None:
    before = (await client.get("/admin/session-policy", headers=owner)).json()
    answer = await client.put(
        "/admin/session-policy", json={"access_token_ttl_seconds": 5}, headers=owner
    )
    assert answer.status_code == 400
    assert "access_token_ttl_seconds must be between 60 and 3600" in answer.json()["detail"]
    assert (await client.get("/admin/session-policy", headers=owner)).json() == before


@pytest.mark.parametrize(
    "body",
    [
        {"access_token_ttl_seconds": "600"},
        {"access_token_ttl_seconds": True},
        {"access_token_ttl_seconds": 600.5},
        {"require_mfa": False},
    ],
)
async def test_a_value_of_the_wrong_kind_or_mfa_off_is_a_400(
    client: httpx.AsyncClient, owner: dict[str, str], body: dict[str, Any]
) -> None:
    answer = await client.put("/admin/session-policy", json=body, headers=owner)
    assert answer.status_code == 400
    assert set(answer.json()) == {"detail"}
    assert (await client.get("/admin/session-policy", headers=owner)).json()["policy"][
        "require_mfa"
    ] is True


@pytest.mark.parametrize("body", [{}, {"surprise": 1}, [1]])
async def test_an_empty_or_unknown_session_policy_body_is_a_400(
    client: httpx.AsyncClient, owner: dict[str, str], body: Any
) -> None:
    answer = await client.put("/admin/session-policy", json=body, headers=owner)
    assert answer.status_code == 400
    assert "surprise" not in answer.text


async def test_the_session_policy_is_reset_with_the_address(
    client: httpx.AsyncClient, owner: dict[str, str], db: Database
) -> None:
    await client.put("/admin/session-policy", json={"access_token_ttl_seconds": 600}, headers=owner)
    answer = await recorded(
        db,
        client.post("/admin/session-policy/reset", headers=owner),
        "policy.changed",
        status=200,
    )
    assert answer.json()["policy"] == answer.json()["defaults"]
