"""The sample console's sign-in settings screens, over warden's own routes (ruling CS22).

Instance settings and allowed factors, a user's method with its pending state
(resend, cancel), recovery-code replacement, the single sign-on setup steps and
the session policy. The console mounts warden's routes with its own permission
for the instance-wide ones, and its screens call them; nothing here is a route
the sample wrote. The browser check stays integration-only.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from console_support import bearer, make_user, sign_in

pytestmark = pytest.mark.db

CONSOLE = Path(__file__).resolve().parents[2] / "examples" / "console"
SCRIPTS = CONSOLE / "static" / "js"


def script(name: str) -> str:
    return (SCRIPTS / name).read_text(encoding="utf-8")


@pytest.fixture
async def admin(console: Any, client: httpx.AsyncClient) -> dict[str, str]:
    await make_user(console, "admin@example.com", "administrator")
    return bearer(await sign_in(client, "admin@example.com"))


# The screens call warden's routes


def test_the_screens_call_wardens_settings_routes() -> None:
    admin = script("admin.js")
    for route in (
        "`${admin}/sign-in-settings`",
        "`${admin}/users/${id}/sign-in-method`",
        "`${admin}/users/${id}/sign-in-method/resend`",
        "`${admin}/users/${id}/sign-in-method/cancel`",
        "`${admin}/session-policy`",
        "`${admin}/session-policy/reset`",
        "`${admin}/sso/setup-guide?preset=",
    ):
        assert route in admin, route
    signin = script("signin.js")
    assert "`${auth}/recovery-codes/regenerate`" in signin
    assert "`${auth}/sign-in-method`" in signin


def test_the_menu_shows_the_settings_screen_to_the_settings_permission() -> None:
    main = script("main.js")
    assert (
        '["#/sign-in-settings", "Sign-in settings", signInSettingsScreen, "policy.manage"]' in main
    )


def test_no_screen_offers_to_switch_the_second_factor_off() -> None:
    admin = script("admin.js")
    assert "checkbox" not in admin.split("// Session policy", 1)[1].split("// Single sign-on", 1)[0]
    assert "require_mfa" not in re.sub(r"[^\n]*read-only and always on[^\n]*", "", admin)
    readme = (CONSOLE / "README.md").read_text(encoding="utf-8")
    assert "require_mfa: false" not in readme
    assert "require_mfa" not in (CONSOLE / "console.template.yaml").read_text(encoding="utf-8")


def test_the_screens_do_not_build_markup_from_text() -> None:
    for name in ("admin.js", "signin.js"):
        assert "innerHTML" not in script(name), name


def test_the_console_no_longer_has_its_own_session_policy_route() -> None:
    routes = (CONSOLE / "console_routes.py").read_text(encoding="utf-8")
    assert '"/policy' not in routes
    assert "identity.policy" not in routes


# The instance-wide routes are guarded by the console's own permission


async def test_the_settings_routes_need_the_console_policy_permission(
    console: Any, client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    # A role that manages users but not the settings: the console's own permission decides.
    console.identity.permissions.define_role("users-only", {"users.manage"})
    await make_user(console, "helper@example.com", "users-only")
    helper = bearer(await sign_in(client, "helper@example.com"))
    for method, path in (
        ("GET", "/admin/sign-in-settings"),
        ("PUT", "/admin/sign-in-settings"),
        ("GET", "/admin/session-policy"),
        ("PUT", "/admin/session-policy"),
        ("POST", "/admin/session-policy/reset"),
    ):
        assert (await client.request(method, path)).status_code == 401, path
        assert (await client.request(method, path, headers=helper)).status_code == 403, path
        assert (await client.request(method, path, headers=admin)).status_code != 403, path
    # The per-user routes stay with the users permission.
    user = await make_user(console, "pat@example.com", "viewer")
    assert (
        await client.get(f"/admin/users/{user.id}/sign-in-method", headers=helper)
    ).status_code == 200


# What each screen shows


async def test_the_instance_settings_screen_round_trip(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    shown = await client.get("/admin/sign-in-settings", headers=admin)
    assert shown.json()["allowed_second_factors"] == ["totp", "passkey"]
    saved = await client.put(
        "/admin/sign-in-settings",
        json={"default_sign_in_method": "password", "allowed_second_factors": ["totp"]},
        headers=admin,
    )
    assert saved.status_code == 200
    assert saved.json()["settings"]["default_sign_in_method"] == "password"
    refused = await client.put(
        "/admin/sign-in-settings", json={"allowed_second_factors": []}, headers=admin
    )
    assert refused.status_code == 400
    capabilities = (await client.get("/admin/capabilities", headers=admin)).json()
    assert capabilities["allowed_second_factors"] == ["totp"]
    assert capabilities["default_sign_in_method"] == "password"


async def test_a_users_method_with_its_pending_state(
    console: Any, client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    user = await make_user(console, "pat@example.com", "viewer")
    moved = await client.post(
        f"/admin/users/{user.id}/sign-in-method",
        json={"sign_in_method": "passkey_only"},
        headers=admin,
    )
    assert moved.status_code == 200
    pending = moved.json()["sign_in_method"]["pending"]
    assert pending["to"] == "passkey_only"
    assert pending["link"] == "passkey_registration"
    assert any("passkey" in m["subject"].lower() for m in console.outbox.messages())
    resent = await client.post(f"/admin/users/{user.id}/sign-in-method/resend", headers=admin)
    assert resent.status_code == 202
    cancelled = await client.post(f"/admin/users/{user.id}/sign-in-method/cancel", headers=admin)
    assert cancelled.status_code == 200
    assert cancelled.json()["sign_in_method"]["pending"] is None
    again = await client.post(f"/admin/users/{user.id}/sign-in-method/cancel", headers=admin)
    assert again.status_code == 409
    assert again.json()["reason"] == "not_pending"


async def test_a_user_replaces_their_recovery_codes(
    console: Any, client: httpx.AsyncClient
) -> None:
    await make_user(console, "alice@example.com", "editor")
    token = await sign_in(client, "alice@example.com")
    regenerated = await client.post("/auth/recovery-codes/regenerate", headers=bearer(token))
    assert regenerated.status_code == 200
    assert len(regenerated.json()["recovery_codes"]) > 0
    own = await client.get("/auth/sign-in-method", headers=bearer(token))
    assert own.json()["sign_in_method"]["effective"] == "password_and_sso"
    assert own.json()["allowed_second_factors"] == ["totp", "passkey"]


async def test_a_session_without_a_recent_second_factor_is_told_to_sign_in_again(
    console: Any, client: httpx.AsyncClient
) -> None:
    from console_support import identity_support

    user = await make_user(console, "bob@example.com", "editor")
    pair = await identity_support().direct_session(console.identity, user.id, ("pwd",))
    refused = await client.post(
        "/auth/recovery-codes/regenerate", headers=bearer(str(pair.access_token))
    )
    assert refused.status_code == 403
    assert "second factor" in refused.json()["detail"]
    assert "403" in script("signin.js")


async def test_the_session_policy_screen_shows_no_second_factor_switch(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    shown = (await client.get("/admin/session-policy", headers=admin)).json()
    assert shown["policy"]["require_mfa"] is True
    refused = await client.put("/admin/session-policy", json={"require_mfa": False}, headers=admin)
    assert refused.status_code == 400
    saved = await client.put(
        "/admin/session-policy", json={"refresh_reuse_grace_seconds": 7}, headers=admin
    )
    assert saved.json()["policy"]["refresh_reuse_grace_seconds"] == 7
    reset = await client.post("/admin/session-policy/reset", headers=admin)
    assert reset.json()["policy"] == reset.json()["defaults"]


async def test_the_single_sign_on_screen_shows_the_setup_steps_with_the_callback(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    settings = (await client.get("/admin/sso/settings", headers=admin)).json()
    steps = settings["setup_guide"]["steps"]
    assert steps
    assert any(settings["callback_url"] in s["text"] for s in steps)
    entra = await client.get("/admin/sso/setup-guide?preset=entra", headers=admin)
    assert entra.status_code == 200
    assert entra.json()["label"] == "Microsoft Entra ID"
