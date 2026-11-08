"""The sample console asks warden what the deployment can do, and its screens follow.

Built with and without a mail sender: warden's two capability routes answer
through the console, the refusals stay as they were, and the screens read
both routes to hide or disable what is unavailable and say why.
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


async def _admin(console: Any, client: httpx.AsyncClient) -> dict[str, str]:
    await make_user(console, "admin@example.com", "administrator")
    return bearer(await sign_in(client, "admin@example.com"))


async def _client(console: Any) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=console.app, client=("192.0.2.10", 50000))
    return httpx.AsyncClient(transport=transport, base_url="http://localhost:8040")


async def test_with_a_sender_everything_that_mails_is_available(
    console: Any, client: httpx.AsyncClient
) -> None:
    admin = await _admin(console, client)
    signin = (await client.get("/auth/capabilities")).json()
    assert signin == {"password_reset": True, "single_sign_on": False, "passkey_sign_in": True}
    full = (await client.get("/admin/capabilities", headers=admin)).json()
    assert full == {
        "mail_sender": True,
        "invitations": True,
        "password_reset": True,
        "passkey_registration_link": True,
        "single_sign_on": False,
        "webauthn": True,
    }
    invited = await client.post(
        "/admin/invitations", json={"email": "carol@example.org"}, headers=admin
    )
    assert invited.status_code == 201


async def test_without_a_sender_the_capabilities_say_so_and_the_503_stays(
    make_console: Any,
) -> None:
    console = await make_console(send_mail=False)
    async with await _client(console) as client:
        admin = await _admin(console, client)
        signin = (await client.get("/auth/capabilities")).json()
        assert signin == {
            "password_reset": False,
            "single_sign_on": False,
            "passkey_sign_in": True,
        }
        full = (await client.get("/admin/capabilities", headers=admin)).json()
        assert full["mail_sender"] is False
        assert full["invitations"] is False
        assert full["password_reset"] is False
        assert full["passkey_registration_link"] is False
        assert full["webauthn"] is True
        invited = await client.post(
            "/admin/invitations", json={"email": "carol@example.org"}, headers=admin
        )
        assert invited.status_code == 503
        assert invited.json() == {"detail": "mail is not configured"}
        requested = await client.post("/auth/password-reset", json={"email": "admin@example.com"})
        assert requested.status_code == 202
        assert (await client.get("/api/outbox")).json()["messages"] == []


async def test_without_the_link_setting_only_the_registration_link_is_unavailable(
    make_console: Any,
) -> None:
    console = await make_console(http={"passkey_registration_link": None})
    async with await _client(console) as client:
        admin = await _admin(console, client)
        full = (await client.get("/admin/capabilities", headers=admin)).json()
        assert full["mail_sender"] is True
        assert full["invitations"] is True
        assert full["passkey_registration_link"] is False
        assert full["webauthn"] is True


def test_the_screens_read_both_capability_routes() -> None:
    signin = (SCRIPTS / "signin.js").read_text(encoding="utf-8")
    admin = (SCRIPTS / "admin.js").read_text(encoding="utf-8")
    assert 'call("GET", `${auth}/capabilities`' in signin
    assert 'call("GET", `${admin}/capabilities`' in admin


def test_the_sign_in_screen_hides_what_is_unavailable() -> None:
    signin = (SCRIPTS / "signin.js").read_text(encoding="utf-8")
    for field in ("password_reset", "single_sign_on", "passkey_sign_in"):
        assert re.search(rf"offered\.{field}\b", signin), field


def test_the_administration_screens_disable_and_explain_mail_actions() -> None:
    admin = (SCRIPTS / "admin.js").read_text(encoding="utf-8")
    for field in ("invitations", "password_reset", "passkey_registration_link", "mail_sender"):
        assert re.search(rf"can\.{field}\b", admin), field
    assert "mail is not configured" in admin
    assert "http.passkey_registration_link" in admin
    # Invite, resend, send reset and send passkey link are each disabled when unavailable.
    assert admin.count("unavailable(") >= 4


def test_the_readme_describes_running_without_a_sender() -> None:
    readme = (CONSOLE / "README.md").read_text(encoding="utf-8")
    assert "--without-mail" in readme
    assert "/capabilities" in readme
    cli = (CONSOLE / "cli.py").read_text(encoding="utf-8")
    assert "--without-mail" in cli
