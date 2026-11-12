"""The sample console's password policy support: routes, the development clock,
the recheck and import helpers, and a forced change round trip, against a real
Postgres. The browser-side rules are tested in ``test_console_password_rules.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from console_support import PASSWORD, assert_strict_csp, bearer, make_user, sign_in

pytestmark = pytest.mark.db

DATA = Path(__file__).resolve().parents[2] / "examples" / "console" / "data"
STRONG = "a much longer, quite different phrase 42!"


async def admin_token(console: Any, client: httpx.AsyncClient) -> str:
    await make_user(console, "root@example.com", "administrator")
    return await sign_in(client, "root@example.com")


async def new_policy(client: httpx.AsyncClient, token: str, **fields: Any) -> dict[str, Any]:
    body = {"name": "Sample", "priority": 5, "min_length": 12, **fields}
    answer = await client.post("/admin/password-policies", json=body, headers=bearer(token))
    assert answer.status_code == 201, answer.text
    policy: dict[str, Any] = answer.json()["policy"]
    return policy


# Mounting and permission


async def test_the_password_routes_are_mounted_behind_their_own_permission(
    console: Any, client: httpx.AsyncClient
) -> None:
    token = await admin_token(console, client)
    await make_user(console, "viewer@example.com", "viewer")
    viewer = await sign_in(client, "viewer@example.com")
    for path in ("/admin/password-policies", "/admin/watch-lists", "/admin/password-exposures"):
        allowed = await client.get(path, headers=bearer(token))
        assert allowed.status_code == 200, path
        refused = await client.get(path, headers=bearer(viewer))
        assert refused.status_code == 403, path


async def test_users_manage_alone_does_not_reach_the_password_routes(
    console: Any, client: httpx.AsyncClient
) -> None:
    # The sample guards the password routes with passwords.manage (question 35).
    console.identity.permissions.define_role("people", {"users.manage"})
    await make_user(console, "people@example.com", "people")
    token = await sign_in(client, "people@example.com")
    users = await client.get("/admin/users", headers=bearer(token))
    assert users.status_code == 200
    policies = await client.get("/admin/password-policies", headers=bearer(token))
    assert policies.status_code == 403


async def test_the_console_settings_say_whether_the_fingerprint_key_is_configured(
    make_console: Any,
) -> None:
    for secret, expected in (({}, False), ({"fingerprint_key_secret": "fp-key"}, True)):
        built = await make_console(passwords=secret)
        transport = httpx.ASGITransport(app=built.app, client=("192.0.2.10", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8040") as c:
            settings = (await c.get("/api/console")).json()
        assert settings["fingerprint"] is expected
        assert settings["dev_clock"] is False


async def test_the_console_settings_carry_the_range_api_and_built_in_list_facts(
    make_console: Any,
) -> None:
    built = await make_console(
        passwords={
            "hibp_range_url": "https://mirror.example.net/range/",
            "hibp_timeout_seconds": 3.5,
            "hibp_padding": False,
        }
    )
    transport = httpx.ASGITransport(app=built.app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8040") as c:
        shown = (await c.get("/api/console")).json()["passwords"]
    assert shown["hibp_range_url"] == "https://mirror.example.net/range/"
    assert shown["hibp_timeout_seconds"] == 3.5
    assert shown["hibp_padding"] is False
    # The bundled list ships with warden; its size is read on the server, never sent
    # to the browser as entries.
    assert 90_000 <= shown["builtin_count"] <= 110_000
    assert set(shown) == {
        "hibp_range_url",
        "hibp_timeout_seconds",
        "hibp_padding",
        "builtin_count",
    }


async def test_the_console_settings_default_to_the_public_range_api(
    client: httpx.AsyncClient,
) -> None:
    shown = (await client.get("/api/console")).json()["passwords"]
    assert shown["hibp_range_url"] == "https://api.pwnedpasswords.com/range/"
    assert shown["hibp_timeout_seconds"] == 5.0
    assert shown["hibp_padding"] is True


# Pages


async def test_the_new_screens_are_served_with_the_policy(client: httpx.AsyncClient) -> None:
    for path in (
        "/static/js/passwordrules.js",
        "/static/js/checklist.js",
        "/static/js/passwords.js",
        "/static/js/dev.js",
        "/accept?t=x",
        "/reset?t=x",
        "/",
    ):
        answer = await client.get(path)
        assert answer.status_code == 200, path
        assert_strict_csp(answer)


# The development clock


async def test_there_is_no_development_clock_unless_it_is_switched_on(
    console: Any, client: httpx.AsyncClient
) -> None:
    assert console.dev_clock is None
    assert (await client.get("/api/dev/clock")).status_code == 404
    assert (await client.put("/api/dev/clock", json={"days": 3})).status_code == 404


async def test_the_development_clock_moves_what_warden_sees(make_console: Any) -> None:
    built = await make_console(dev_clock=True)
    transport = httpx.ASGITransport(app=built.app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8040") as c:
        before = (await c.get("/api/dev/clock")).json()
        assert before["offset_days"] == 0
        assert (await c.get("/api/console")).json()["dev_clock"] is True
        moved = await c.put("/api/dev/clock", json={"days": 40})
        assert moved.status_code == 200
        assert moved.json()["offset_days"] == 40
        bad = await c.put("/api/dev/clock", json={"days": "soon"})
        assert bad.status_code == 400
        out_of_range = await c.put("/api/dev/clock", json={"days": 100000})
        assert out_of_range.status_code == 400
        assert (await c.get("/api/dev/clock")).json()["offset_days"] == 40
    assert built.dev_clock is not None
    assert built.dev_clock() - __import__("time").time() > 39 * 86400


async def test_expiry_is_walked_without_waiting(make_console: Any) -> None:
    built = await make_console(dev_clock=True)
    transport = httpx.ASGITransport(app=built.app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8040") as c:
        token = await admin_token(built, c)
        policy = await new_policy(
            c,
            token,
            name="Thirty days",
            tiers=[{"name": "standard", "min_length": 0, "min_classes": 0, "max_age_days": 30}],
            warning_days=10,
        )
        mapped = await c.put(
            "/admin/password-policy-roles/editor",
            json={"policy_id": policy["id"]},
            headers=bearer(token),
        )
        assert mapped.status_code == 204, mapped.text
        await make_user(built, "ed@example.com", "editor")
        first = await c.post(
            "/auth/sign-in", json={"email": "ed@example.com", "password": PASSWORD}
        )
        assert first.json()["status"] == "signed_in"
        assert first.json().get("password_expires_in_days") is None

        assert (await c.put("/api/dev/clock", json={"days": 25})).status_code == 200
        warned = await c.post(
            "/auth/sign-in", json={"email": "ed@example.com", "password": PASSWORD}
        )
        assert warned.json()["status"] == "signed_in"
        assert 0 < warned.json()["password_expires_in_days"] <= 6

        assert (await c.put("/api/dev/clock", json={"days": 40})).status_code == 200
        due = await c.post("/auth/sign-in", json={"email": "ed@example.com", "password": PASSWORD})
        body = due.json()
        assert body["status"] == "password_change_required"
        assert body["reason"] == "expired"


# Recheck


async def test_recheck_is_an_administrators_action_and_reports_counts(
    console: Any, client: httpx.AsyncClient
) -> None:
    token = await admin_token(console, client)
    await make_user(console, "viewer@example.com", "viewer")
    viewer = await sign_in(client, "viewer@example.com")
    assert (await client.post("/api/passwords/recheck")).status_code == 401
    assert (await client.post("/api/passwords/recheck", headers=bearer(viewer))).status_code == 403
    ran = await client.post("/api/passwords/recheck", headers=bearer(token))
    assert ran.status_code == 200
    assert set(ran.json()) >= {"checked", "matched", "flagged", "sessions_ended", "unopened"}


async def test_recheck_flags_a_user_whose_password_is_now_on_a_list(
    make_console: Any,
) -> None:
    built = await make_console(passwords={"fingerprint_key_secret": "fp-key"})
    built.identity.password_fingerprints  # noqa: B018  (present when the key is configured)
    transport = httpx.ASGITransport(app=built.app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8040") as c:
        token = await admin_token(built, c)
        policy = await new_policy(c, token, fingerprint_enabled=True, name="Fingerprinted")
        await c.put(
            "/admin/password-policy-roles/editor",
            json={"policy_id": policy["id"]},
            headers=bearer(token),
        )
        user = await make_user(built, "fp@example.com", "editor")
        await sign_in(c, "fp@example.com")
        made = await c.post(
            "/admin/watch-lists",
            json={"name": "Known", "reason": "Known to be weak", "kind": "manual"},
            headers=bearer(token),
        )
        listed = made.json()["watch_list"]["id"]
        await c.post(
            f"/admin/watch-lists/{listed}/entries",
            json={"passwords": [PASSWORD]},
            headers=bearer(token),
        )
        await c.put(
            f"/admin/password-policies/{policy['id']}/watch-lists/{listed}", headers=bearer(token)
        )
        ran = await c.post("/api/passwords/recheck", headers=bearer(token))
        assert ran.status_code == 200, ran.text
        assert ran.json()["flagged"] == 1
        status = await c.get(f"/admin/users/{user.id}/password-policy", headers=bearer(token))
        assert status.json()["change_required"] is True
        again = await c.post(
            "/auth/sign-in", json={"email": "fp@example.com", "password": PASSWORD}
        )
        assert again.json()["status"] == "password_change_required"
        assert again.json()["reason"] == "watch_list"
        assert again.json()["watch_list_reason"] == "Known to be weak"


# The synthetic import


def test_the_import_file_is_synthetic_and_in_the_downloader_format() -> None:
    import re

    lines = (DATA / "synthetic-pwned.txt").read_text(encoding="utf-8").splitlines()
    assert 3 <= len(lines) <= 50
    for line in lines:
        assert re.fullmatch(r"[0-9A-F]{40}:[1-9][0-9]*", line), line


async def test_the_shipped_file_imports_into_an_imported_list_only(
    console: Any, client: httpx.AsyncClient
) -> None:
    token = await admin_token(console, client)
    manual = await client.post(
        "/admin/watch-lists",
        json={"name": "Manual", "reason": "Typed in", "kind": "manual"},
        headers=bearer(token),
    )
    refused = await client.post(
        f"/api/watch-lists/{manual.json()['watch_list']['id']}/import-sample",
        headers=bearer(token),
    )
    assert refused.status_code == 409

    imported = await client.post(
        "/admin/watch-lists",
        json={"name": "Pwned sample", "reason": "Seen in a breach", "kind": "imported"},
        headers=bearer(token),
    )
    list_id = imported.json()["watch_list"]["id"]
    assert (await client.post(f"/api/watch-lists/{list_id}/import-sample")).status_code == 401
    done = await client.post(f"/api/watch-lists/{list_id}/import-sample", headers=bearer(token))
    assert done.status_code == 200, done.text
    assert done.json()["imported"] >= 3
    shown = await client.get(f"/admin/watch-lists/{list_id}", headers=bearer(token))
    assert shown.json()["watch_list"]["entry_count"] == done.json()["imported"]
    missing = await client.post(
        "/api/watch-lists/00000000-0000-0000-0000-000000000000/import-sample",
        headers=bearer(token),
    )
    assert missing.status_code == 404


async def test_a_password_in_the_shipped_file_is_refused_by_the_check_route(
    console: Any, client: httpx.AsyncClient
) -> None:
    token = await admin_token(console, client)
    made = await client.post(
        "/admin/watch-lists",
        json={"name": "Pwned sample", "reason": "Seen in a breach", "kind": "imported"},
        headers=bearer(token),
    )
    list_id = made.json()["watch_list"]["id"]
    await client.post(f"/api/watch-lists/{list_id}/import-sample", headers=bearer(token))
    default = next(
        p
        for p in (await client.get("/admin/password-policies", headers=bearer(token))).json()[
            "policies"
        ]
        if p["is_default"]
    )
    await client.put(
        f"/admin/password-policies/{default['id']}/watch-lists/{list_id}", headers=bearer(token)
    )
    await make_user(console, "carol@example.com", "editor")
    carol = await sign_in(client, "carol@example.com")
    checked = await client.post(
        "/auth/password/check", json={"password": "Sample-Breached-Pass1"}, headers=bearer(carol)
    )
    assert checked.status_code == 200
    assert checked.json()["watch_list"] == {"reason": "Seen in a breach"}
    fine = await client.post(
        "/auth/password/check", json={"password": STRONG}, headers=bearer(carol)
    )
    assert fine.json()["watch_list"] is None


# A forced change, round trip


async def test_a_forced_change_round_trip(console: Any, client: httpx.AsyncClient) -> None:
    token = await admin_token(console, client)
    user = await make_user(console, "dave@example.com", "editor")
    required = await client.put(
        f"/admin/users/{user.id}/password-change-required", headers=bearer(token)
    )
    assert required.status_code == 200
    assert required.json() == {"change_required": True, "change_reason": "administrator"}

    gate = await client.post(
        "/auth/sign-in", json={"email": "dave@example.com", "password": PASSWORD}
    )
    body = gate.json()
    assert body["status"] == "password_change_required"
    assert body["reason"] == "administrator"
    challenge = body["challenge"]

    described = await client.post("/auth/password-change/policy", json={"challenge": challenge})
    assert described.status_code == 200
    assert described.json()["rules"]["min_length"] >= 8
    weak = await client.post(
        "/auth/password-change/check", json={"challenge": challenge, "password": "short"}
    )
    assert weak.json()["ok"] is False
    good = await client.post(
        "/auth/password-change/check", json={"challenge": challenge, "password": STRONG}
    )
    assert good.json()["ok"] is True

    refused = await client.post(
        "/auth/password-change", json={"challenge": challenge, "new_password": "short"}
    )
    assert refused.status_code == 400
    done = await client.post(
        "/auth/password-change", json={"challenge": challenge, "new_password": STRONG}
    )
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "signed_in"
    again = await client.post(
        "/auth/sign-in", json={"email": "dave@example.com", "password": STRONG}
    )
    assert again.json()["status"] == "signed_in"


async def test_an_administrator_clears_a_required_change(
    console: Any, client: httpx.AsyncClient
) -> None:
    token = await admin_token(console, client)
    user = await make_user(console, "erin@example.com", "editor")
    await client.put(f"/admin/users/{user.id}/password-change-required", headers=bearer(token))
    cleared = await client.delete(
        f"/admin/users/{user.id}/password-change-required", headers=bearer(token)
    )
    assert cleared.status_code == 204
    signed = await client.post(
        "/auth/sign-in", json={"email": "erin@example.com", "password": PASSWORD}
    )
    assert signed.json()["status"] == "signed_in"


async def test_the_four_set_points_each_have_feedback_routes(
    console: Any, client: httpx.AsyncClient
) -> None:
    paths = set(console.app.openapi()["paths"])
    assert {
        "/auth/password/policy",
        "/auth/password/check",
        "/auth/password-change/policy",
        "/auth/password-change/check",
        "/auth/invitations/accept/password-policy",
        "/auth/invitations/accept/password-check",
        "/auth/password-reset/policy",
        "/auth/password-reset/check",
    } <= paths


# What the screens call


SCRIPTS = Path(__file__).resolve().parents[2] / "examples" / "console" / "static" / "js"


def warden_calls() -> set[tuple[str, str]]:
    """Every (method, path) a screen sends to a warden router, path parameters as ``{}``."""
    import re

    found: set[tuple[str, str]] = set()
    simple = re.compile(r'call\("([A-Z]+)", `\$\{(auth|admin|audit|keys)\}([^`?]*)')
    for script in SCRIPTS.glob("*.js"):
        text = script.read_text(encoding="utf-8")
        for method, prefix, rest in simple.findall(text):
            rest = re.sub(r"(?<=[^/])\$\{[^}]*\}$", "", rest)
            found.add((method, f"/{prefix}" + re.sub(r"\$\{[^}]*\}", "{}", rest)))
        if 'attached ? "DELETE" : "PUT"' in text:
            for method in ("PUT", "DELETE"):
                found.add((method, "/admin/password-policies/{}/watch-lists/{}"))
    return found


def test_the_screens_call_every_password_route_they_stand_for() -> None:
    calls = warden_calls()
    for expected in (
        ("GET", "/auth/password/policy"),
        ("POST", "/auth/password/check"),
        ("POST", "/auth/password"),
        ("POST", "/auth/password-change/policy"),
        ("POST", "/auth/password-change/check"),
        ("POST", "/auth/password-change"),
        ("POST", "/auth/invitations/accept/password-policy"),
        ("POST", "/auth/invitations/accept/password-check"),
        ("POST", "/auth/password-reset/policy"),
        ("POST", "/auth/password-reset/check"),
        ("GET", "/admin/password-policies"),
        ("POST", "/admin/password-policies"),
        ("PUT", "/admin/password-policies/{}"),
        ("DELETE", "/admin/password-policies/{}"),
        ("POST", "/admin/password-policies/affected-users"),
        ("GET", "/admin/password-policies/{}/affected-users"),
        ("PUT", "/admin/password-policies/{}/priority"),
        ("PUT", "/admin/password-policy-order"),
        ("PUT", "/admin/password-policy-roles/{}"),
        ("DELETE", "/admin/password-policy-roles/{}"),
        ("PUT", "/admin/password-policies/{}/watch-lists/{}"),
        ("DELETE", "/admin/password-policies/{}/watch-lists/{}"),
        ("GET", "/admin/users/{}/password-policy"),
        ("PUT", "/admin/users/{}/password-policy"),
        ("DELETE", "/admin/users/{}/password-policy"),
        ("PUT", "/admin/users/{}/password-change-required"),
        ("DELETE", "/admin/users/{}/password-change-required"),
        ("GET", "/admin/watch-lists"),
        ("POST", "/admin/watch-lists"),
        ("GET", "/admin/watch-lists/{}"),
        ("PUT", "/admin/watch-lists/{}"),
        ("DELETE", "/admin/watch-lists/{}"),
        ("POST", "/admin/watch-lists/{}/entries"),
        ("POST", "/admin/watch-lists/{}/entries/removal"),
        ("POST", "/admin/watch-lists/{}/terms"),
        ("POST", "/admin/watch-lists/{}/terms/removal"),
    ):
        assert expected in calls, expected


def test_every_place_a_password_is_set_uses_the_live_checklist() -> None:
    signin = (SCRIPTS / "signin.js").read_text(encoding="utf-8")
    lifecycle = (SCRIPTS / "lifecycle.js").read_text(encoding="utf-8")
    assert signin.count("livePassword({") == 2  # the signed-in change and the forced change
    assert lifecycle.count("livePassword({") == 2  # an invitation and a reset
    for source in (signin, lifecycle):
        assert 'type: "password", autocomplete: "new-password"' not in source


def test_the_checklist_calls_the_check_route_after_a_pause_not_on_every_key() -> None:
    source = (SCRIPTS / "checklist.js").read_text(encoding="utf-8")
    assert "setTimeout(ask, PAUSE_MS)" in source
    assert "clearTimeout(timer)" in source
    assert "if (mine !== ticket) return;" in source  # a stale answer is dropped


def test_each_reason_for_a_forced_change_has_plain_words() -> None:
    source = (SCRIPTS / "signin.js").read_text(encoding="utf-8")
    for reason in ("expired", "watch_list", "administrator", "policy"):
        assert f'case "{reason}":' in source
    assert "password_expires_in_days" in source


def test_the_fingerprint_notice_is_in_the_policy_form() -> None:
    source = (SCRIPTS / "passwords.js").read_text(encoding="utf-8")
    assert "fingerprint key is not configured" in source
    assert "settings.fingerprint" in source


def test_the_gate_walk_is_in_the_readme_in_order() -> None:
    readme = (SCRIPTS.parents[1] / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Password policies", 1)[1]
    steps = [
        "Create policies",
        "Map roles and pin a user",
        "The live checklist",
        "A watch list refusal",
        "Import a Pwned Passwords file",
        "Recheck, then a forced change",
        "Expiry warning, then a forced change",
        "The real range API",
    ]
    positions = [section.index(step) for step in steps]
    assert positions == sorted(positions)


async def test_forbid_user_details_can_be_set_over_http(
    console: Any, client: httpx.AsyncClient
) -> None:
    token = await admin_token(console, client)
    made = await new_policy(client, token, name="No details", forbid_user_details=True)
    assert made["forbid_user_details"] is True


# The guidance screens


def _passwords_source() -> str:
    return (SCRIPTS / "passwords.js").read_text(encoding="utf-8")


def test_the_policy_screen_has_a_how_to_above_the_list() -> None:
    source = _passwords_source()
    how_to = source.index("How to set up a password policy")
    assert how_to < source.index('card("Policies"')
    for word in ("priority", "Role mapping", "pin", "Preview affected users", "default policy"):
        assert word in source[how_to : source.index('card("Policies"')], word


def test_the_policy_form_explains_each_group_of_settings_in_page_text() -> None:
    source = _passwords_source()
    for fragment in (
        "Kinds of character are",  # length and character kinds
        "A passphrase is a long password",  # passphrases
        "skip the kinds-of-character rule",
        "Tiers set how long a password may be kept",  # tiers and change periods
        "History stops a user going back",  # history and minimum age
        "User details:",  # user details
        "The built-in list",  # watch lists and the built-in list
        "A list has no effect until it is attached to a policy",
        "needs no API key and no account",  # the range API
        "first five characters of the password's SHA-1 hash",
        "allow lets the password through and records that in the audit trail",
        "The fingerprint is the SHA-1 of the password",  # fingerprint, recheck, sessions
        "ends their live sessions",
        "Without this, a password that fails an edited policy carries on",  # enforce
    ):
        assert fragment in source, fragment
    # Help is ordinary text: no title or tooltip attribute carries it.
    assert '"title"' not in source
    assert 'setAttribute("title"' not in source


def test_the_built_in_list_is_said_to_need_no_loading_on_both_screens() -> None:
    source = _passwords_source()
    assert source.count("needs no loading or importing") == 1  # the policy form
    assert "The built-in list needs no setup" in source  # the Watch lists screen
    assert source.count("${builtinSize(passwords)}") == 2
    assert "about 100,000 common passwords" in source  # when the size is not known
    assert "builtin_count" in source


def test_the_range_url_and_timeout_come_from_the_console_settings() -> None:
    source = _passwords_source()
    assert "passwords.hibp_range_url" in source
    assert "passwords.hibp_timeout_seconds" in source
    assert "settings.passwords" in source


def test_the_manual_list_has_two_panels_and_no_four_forms() -> None:
    source = _passwords_source()
    assert source.count("\n      entryPanel({") == 2
    assert 'title: "Exact passwords"' in source
    assert 'title: "Terms"' in source
    assert 'action("Add"' in source
    assert 'action("Remove"' in source
    for gone in ("Add exact passwords", "Remove exact passwords", "Add terms", "Remove terms"):
        assert gone not in source, gone
    for explanation in (
        "An exact password refuses only that password",
        "A term refuses any password that contains it",
        "3 to 64 characters",
        "never shown again",
        "type it again",
        "update after each action",
    ):
        assert explanation in source, explanation


def test_an_imported_list_explains_the_file_the_threshold_and_the_command_line() -> None:
    source = _passwords_source()
    for fragment in ("HASH:count", "A threshold keeps only the hashes", "passwords import --list"):
        assert fragment in source, fragment
    assert "Import the sample file" in source


def test_the_screens_set_no_inline_script_or_style() -> None:
    for script in SCRIPTS.glob("*.js"):
        text = script.read_text(encoding="utf-8")
        if script.name != "dom.js":  # dom.js names innerHTML only to say it is not used
            assert "innerHTML" not in text, script.name
        assert "<script" not in text, script.name
    assert "style:" not in _passwords_source()
    assert ".style" not in _passwords_source()


def test_the_readme_answers_the_api_key_and_built_in_list_questions() -> None:
    readme = (SCRIPTS.parents[1] / "README.md").read_text(encoding="utf-8")
    section = readme.split("### The API key and the built-in list", 1)[1].split("## Gaps", 1)[0]
    assert "No. warden uses only the free Pwned Passwords range API" in section
    assert "hibp_range_url" in section
    assert "common-passwords.sha1.gz" in section
    assert "never sends the entries to the browser" in section


async def test_exact_passwords_and_terms_are_added_and_removed_with_counts(
    console: Any, client: httpx.AsyncClient
) -> None:
    token = await admin_token(console, client)
    made = await client.post(
        "/admin/watch-lists",
        json={"name": "Typed", "reason": "Typed in", "kind": "manual"},
        headers=bearer(token),
    )
    list_id = made.json()["watch_list"]["id"]
    base = f"/admin/watch-lists/{list_id}"

    async def counts() -> tuple[int, int]:
        shown = (await client.get(base, headers=bearer(token))).json()["watch_list"]
        return int(shown["entry_count"]), int(shown["term_count"])

    added = await client.post(
        f"{base}/entries",
        json={"passwords": ["synthetic-one", "synthetic-two"]},
        headers=bearer(token),
    )
    assert added.json()["added"] == 2
    added = await client.post(
        f"{base}/terms", json={"terms": ["examplecorp"]}, headers=bearer(token)
    )
    assert added.json()["added"] == 1
    assert await counts() == (2, 1)
    removed = await client.post(
        f"{base}/entries/removal", json={"passwords": ["synthetic-one"]}, headers=bearer(token)
    )
    assert removed.json()["removed"] == 1
    removed = await client.post(
        f"{base}/terms/removal", json={"terms": ["examplecorp"]}, headers=bearer(token)
    )
    assert removed.json()["removed"] == 1
    assert await counts() == (1, 0)


async def test_the_stylesheet_and_script_keep_the_strict_content_security_policy(
    client: httpx.AsyncClient,
) -> None:
    for path in ("/static/console.css", "/static/js/passwords.js", "/api/console"):
        answer = await client.get(path)
        assert answer.status_code == 200, path
        assert_strict_csp(answer)
