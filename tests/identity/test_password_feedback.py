"""Live password feedback (ruling PW10) at the four places a password is set.

Each place has a route describing the applicable policy and a check route
returning each rule's result, the passphrase and tier, and any watch-list
match with its reason. Both are bound to the place's own credential (a
session, a reset link, an invitation link, a forced-change challenge),
never check history, store nothing, audit nothing, answer ``no-store`` and
are throttled per credential and source address; a caller without a valid
credential gets the uniform refusal and learns nothing.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from identity_support import FAST_HASHER, MemorySecrets, RecordingSender, audit_rows
from password_support import OTHER_STRONG, STRICT, STRONG, http, pin_policy, set_default

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import (
    ChangeReason,
    Identity,
    PasswordRules,
    PermissionRegistry,
    PolicySettings,
    WatchListKind,
)
from warden.keys import KeyStore

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'
VECTORS = Path(__file__).resolve().parents[2] / "docs" / "contract" / "password-rule-vectors.json"
PLACES = ("signed_in", "reset", "invitation", "forced_change")


@asynccontextmanager
async def _place(
    identity: Identity, mail: RecordingSender, place: str, c: httpx.AsyncClient
) -> AsyncIterator[tuple[str, str, dict[str, Any], dict[str, str]]]:
    """For one place: (policy path, check path, the credential's body, headers)."""
    if place == "invitation":
        await identity.invitations.create("invitee@example.com", actor="admin")
        body = {"token": mail.token()}
        yield (
            "/auth/invitations/accept/password-policy",
            "/auth/invitations/accept/password-check",
            body,
            {},
        )
        return
    user = await identity.users.create("member@example.com", password=STRONG, actor="test")
    if place == "reset":
        await identity.resets.request(user.email)
        yield (
            "/auth/password-reset/policy",
            "/auth/password-reset/check",
            {"token": mail.token()},
            {},
        )
        return
    if place == "forced_change":
        await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    answer = (await c.post("/auth/sign-in", json={"email": user.email, "password": STRONG})).json()
    if place == "forced_change":
        yield (
            "/auth/password-change/policy",
            "/auth/password-change/check",
            {"challenge": answer["challenge"]},
            {},
        )
        return
    headers = {"authorization": f"Bearer {answer['access_token']}"}
    yield "/auth/password/policy", "/auth/password/check", {}, headers


async def _policy(
    c: httpx.AsyncClient, path: str, body: dict[str, Any], headers: dict[str, str]
) -> httpx.Response:
    if path == "/auth/password/policy":
        return await c.get(path, headers=headers)
    return await c.post(path, json=body, headers=headers)


async def _counts(db: Database) -> tuple[int, int, int, int]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT (SELECT count(*) FROM warden.audit_events),"
            " (SELECT count(*) FROM warden.password_history),"
            " (SELECT count(*) FROM warden.password_states),"
            " (SELECT count(*) FROM warden.single_use_tokens WHERE consumed_at IS NOT NULL)"
        )
        row = await cur.fetchone()
    assert row is not None
    return (int(row[0]), int(row[1]), int(row[2]), int(row[3]))


@pytest.mark.parametrize("place", PLACES)
async def test_each_place_describes_its_policy_and_checks_a_candidate(
    place: str, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    reason = "Seen in the example.com breach"
    watch = await identity.watch_lists.create("Breach", reason, WatchListKind.MANUAL, actor="a")
    await identity.watch_lists.add_entries(watch.id, ["Tidewater-Copper-58*"], actor="a")
    default = await identity.password_policies.default()
    await identity.password_policies.attach(default.id, watch.id, actor="a")
    await set_default(identity, rules=STRICT, history_count=5)
    async with http(identity) as c, _place(identity, mail, place, c) as (pp, cp, body, headers):
        before = await _counts(db)
        described = await _policy(c, pp, body, headers)
        assert described.status_code == 200, described.text
        assert described.headers["cache-control"] == "no-store"
        assert described.json() == {"rules": STRICT.describe(), "history_count": 5}

        checked = await c.post(cp, json={**body, "password": "Ab1!"}, headers=headers)
        assert checked.status_code == 200, checked.text
        assert checked.headers["cache-control"] == "no-store"
        result = checked.json()
        assert result["ok"] is False
        assert [(r["code"], r["passed"]) for r in result["results"]] == [
            ("min_length", False),
            ("max_length", True),
            ("min_classes", True),
            ("max_repeat", True),
            ("no_email", True),
            ("no_display_name", True),
        ]
        assert result["results"][0]["message"] == "Use at least 12 characters"
        assert result["watch_list"] is None and result["watch_list_unavailable"] is False

        listed = await c.post(
            cp, json={**body, "password": "Tidewater-Copper-58*"}, headers=headers
        )
        assert listed.json()["watch_list"] == {"reason": reason}
        assert listed.json()["ok"] is False
        assert str(watch.id) not in listed.text

        # History is never checked here: the current password checks as fine.
        current = await c.post(cp, json={**body, "password": STRONG}, headers=headers)
        assert current.json()["ok"] is True
        assert await _counts(db) == before


@pytest.mark.parametrize("place", PLACES)
async def test_each_place_refuses_a_caller_without_a_valid_credential(
    place: str, identity: Identity, mail: RecordingSender
) -> None:
    async with http(identity) as c, _place(identity, mail, place, c) as (pp, cp, body, headers):
        if headers:
            bad_headers = {"authorization": "Bearer not-a-token"}
            attempts = [({}, {}), ({}, bad_headers)]
        else:
            key = next(iter(body))
            attempts = [({}, {}), ({key: "A" * 43}, {}), ({key: 5}, {}), ({key: ""}, {})]
        for sent, sent_headers in attempts:
            for response in (
                await _policy(c, pp, sent, sent_headers),
                await c.post(cp, json={**sent, "password": STRONG}, headers=sent_headers),
                await c.post(cp, json=sent, headers=sent_headers),
            ):
                assert response.status_code == 401, (sent, response.text)
                assert response.content == REFUSAL
                assert response.headers["cache-control"] == "no-store"


async def test_a_used_reset_link_reveals_nothing(identity: Identity, mail: RecordingSender) -> None:
    await identity.users.create("member@example.com", password=STRONG, actor="test")
    await identity.resets.request("member@example.com")
    token = mail.token()
    async with http(identity) as c:
        done = await c.post(
            "/auth/password-reset/complete", json={"token": token, "new_password": OTHER_STRONG}
        )
        assert done.status_code == 204
        for response in (
            await c.post("/auth/password-reset/policy", json={"token": token}),
            await c.post("/auth/password-reset/check", json={"token": token, "password": "x"}),
        ):
            assert response.status_code == 401 and response.content == REFUSAL


async def test_a_missing_candidate_is_a_400_only_with_a_valid_credential(
    identity: Identity, mail: RecordingSender
) -> None:
    async with http(identity) as c, _place(identity, mail, "reset", c) as (_, cp, body, _h):
        missing = await c.post(cp, json=body)
        assert missing.status_code == 400
        assert missing.json() == {"detail": "send the candidate password as a string"}


@pytest.fixture
def identity(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
) -> Identity:
    return Identity(
        config,
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        mail_sender=mail,
        password_check_limit=4,
    )


@pytest.mark.parametrize("place", PLACES)
async def test_each_place_is_throttled_per_credential(
    place: str, identity: Identity, mail: RecordingSender
) -> None:
    async with http(identity) as c, _place(identity, mail, place, c) as (pp, cp, body, headers):
        for _ in range(2):
            assert (await _policy(c, pp, body, headers)).status_code == 200
            ok = await c.post(cp, json={**body, "password": STRONG}, headers=headers)
            assert ok.status_code == 200
        spent = await c.post(cp, json={**body, "password": STRONG}, headers=headers)
        assert spent.status_code == 401 and spent.content == REFUSAL
        assert (await _policy(c, pp, body, headers)).status_code == 401


async def test_the_check_routes_are_throttled_per_source_address(
    identity: Identity, mail: RecordingSender
) -> None:
    """An address gets five times the per-credential budget, across credentials."""
    for n in range(6):
        await identity.users.create(f"member{n}@example.com", password=STRONG, actor="test")
        await identity.resets.request(f"member{n}@example.com")
    tokens = [mail.token(i) for i in range(6)]
    async with http(identity) as c:
        answers = []
        for token in tokens:
            for _ in range(4):
                answers.append(
                    await c.post(
                        "/auth/password-reset/check", json={"token": token, "password": "x"}
                    )
                )
        assert [a.status_code for a in answers[:20]] == [200] * 20
        assert all(a.status_code == 401 for a in answers[20:])
    async with http(identity, address="198.51.100.7") as other:
        fresh = await other.post(
            "/auth/password-reset/check", json={"token": tokens[5], "password": "x"}
        )
    # The sixth token's own budget was spent from the first address.
    assert fresh.status_code == 401


async def test_the_range_api_answer_is_part_of_the_check(
    identity: Identity, mail: RecordingSender
) -> None:
    from hibp_stub import failing_transport, listing_transport

    from warden.identity import HibpRangeClient

    breached = "Marigold-Thunder-15&"
    identity.watch_lists.hibp = HibpRangeClient(
        identity.config.passwords, transport=listing_transport(breached)
    )
    await set_default(identity, hibp_enabled=True)
    async with http(identity) as c, _place(identity, mail, "reset", c) as (_, cp, body, _h):
        found = (await c.post(cp, json={**body, "password": breached})).json()
        assert found["watch_list"] == {"reason": "This password has appeared in a data breach"}
        identity.watch_lists.hibp = HibpRangeClient(
            identity.config.passwords, transport=failing_transport()
        )
        down = (await c.post(cp, json={**body, "password": breached})).json()
        assert down["watch_list_unavailable"] is True and down["ok"] is True
        await set_default(identity, hibp_on_unavailable="refuse")
        refused = (await c.post(cp, json={**body, "password": breached})).json()
        assert refused["watch_list_unavailable"] is True and refused["ok"] is False


def _vectors() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(VECTORS.read_text(encoding="utf-8"))
    return data


async def test_the_vectors_file_and_the_server_agree_through_the_check_route(
    db: Database,
    keys: KeyStore,
    config: WardenConfig,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    """Every case in docs/contract/password-rule-vectors.json, through ``/password/check``."""
    identity = Identity(
        config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER, password_check_limit=500
    )
    vectors = _vectors()
    policies = {}
    for name, description in vectors["policies"].items():
        policies[name] = await identity.password_policies.create(
            PolicySettings(
                name=f"vectors {name}", rules=PasswordRules.from_description(description)
            ),
            priority=len(policies) + 1,
            actor="test",
        )
    users: dict[str, Any] = {}
    checked = 0
    async with http(identity) as c:
        for case in vectors["cases"]:
            context = case["user"] or {"email": "q0@example.net", "display_name": None}
            key = json.dumps(context, sort_keys=True)
            if key not in users:
                user = await identity.users.create(
                    context["email"],
                    display_name=context["display_name"],
                    password=STRONG,
                    actor="test",
                )
                answer = (
                    await c.post("/auth/sign-in", json={"email": user.email, "password": STRONG})
                ).json()
                users[key] = (user, {"authorization": f"Bearer {answer['access_token']}"})
            user, headers = users[key]
            await identity.password_policies.pin(user.id, policies[case["policy"]].id, actor="t")
            response = await c.post(
                "/auth/password/check", json={"password": case["password"]}, headers=headers
            )
            assert response.status_code == 200, (case["name"], response.text)
            body = response.json()
            expected = case["expected"]
            assert [
                {"code": r["code"], "passed": r["passed"], "waived": r["waived"]}
                for r in body["results"]
            ] == expected["results"], case["name"]
            assert body["passphrase"] is expected["passphrase"], case["name"]
            assert body["tier"] == expected["tier"], case["name"]
            if body["watch_list"] is None:
                assert body["ok"] is expected["ok"], case["name"]
            checked += 1
    assert checked == len(vectors["cases"])


async def test_a_pinned_policy_is_the_one_described(
    identity: Identity, mail: RecordingSender
) -> None:
    user = await identity.users.create("member@example.com", password=STRONG, actor="test")
    pinned = PasswordRules(min_length=16)
    await pin_policy(identity, user, rules=pinned, history_count=2)
    async with http(identity) as c:
        answer = (
            await c.post("/auth/sign-in", json={"email": user.email, "password": STRONG})
        ).json()
        headers = {"authorization": f"Bearer {answer['access_token']}"}
        described = await c.get("/auth/password/policy", headers=headers)
    assert described.json() == {"rules": pinned.describe(), "history_count": 2}
    assert not [r for r in await audit_rows(identity.db, "warden.identity.password.rejected")]
