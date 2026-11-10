"""Every place a password is set goes through the user's password policy (rulings PW3 to PW7).

The six places: ``Users.create`` and ``Users.set_password`` (administrative),
the signed-in change, reset completion, invitation acceptance and the
forced change. Each refuses a password failing each rule, or on a watch
list with the list's reason, and accepts one that passes; a refusal is a
400 naming every failure (or ``PasswordRejected``), audited with codes and
list ids only, and leaves a link usable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from identity_support import RecordingSender, audit_rows
from password_support import (
    COMMON,
    DISPLAY_NAME,
    EMAIL,
    FAILING,
    STRICT,
    STRONG,
    http,
    set_default,
)

from warden.db import Database
from warden.identity import (
    ChangeReason,
    Identity,
    PasswordRejected,
    PasswordRules,
    WatchListKind,
)
from warden.identity.password_policy import UserContext, evaluate

pytestmark = pytest.mark.db

# Each set point: (identity, client, password) -> the failure codes, or [] when accepted.
SetPoint = Callable[[Identity, httpx.AsyncClient, RecordingSender, str], Awaitable[list[str]]]


def _codes(response: httpx.Response) -> list[str]:
    if response.status_code in (200, 204):
        return []
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["detail"] == "password not accepted"
    assert response.headers["cache-control"] == "no-store"
    for failure in body["failures"]:
        assert set(failure) == {"code", "message"}
        assert failure["message"]
    return [f["code"] for f in body["failures"]]


async def _create(
    identity: Identity, c: httpx.AsyncClient, m: RecordingSender, pw: str
) -> list[str]:
    try:
        await identity.users.create(EMAIL, display_name=DISPLAY_NAME, password=pw, actor="test")
    except PasswordRejected as exc:
        return [f.code for f in exc.failures]
    return []


async def _administrator(
    identity: Identity, c: httpx.AsyncClient, m: RecordingSender, pw: str
) -> list[str]:
    user = await identity.users.create(
        EMAIL, display_name=DISPLAY_NAME, password=STRONG, actor="test"
    )
    try:
        await identity.users.set_password(user.id, pw, actor="admin")
    except PasswordRejected as exc:
        return [f.code for f in exc.failures]
    return []


async def _change(
    identity: Identity, c: httpx.AsyncClient, m: RecordingSender, pw: str
) -> list[str]:
    await identity.users.create(EMAIL, display_name=DISPLAY_NAME, password=STRONG, actor="test")
    body = (await c.post("/auth/sign-in", json={"email": EMAIL, "password": STRONG})).json()
    headers = {"authorization": f"Bearer {body['access_token']}"}
    response = await c.post(
        "/auth/password",
        json={"current_password": STRONG, "new_password": pw},
        headers=headers,
    )
    return _codes(response)


async def _reset(
    identity: Identity, c: httpx.AsyncClient, m: RecordingSender, pw: str
) -> list[str]:
    await identity.users.create(EMAIL, display_name=DISPLAY_NAME, password=STRONG, actor="test")
    assert await identity.resets.request(EMAIL) is None
    token = m.token()
    response = await c.post(
        "/auth/password-reset/complete", json={"token": token, "new_password": pw}
    )
    found = _codes(response)
    if found:
        # The link is still usable after a refusal.
        again = await c.post(
            "/auth/password-reset/complete", json={"token": token, "new_password": STRONG + "x"}
        )
        assert again.status_code == 204, again.text
    return found


async def _invitation(
    identity: Identity, c: httpx.AsyncClient, m: RecordingSender, pw: str
) -> list[str]:
    await identity.invitations.create(EMAIL, display_name=DISPLAY_NAME, actor="admin")
    token = m.token()
    response = await c.post("/auth/invitations/accept", json={"token": token, "password": pw})
    found = _codes(response)
    if found:
        again = await c.post("/auth/invitations/accept", json={"token": token, "password": STRONG})
        assert again.status_code == 200, again.text
    return found


async def _forced(
    identity: Identity, c: httpx.AsyncClient, m: RecordingSender, pw: str
) -> list[str]:
    user = await identity.users.create(
        EMAIL, display_name=DISPLAY_NAME, password=STRONG, actor="test"
    )
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    body = (await c.post("/auth/sign-in", json={"email": EMAIL, "password": STRONG})).json()
    assert body["status"] == "password_change_required"
    response = await c.post(
        "/auth/password-change", json={"challenge": body["challenge"], "new_password": pw}
    )
    return _codes(response)


SET_POINTS: dict[str, SetPoint] = {
    "create": _create,
    "administrator": _administrator,
    "change": _change,
    "reset": _reset,
    "invitation": _invitation,
    "forced_change": _forced,
}


def test_the_failing_candidates_each_fail_exactly_their_rule() -> None:
    context = UserContext(EMAIL, DISPLAY_NAME)
    for code, candidate in FAILING.items():
        assert [str(c) for c in evaluate(candidate, STRICT, context).failed] == [code]
    assert evaluate(STRONG, STRICT, context).ok


@pytest.mark.parametrize("place", SET_POINTS)
@pytest.mark.parametrize("rule", FAILING)
async def test_every_set_point_refuses_a_password_failing_each_rule(
    place: str, rule: str, identity: Identity, mail: RecordingSender
) -> None:
    await set_default(identity, rules=STRICT)
    async with http(identity) as c:
        assert await SET_POINTS[place](identity, c, mail, FAILING[rule]) == [rule]


@pytest.mark.parametrize("place", SET_POINTS)
async def test_every_set_point_accepts_a_passing_password(
    place: str, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    await set_default(identity, rules=STRICT)
    async with http(identity) as c:
        assert await SET_POINTS[place](identity, c, mail, "Osprey-Lantern-93#") == []
    user = await identity.users.get_by_email(EMAIL)
    assert user is not None
    assert (await identity.passwords.verify(*(await _hash(db, user.id)), "Osprey-Lantern-93#")).ok
    changed = [r for r in await audit_rows(db, "warden.identity.password.changed")]
    assert changed[-1]["outcome"] == "success"
    assert changed[-1]["resource_id"] == str(user.id)


async def _hash(db: Database, user_id: Any) -> tuple[str]:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT password_hash FROM warden.users WHERE id = %s", (user_id,))
        row = await cur.fetchone()
    assert row is not None
    return (row[0],)


@pytest.mark.parametrize("place", SET_POINTS)
async def test_every_set_point_refuses_a_listed_password_with_the_lists_reason(
    place: str, identity: Identity, mail: RecordingSender, db: Database
) -> None:
    listed = "Tidewater-Copper-58*"
    reason = "This password appeared in the example.org breach"
    watch = await identity.watch_lists.create(
        "Example breach", reason, WatchListKind.MANUAL, actor="admin"
    )
    await identity.watch_lists.add_entries(watch.id, [listed], actor="admin")
    default = await identity.password_policies.default()
    await identity.password_policies.attach(default.id, watch.id, actor="admin")
    await set_default(identity, rules=STRICT)
    async with http(identity) as c:
        if place in ("change", "reset", "invitation", "forced_change"):
            found = await _http_failures(place, identity, c, mail, listed)
            assert found == [{"code": "watch_list", "message": reason}]
        else:
            with pytest.raises(PasswordRejected) as raised:
                if place == "create":
                    await identity.users.create(EMAIL, password=listed, actor="test")
                else:
                    user = await identity.users.create(EMAIL, password=STRONG, actor="test")
                    await identity.users.set_password(user.id, listed, actor="admin")
            assert [(f.code, f.message) for f in raised.value.failures] == [("watch_list", reason)]
    rejected = await audit_rows(db, "warden.identity.password.rejected")
    assert rejected[-1]["details"]["codes"] == ["watch_list"]
    assert rejected[-1]["details"]["list_id"] == str(watch.id)
    assert rejected[-1]["details"]["source"] == "list"


async def _http_failures(
    place: str, identity: Identity, c: httpx.AsyncClient, m: RecordingSender, pw: str
) -> list[dict[str, str]]:
    captured: list[dict[str, str]] = []
    original = c.post

    async def post(url: str, **kw: Any) -> httpx.Response:
        response = await original(url, **kw)
        if response.status_code == 400 and not captured:
            captured.extend(response.json()["failures"])
        return response

    c.post = post  # type: ignore[method-assign]
    try:
        await SET_POINTS[place](identity, c, m, pw)
    finally:
        c.post = original  # type: ignore[method-assign]
    return captured


async def test_a_refusal_names_every_failed_rule_at_once(identity: Identity) -> None:
    await set_default(identity, rules=STRICT)
    with pytest.raises(PasswordRejected) as raised:
        await identity.users.create(EMAIL, display_name=DISPLAY_NAME, password="aa", actor="t")
    assert [f.code for f in raised.value.failures] == ["min_length", "min_classes"]
    assert raised.value.failures[0].message == "Use at least 12 characters"
    assert "aa" not in str(raised.value)


async def test_the_seeded_default_refuses_a_common_password_and_nothing_else_changes(
    identity: Identity, mail: RecordingSender, db: Database
) -> None:
    """PW0 and PW12: the built-in list is the only change on the default policy."""
    with pytest.raises(PasswordRejected) as raised:
        await identity.users.create(EMAIL, password=COMMON, actor="test")
    assert [(f.code, f.message) for f in raised.value.failures] == [
        ("watch_list", "This password is too common")
    ]
    # b18's rule otherwise: twelve characters, nothing more.
    with pytest.raises(PasswordRejected) as short:
        await identity.users.create(EMAIL, password="elevenchars", actor="test")
    assert [f.code for f in short.value.failures] == ["min_length"]
    user = await identity.users.create(EMAIL, password="aaaaaaaaaaab", actor="test")
    assert user.has_password
    rejected = await audit_rows(db, "warden.identity.password.rejected")
    assert rejected[0]["details"]["source"] == "builtin"
    assert rejected[0]["details"]["list_id"] is None


async def test_a_passphrase_skips_the_class_rule_when_the_policy_says_so(
    identity: Identity,
) -> None:
    from warden.identity.password_policy import PassphraseRule

    phrase = "quiet harbour lantern evening"
    rules = PasswordRules(
        min_length=12, min_classes=3, passphrase=PassphraseRule(20, 4, relaxes_classes=True)
    )
    await set_default(identity, rules=rules)
    user = await identity.users.create(EMAIL, password=phrase, actor="test")
    assert user.has_password
    await set_default(
        identity,
        rules=PasswordRules(
            min_length=12, min_classes=3, passphrase=PassphraseRule(20, 4, relaxes_classes=False)
        ),
    )
    with pytest.raises(PasswordRejected) as raised:
        await identity.users.set_password(user.id, phrase + " again", actor="admin")
    assert [f.code for f in raised.value.failures] == ["min_classes"]


async def test_the_tier_and_expiry_are_stored_when_a_password_is_set(
    identity: Identity,
) -> None:
    from warden.identity.password_policy import PassphraseRule, Tier

    rules = PasswordRules(
        min_length=12,
        passphrase=PassphraseRule(20, 4),
        tiers=(
            Tier("passphrase", passphrase=True, max_age_days=365),
            Tier("standard", max_age_days=90),
        ),
    )
    await set_default(identity, rules=rules)
    user = await identity.users.create(EMAIL, password=STRONG, actor="test")
    state = await identity.password_states.get(user.id)
    assert state is not None and state.tier == "standard"
    assert state.password_set_at is not None and state.expires_at is not None
    assert (state.expires_at - state.password_set_at).days == 90
    await identity.users.set_password(user.id, "quiet harbour lantern evening", actor="admin")
    state = await identity.password_states.get(user.id)
    assert state is not None and state.tier == "passphrase"
    assert state.expires_at is not None and state.password_set_at is not None
    assert (state.expires_at - state.password_set_at).days == 365


async def test_setting_a_password_clears_a_required_change(identity: Identity) -> None:
    user = await identity.users.create(EMAIL, password=STRONG, actor="test")
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    await identity.users.set_password(user.id, "Osprey-Lantern-93#", actor="admin")
    state = await identity.password_states.get(user.id)
    assert state is not None and state.change_reason is None


async def test_an_invitation_meets_the_policy_its_staged_roles_resolve_to(
    identity: Identity, mail: RecordingSender, db: Database
) -> None:
    """Skuld question 34, answer (a): as if the staged roles were granted, else the default."""
    from warden.identity import PolicySettings, StagedGrant

    strict = await identity.password_policies.create(
        PolicySettings(name="Analysts", rules=PasswordRules(min_length=20)),
        priority=1,
        actor="admin",
    )
    await identity.password_policies.map_role("analyst", strict.id, actor="admin")
    await identity.invitations.create(
        "analyst@example.com", actor="admin", grants=[StagedGrant("analyst")]
    )
    analyst_token = mail.token()
    await identity.invitations.create(
        "viewer@example.com", actor="admin", grants=[StagedGrant("viewer")]
    )
    viewer_token = mail.token()
    async with http(identity) as c:
        described = await c.post(
            "/auth/invitations/accept/password-policy", json={"token": analyst_token}
        )
        assert described.json()["rules"]["min_length"] == 20
        refused = await c.post(
            "/auth/invitations/accept", json={"token": analyst_token, "password": STRONG}
        )
        assert [f["code"] for f in refused.json()["failures"]] == ["min_length"]
        accepted = await c.post(
            "/auth/invitations/accept",
            json={"token": analyst_token, "password": "Kestrel-Harbour-Lantern-42!"},
        )
        assert accepted.status_code == 200
        # A role mapped to no policy: the default (twelve characters).
        viewer = await c.post(
            "/auth/invitations/accept", json={"token": viewer_token, "password": STRONG}
        )
        assert viewer.status_code == 200
    analyst = await identity.users.get_by_email("analyst@example.com")
    assert analyst is not None
    assert (await identity.password_policies.effective(analyst.id)).policy.id == strict.id
    changed = await audit_rows(db, "warden.identity.password.changed")
    assert {r["details"]["policy_id"] for r in changed if r["resource_id"] == str(analyst.id)} == {
        str(strict.id)
    }


async def test_a_bad_link_is_refused_uniformly_whatever_the_password(
    identity: Identity,
) -> None:
    """Nothing about a policy reaches a caller without a live link."""
    async with http(identity) as c:
        for path, body in (
            ("/auth/password-reset/complete", {"token": "A" * 43, "new_password": "short"}),
            ("/auth/invitations/accept", {"token": "A" * 43, "password": "short"}),
        ):
            response = await c.post(path, json=body)
            assert response.status_code == 401
            assert response.content == b'{"detail":"authentication failed"}'
