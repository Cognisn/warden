"""Password policies at sign-in (rulings PW5, PW8, PW9 and PW11).

After a correct password the plaintext is checked against the effective
policy's watch lists, re-evaluated against the current rules (tier and
expiry recomputed from when it was set), and its expiry checked; any of
these, or an administrator's flag, makes the sign-in answer
``password_change_required`` where it would have issued a session: after
the second factor, never before. The change is completed with the
single-use challenge and a new password, and issues the session the
sign-in would have, with the same ``amr``.
"""

from __future__ import annotations

import base64
import time
import uuid
from typing import Any

import httpx
import pytest
from identity_support import (
    FAST_HASHER,
    MemorySecrets,
    RecordingSender,
    audit_rows,
    current_code,
    enrol_totp,
    make_config,
    race,
)
from password_support import (
    COMMON,
    OTHER_STRONG,
    STRICT,
    STRONG,
    Clock,
    http,
    set_default,
)

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import (
    ChangeReason,
    Identity,
    PasswordRules,
    PermissionRegistry,
    User,
    UserStatus,
    WatchListKind,
)
from warden.identity.password_policy import Tier
from warden.identity.totp import code_at, step_for
from warden.keys import KeyStore

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'
EXPIRING = PasswordRules(min_length=12, tiers=(Tier("standard", max_age_days=30),), warning_days=14)


@pytest.fixture
def clock() -> Clock:
    return Clock(time.time)


@pytest.fixture
def identity(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
    clock: Clock,
) -> Identity:
    return Identity(
        config,
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        mail_sender=mail,
        clock=clock,
    )


async def _user(identity: Identity, password: str = STRONG, **kw: Any) -> User:
    return await identity.users.create(
        f"user-{uuid.uuid4().hex[:8]}@example.com", password=password, actor="test", **kw
    )


async def _sign_in(c: httpx.AsyncClient, user: User, password: str = STRONG) -> dict[str, Any]:
    response = await c.post("/auth/sign-in", json={"email": user.email, "password": password})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def _legacy_password(db: Database, user: User, password: str) -> None:
    """Set a password behind the policy's back, as one set before enforcement began."""
    digest = await FAST_HASHER.hash(password)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.users SET password_hash = %s WHERE id = %s", (digest, user.id)
        )
        await conn.execute("DELETE FROM warden.password_states WHERE user_id = %s", (user.id,))
        await conn.execute("DELETE FROM warden.password_history WHERE user_id = %s", (user.id,))


async def _complete(c: httpx.AsyncClient, challenge: str, new: str) -> httpx.Response:
    return await c.post("/auth/password-change", json={"challenge": challenge, "new_password": new})


async def _amr(identity: Identity, access_token: str) -> list[str]:
    principal = await identity.authenticate(access_token)
    return list(principal.amr)


async def _sessions(db: Database, user: User) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s AND revoked_at IS NULL",
            (user.id,),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


# Watch lists at sign-in (PW8)


async def test_a_password_on_the_built_in_list_must_change_at_sign_in(
    identity: Identity, db: Database
) -> None:
    user = await _user(identity, password=None)  # type: ignore[arg-type]
    await _legacy_password(db, user, COMMON)
    async with http(identity) as c:
        body = await _sign_in(c, user, COMMON)
    assert body["status"] == "password_change_required"
    assert body["reason"] == "watch_list"
    assert body["watch_list_reason"] == "This password is too common"
    assert body["expires_in"] == 300 and body["challenge"]
    assert "access_token" not in body
    state = await identity.password_states.get(user.id)
    assert state is not None and state.change_reason is ChangeReason.WATCH_LIST
    flagged = await audit_rows(db, "warden.identity.password.change_required")
    assert flagged[0]["details"]["trigger"] == "sign_in"
    assert flagged[0]["details"]["source"] == "builtin"
    assert COMMON not in str(await audit_rows(db))


async def test_a_password_added_to_a_watch_list_must_change_with_the_lists_reason(
    identity: Identity, db: Database
) -> None:
    user = await _user(identity)
    reason = "Seen in the example.net breach"
    watch = await identity.watch_lists.create("Breach", reason, WatchListKind.MANUAL, actor="a")
    await identity.watch_lists.add_entries(watch.id, [STRONG], actor="a")
    default = await identity.password_policies.default()
    await identity.password_policies.attach(default.id, watch.id, actor="a")
    async with http(identity) as c:
        body = await _sign_in(c, user)
        assert body["status"] == "password_change_required"
        assert (body["reason"], body["watch_list_reason"]) == ("watch_list", reason)
        done = await _complete(c, body["challenge"], OTHER_STRONG)
        assert done.status_code == 200, done.text
        assert done.json()["status"] == "signed_in"
        again = await _sign_in(c, user, OTHER_STRONG)
    assert again["status"] == "signed_in"
    flagged = await audit_rows(db, "warden.identity.password.change_required")
    assert flagged[0]["details"]["list_id"] == str(watch.id)


async def test_the_range_api_being_unavailable_never_stops_a_sign_in(
    identity: Identity, db: Database
) -> None:
    from hibp_stub import failing_transport

    from warden.identity import HibpRangeClient

    user = await _user(identity)
    identity.watch_lists.hibp = HibpRangeClient(
        identity.config.passwords, transport=failing_transport()
    )
    await set_default(identity, hibp_enabled=True, hibp_on_unavailable="refuse")
    async with http(identity) as c:
        assert (await _sign_in(c, user))["status"] == "signed_in"
    rows = await audit_rows(db, "warden.identity.password.watch_list_unavailable")
    assert rows[-1]["details"] == {"via": "sign_in", "on_unavailable": "refuse"}


# Re-evaluation against the current policy (PW11)


async def test_a_policy_enforced_on_sign_in_forces_a_change_after_an_edit(
    identity: Identity,
) -> None:
    user = await _user(identity, password="plainlowercaseonly")
    await set_default(identity, rules=STRICT, enforce_on_sign_in=True)
    async with http(identity) as c:
        body = await _sign_in(c, user, "plainlowercaseonly")
        assert (body["status"], body["reason"]) == ("password_change_required", "policy")
        assert "watch_list_reason" not in body
        refused = await _complete(c, body["challenge"], "stilllowercaseonly")
        assert refused.status_code == 400
        assert [f["code"] for f in refused.json()["failures"]] == ["min_classes"]
        done = await _complete(c, body["challenge"], STRONG)
        assert done.status_code == 200, done.text


async def test_a_policy_not_enforced_on_sign_in_lets_the_password_carry_on(
    identity: Identity,
) -> None:
    user = await _user(identity, password="plainlowercaseonly")
    await set_default(identity, rules=STRICT, enforce_on_sign_in=False)
    async with http(identity) as c:
        assert (await _sign_in(c, user, "plainlowercaseonly"))["status"] == "signed_in"
    state = await identity.password_states.get(user.id)
    assert state is not None and state.change_reason is None


async def test_the_tier_and_expiry_are_recomputed_from_when_the_password_was_set(
    identity: Identity, clock: Clock
) -> None:
    user = await _user(identity)
    before = await identity.password_states.get(user.id)
    assert before is not None and before.tier is None and before.expires_at is None
    assert before.password_set_at is not None
    clock.advance(days=10)
    await set_default(identity, rules=EXPIRING)
    async with http(identity) as c:
        assert (await _sign_in(c, user))["status"] == "signed_in"
    after = await identity.password_states.get(user.id)
    assert after is not None and after.tier == "standard"
    assert after.password_set_at == before.password_set_at
    assert after.expires_at is not None
    assert (after.expires_at - before.password_set_at).days == 30


async def test_a_password_set_before_enforcement_starts_its_clock_at_the_first_sign_in(
    identity: Identity, db: Database
) -> None:
    await set_default(identity, rules=EXPIRING)
    user = await _user(identity)
    await _legacy_password(db, user, STRONG)
    async with http(identity) as c:
        assert (await _sign_in(c, user))["status"] == "signed_in"
    state = await identity.password_states.get(user.id)
    assert state is not None and state.password_set_at is not None
    assert state.expires_at is not None
    assert (state.expires_at - state.password_set_at).days == 30


# Expiry, with a test clock (PW5)


async def test_an_expired_password_must_change(
    identity: Identity, clock: Clock, db: Database
) -> None:
    await set_default(identity, rules=EXPIRING)
    user = await _user(identity)
    clock.advance(days=30, hours=1)
    async with http(identity) as c:
        body = await _sign_in(c, user)
        assert (body["status"], body["reason"]) == ("password_change_required", "expired")
        done = await _complete(c, body["challenge"], OTHER_STRONG)
        assert done.status_code == 200
    expired = await audit_rows(db, "warden.identity.password.expired")
    assert [r["resource_id"] for r in expired] == [str(user.id)]
    state = await identity.password_states.get(user.id)
    assert state is not None and state.change_reason is None
    assert state.expires_at is not None and state.password_set_at is not None


async def test_a_password_just_short_of_its_expiry_signs_in(
    identity: Identity, clock: Clock
) -> None:
    await set_default(identity, rules=EXPIRING)
    user = await _user(identity)
    clock.advance(days=29, hours=23)
    async with http(identity) as c:
        body = await _sign_in(c, user)
    assert body["status"] == "signed_in"
    assert body["password_expires_in_days"] == 1


async def test_the_warning_appears_only_within_the_window(identity: Identity, clock: Clock) -> None:
    await set_default(identity, rules=EXPIRING)
    user = await _user(identity)
    async with http(identity) as c:
        clock.advance(days=15)  # 15 days left, window is 14
        assert "password_expires_in_days" not in await _sign_in(c, user)
        clock.advance(days=10)  # 5 days left
        assert (await _sign_in(c, user))["password_expires_in_days"] == 5


# The administrator's flag, and the forced change end to end (PW9)


@pytest.mark.parametrize("reason", list(ChangeReason))
async def test_the_forced_change_for_each_reason_end_to_end(
    reason: ChangeReason, identity: Identity, clock: Clock, db: Database
) -> None:
    user = await _user(identity, password="plainlowercaseonly")
    if reason is ChangeReason.WATCH_LIST:
        watch = await identity.watch_lists.create("w", "Listed", WatchListKind.MANUAL, actor="a")
        await identity.watch_lists.add_entries(watch.id, ["plainlowercaseonly"], actor="a")
        default = await identity.password_policies.default()
        await identity.password_policies.attach(default.id, watch.id, actor="a")
    elif reason is ChangeReason.POLICY:
        await set_default(identity, rules=STRICT, enforce_on_sign_in=True)
    elif reason is ChangeReason.EXPIRED:
        await set_default(identity, rules=EXPIRING)
        await identity.users.set_password(user.id, "plainlowercaseonly2", actor="a")
        clock.advance(days=31)
    else:
        await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    password = "plainlowercaseonly2" if reason is ChangeReason.EXPIRED else "plainlowercaseonly"
    async with http(identity) as c:
        body = await _sign_in(c, user, password)
        assert body["status"] == "password_change_required"
        assert body["reason"] == reason.value
        assert await _sessions(db, user) == 0
        done = await _complete(c, body["challenge"], STRONG)
        assert done.status_code == 200, done.text
        signed_in = done.json()
        assert signed_in["status"] == "signed_in"
        assert await _amr(identity, signed_in["access_token"]) == ["pwd"]
        # The old password no longer works; the new one signs in normally.
        old = await c.post("/auth/sign-in", json={"email": user.email, "password": password})
        assert old.status_code == 401 and old.content == REFUSAL
        assert (await _sign_in(c, user, STRONG))["status"] == "signed_in"
    completed = await audit_rows(db, "warden.identity.password.change_completed")
    assert completed[-1]["outcome"] == "success"
    assert completed[-1]["details"]["reason"] == reason.value
    changed = await audit_rows(db, "warden.identity.password.changed")
    assert changed[-1]["details"]["via"] == "forced_change"


async def test_the_second_factor_comes_before_the_change(identity: Identity, db: Database) -> None:
    user = await _user(identity)
    secret = await enrol_totp(identity, user)
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        first = await _sign_in(c, user)
        # Holding only the password reveals nothing about the change.
        assert first["status"] == "mfa_required"
        assert set(first) == {"status", "challenge", "expires_in", "methods"}
        # The MFA challenge cannot be used to change the password.
        assert (await _complete(c, first["challenge"], OTHER_STRONG)).status_code == 401
        verified = await c.post(
            "/auth/totp/verify",
            json={"challenge": first["challenge"], "code": current_code(secret, 1)},
        )
        body = verified.json()
        assert (body["status"], body["reason"]) == ("password_change_required", "administrator")
        assert await _sessions(db, user) == 0
        done = await _complete(c, body["challenge"], OTHER_STRONG)
        assert done.status_code == 200
        assert await _amr(identity, done.json()["access_token"]) == ["pwd", "otp"]


async def test_a_recovery_code_then_the_change_keeps_its_amr(identity: Identity) -> None:
    user = await _user(identity)
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(
        user.id, current_code(enrolment.secret), actor="test"
    )
    assert codes
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        first = await _sign_in(c, user)
        used = await c.post(
            "/auth/recovery-code", json={"challenge": first["challenge"], "code": codes[0]}
        )
        body = used.json()
        assert body["status"] == "password_change_required"
        done = await _complete(c, body["challenge"], OTHER_STRONG)
        assert await _amr(identity, done.json()["access_token"]) == ["pwd", "recovery_code"]


async def test_a_forced_enrolment_then_the_change_returns_the_recovery_codes(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    identity = Identity(
        make_config(require_mfa=True), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER
    )
    user = await _user(identity)
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        first = await _sign_in(c, user)
        assert first["status"] == "mfa_enrolment_required"
        begun = await c.post("/auth/totp/enrolment", json={"challenge": first["challenge"]})
        encoded = begun.json()["secret"]
        secret = base64.b32decode(encoded + "=" * (-len(encoded) % 8))
        confirmed = await c.post(
            "/auth/totp/enrolment/confirm",
            json={"challenge": first["challenge"], "code": code_at(secret, step_for(time.time()))},
        )
        body = confirmed.json()
        assert body["status"] == "password_change_required"
        assert len(body["recovery_codes"]) == 10
        assert "access_token" not in body
        done = await _complete(c, body["challenge"], OTHER_STRONG)
        assert await _amr(identity, done.json()["access_token"]) == ["pwd", "otp"]


async def test_the_change_challenge_is_used_once_under_concurrency(
    identity: Identity, db: Database
) -> None:
    user = await _user(identity)
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        body = await _sign_in(c, user)
        answers = await race(
            lambda: _complete(c, body["challenge"], OTHER_STRONG),
            lambda: _complete(c, body["challenge"], "Copper-Willow-61%"),
        )
    statuses = sorted(a.status_code for a in answers)
    assert statuses == [200, 401]
    assert await _sessions(db, user) == 1
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.password_history WHERE user_id = %s", (user.id,)
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 2  # the first password, and one change
    completed = await audit_rows(db, "warden.identity.password.change_completed")
    assert sorted(r["outcome"] for r in completed) == ["failure", "success"]
    assert [r["details"] for r in completed if r["outcome"] == "failure"] == [
        {"reason": "challenge_used"}
    ]


async def test_refused_passwords_use_up_the_challenges_attempts(identity: Identity) -> None:
    user = await _user(identity)
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        body = await _sign_in(c, user)
        for _ in range(identity.config.identity.mfa_max_failures):
            assert (await _complete(c, body["challenge"], "short")).status_code == 400
        last = await _complete(c, body["challenge"], OTHER_STRONG)
    assert last.status_code == 401 and last.content == REFUSAL


async def test_a_user_suspended_after_the_challenge_gets_nothing(
    identity: Identity, db: Database
) -> None:
    user = await _user(identity)
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        body = await _sign_in(c, user)
        await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="a")
        refused = await _complete(c, body["challenge"], OTHER_STRONG)
    assert refused.status_code == 401 and refused.content == REFUSAL
    assert await _sessions(db, user) == 0
    reasons = await audit_rows(db, "warden.identity.password.change_completed")
    assert reasons[-1]["details"] == {"reason": "user_inactive"}


async def test_a_tampered_challenge_tag_names_no_challenge(identity: Identity) -> None:
    """The amr travels in the token; altering it changes the hash, so nothing matches."""
    user = await _user(identity)
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        body = await _sign_in(c, user)
        assert body["challenge"].startswith("p")
        forged = "h" + body["challenge"][1:]
        assert (await _complete(c, forged, OTHER_STRONG)).status_code == 401
        assert (await _complete(c, body["challenge"], OTHER_STRONG)).status_code == 200


# Failed sign-ins keep the uniform refusal


async def test_a_flagged_user_with_a_wrong_password_gets_the_uniform_refusal(
    identity: Identity, db: Database
) -> None:
    user = await _user(identity)
    await identity.password_states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    async with http(identity) as c:
        wrong = await c.post("/auth/sign-in", json={"email": user.email, "password": "nope"})
        unknown = await c.post(
            "/auth/sign-in", json={"email": "nobody@example.com", "password": STRONG}
        )
    for response in (wrong, unknown):
        assert response.status_code == 401
        assert response.content == REFUSAL
        assert response.headers["cache-control"] == "no-store"
    assert wrong.headers == unknown.headers
    await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="a")
    async with http(identity) as c:
        inactive = await c.post("/auth/sign-in", json={"email": user.email, "password": STRONG})
    assert inactive.content == REFUSAL and inactive.headers == wrong.headers


async def test_failed_sign_in_timing_is_unchanged_by_the_passwords_state(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    """#133 bounds: a flagged user's wrong password, a listed wrong password, a plain
    wrong password and an unknown address take indistinguishable time (production cost)."""
    import statistics

    from warden.identity.passwords import PasswordHasher

    identity = Identity(
        config,
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=PasswordHasher(),
        sign_in_attempt_limit=1000,
    )
    watch = await identity.watch_lists.create("w", "Listed", WatchListKind.MANUAL, actor="a")
    await identity.watch_lists.add_entries(watch.id, [COMMON, "wrong " + STRONG], actor="a")
    default = await identity.password_policies.default()
    await identity.password_policies.attach(default.id, watch.id, actor="a")
    plain = await identity.users.create("plain@example.com", password=STRONG, actor="t")
    flagged = await identity.users.create("flagged@example.com", password=STRONG, actor="t")
    await identity.password_states.require_change(flagged.id, ChangeReason.ADMINISTRATOR)
    cases = {
        "unknown": ("nobody-here@example.com", STRONG),
        "wrong_password": (plain.email, "wrong " + OTHER_STRONG),
        "wrong_password_flagged": (flagged.email, "wrong " + OTHER_STRONG),
        "wrong_password_listed": (plain.email, "wrong " + STRONG),
    }
    samples: dict[str, list[float]] = {name: [] for name in cases}
    async with http(identity) as c:
        for email, password in cases.values():  # warm-up
            await c.post("/auth/sign-in", json={"email": email, "password": password})
        for _ in range(12):
            for name, (email, password) in cases.items():
                start = time.perf_counter()
                response = await c.post(
                    "/auth/sign-in", json={"email": email, "password": password}
                )
                samples[name].append(time.perf_counter() - start)
                assert response.status_code == 401 and response.content == REFUSAL
    medians = {name: statistics.median(values) for name, values in samples.items()}
    assert min(medians.values()) / max(medians.values()) > 0.75, medians


# History (PW6) and minimum age


async def test_history_refuses_each_of_the_last_n_and_accepts_the_one_before(
    identity: Identity,
) -> None:
    from warden.identity import PasswordRejected

    await set_default(identity, history_count=3)
    passwords = [f"Harbour-Kestrel-{n:02d}!" for n in range(5)]
    user = await _user(identity, password=passwords[0])
    for password in passwords[1:]:
        await identity.users.set_password(user.id, password, actor="a")
    # The last three: passwords[2], [3] and [4] (the current one).
    for reused in passwords[2:]:
        with pytest.raises(PasswordRejected) as raised:
            await identity.users.set_password(user.id, reused, actor="a")
        assert [(f.code, f.message) for f in raised.value.failures] == [
            ("history", "Choose a password you have not used recently")
        ]
    await identity.users.set_password(user.id, passwords[1], actor="a")


async def test_history_counts_a_password_set_before_enforcement_began(
    identity: Identity, db: Database
) -> None:
    from warden.identity import PasswordRejected

    await set_default(identity, history_count=1)
    user = await _user(identity)
    await _legacy_password(db, user, OTHER_STRONG)
    with pytest.raises(PasswordRejected):
        await identity.users.set_password(user.id, OTHER_STRONG, actor="a")


async def test_the_minimum_age_limits_only_the_users_own_change(
    identity: Identity, clock: Clock, mail: RecordingSender
) -> None:
    await set_default(identity, min_age_hours=24)
    user = await _user(identity)
    async with http(identity) as c:
        body = await _sign_in(c, user)
        headers = {"authorization": f"Bearer {body['access_token']}"}
        too_soon = await c.post(
            "/auth/password",
            json={"current_password": STRONG, "new_password": OTHER_STRONG},
            headers=headers,
        )
        assert too_soon.status_code == 400
        assert [f["code"] for f in too_soon.json()["failures"]] == ["min_age"]
        # A reset is never blocked by it.
        await identity.resets.request(user.email)
        reset = await c.post(
            "/auth/password-reset/complete",
            json={"token": mail.token(), "new_password": OTHER_STRONG},
        )
        assert reset.status_code == 204
        clock.advance(hours=25)
        body = await _sign_in(c, user, OTHER_STRONG)
        headers = {"authorization": f"Bearer {body['access_token']}"}
        later = await c.post(
            "/auth/password",
            json={"current_password": OTHER_STRONG, "new_password": STRONG},
            headers=headers,
        )
    assert later.status_code == 204, later.text


async def test_two_concurrent_changes_leave_one_history_entry_each_and_a_consistent_state(
    identity: Identity, db: Database
) -> None:
    user = await _user(identity)
    results = await race(
        lambda: identity.users.set_password(user.id, OTHER_STRONG, actor="a"),
        lambda: identity.users.set_password(user.id, "Copper-Willow-61%", actor="b"),
    )
    assert not [r for r in results if isinstance(r, BaseException)]
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT password_hash FROM warden.password_history WHERE user_id = %s"
            " ORDER BY set_at DESC, id DESC",
            (user.id,),
        )
        history = [r[0] for r in await cur.fetchall()]
        cur = await conn.execute("SELECT password_hash FROM warden.users WHERE id = %s", (user.id,))
        row = await cur.fetchone()
    assert row is not None
    assert len(history) == 3
    assert row[0] in history[:2]
    matching = [
        p for p in (OTHER_STRONG, "Copper-Willow-61%") if (await FAST_HASHER.verify(row[0], p)).ok
    ]
    assert len(matching) == 1
    state = await identity.password_states.get(user.id)
    assert state is not None and state.change_reason is None


# Fingerprints (PW8)


async def test_the_fingerprint_is_written_at_sign_in_when_the_policy_keeps_one(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    from warden.config import parse_config
    from warden.identity.crypto import new_totp_key

    secrets.set("warden.password-fingerprint", new_totp_key())
    config = parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "identity": {"require_mfa": False},
            "passwords": {"fingerprint_key_secret": "warden.password-fingerprint"},
        }
    )
    identity = Identity(config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    user = await _user(identity)
    state = await identity.password_states.get(user.id)
    assert state is not None and not state.has_fingerprint
    await set_default(identity, fingerprint_enabled=True)
    async with http(identity) as c:
        assert (await _sign_in(c, user))["status"] == "signed_in"
    sealed = await identity.password_states.fingerprint(user.id)
    assert sealed is not None
    opened = identity.password_fingerprints.open(user.id, sealed)
    from warden.identity.password_policy import password_digest

    assert opened is not None and opened.digest == password_digest(STRONG)
    # Setting a new password replaces it.
    await identity.users.set_password(user.id, OTHER_STRONG, actor="a")
    sealed = await identity.password_states.fingerprint(user.id)
    assert sealed is not None
    reopened = identity.password_fingerprints.open(user.id, sealed)
    assert reopened is not None and reopened.digest == password_digest(OTHER_STRONG)
