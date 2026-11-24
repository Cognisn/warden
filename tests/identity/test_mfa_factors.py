"""Second factors under ruling CS14, and self-service recovery codes (CS22).

MFA is always required on a password sign-in: ``identity.require_mfa``
false is refused at start-up and at run time. The second factors an
administrator allows (``warden.sign_in_settings.allowed_second_factors``)
govern enrolment and the challenge. Recovery codes are always the backup,
and a signed-in user may replace theirs after a fresh second factor.

The tests here use TOTP; ``webauthn/test_mfa_factors_webauthn.py`` covers
security keys and passkeys.
"""

from __future__ import annotations

import dataclasses
import uuid

import httpx
import pytest
from identity_support import (
    PASSWORD,
    MemorySecrets,
    RecordingSender,
    UserFactory,
    age_sessions,
    audit_rows,
    current_code,
    direct_session,
    enrol_totp,
    fresh_totp_code,
    make_config,
    race,
    sign_in_tokens,
)
from psycopg.types.json import Jsonb

from warden.config import ConfigError, parse_config
from warden.db import POLICY_SETTING, Database
from warden.identity import (
    AuthenticationRefused,
    FreshSecondFactorRequired,
    Identity,
    PermissionRegistry,
    PolicyError,
    Principal,
    SecondFactorKind,
    SecondFactorNotAllowed,
    SessionPolicy,
    SignInMethod,
    SignInSettingsError,
    User,
)
from warden.identity.mail import MailKind
from warden.keys import KeyStore

DB = pytest.mark.db
ALWAYS = "MFA is always required for password sign-in in warden 0.2.0 and later"


def _tree(**identity: object) -> dict[str, object]:
    http = {
        "public_base_url": "https://app.example.com",
        "accept_invitation_link": "/accept?t={token}",
        "reset_password_link": "/reset?t={token}",
    }
    return {"http": http, "identity": identity}


async def _allow(identity: Identity, *factors: str) -> None:
    await identity.update_sign_in_settings(actor="admin-1", allowed_second_factors=list(factors))


async def _principal(identity: Identity, user: User, amr: tuple[str, ...]) -> Principal:
    pair = await direct_session(identity, user.id, amr)
    return await identity.authenticate(pair.access_token)


async def _unused_codes(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.recovery_codes WHERE user_id = %s AND used_at IS NULL",
            (user_id,),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def _sessions(db: Database, user_id: uuid.UUID) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.sessions WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


# MFA always on (CS14)


def test_require_mfa_false_is_refused_at_start_up() -> None:
    with pytest.raises(ConfigError) as caught:
        parse_config(_tree(require_mfa=False))
    message = str(caught.value)
    assert "warden.identity.require_mfa" in message
    assert ALWAYS in message


def test_require_mfa_true_is_still_accepted_and_is_the_default() -> None:
    assert parse_config(_tree(require_mfa=True)).identity.require_mfa is True
    assert parse_config(_tree()).identity.require_mfa is True


def test_the_session_policy_refuses_require_mfa_false() -> None:
    policy = SessionPolicy.from_config(parse_config(_tree()).identity)
    assert policy.require_mfa is True
    off = SessionPolicy(
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=28_800,
        session_lifespan_seconds=43_200,
        refresh_reuse_grace_seconds=10,
        require_mfa=False,
    )
    with pytest.raises(PolicyError, match=ALWAYS):
        off.validate()


@DB
async def test_mfa_cannot_be_switched_off_at_run_time(identity: Identity, db: Database) -> None:
    with pytest.raises(PolicyError, match=ALWAYS):
        await identity.policy.update(actor="admin-1", require_mfa=False)
    assert (await identity.policy.current()).require_mfa is True
    assert await audit_rows(db, "warden.identity.policy.changed") == []
    # True is accepted, and changes nothing.
    assert (await identity.policy.update(actor="admin-1", require_mfa=True)).require_mfa


@DB
async def test_a_stored_require_mfa_false_from_0_1_is_ignored(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """An override stored by 0.1.x no longer switches MFA off; the others still apply."""
    async with db.transaction() as tx:
        await tx.execute(
            "INSERT INTO warden.settings (key, value, updated_at) VALUES (%s, %s, now())",
            (POLICY_SETTING, Jsonb({"require_mfa": False, "refresh_reuse_grace_seconds": 0})),
        )
    identity.policy.invalidate()
    policy = await identity.policy.current()
    assert policy.require_mfa is True
    assert policy.refresh_reuse_grace_seconds == 0
    user = await make_user()
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "enrol"


@DB
@pytest.mark.parametrize(
    "method", [None, SignInMethod.PASSWORD, SignInMethod.PASSWORD_AND_SSO], ids=str
)
async def test_a_password_sign_in_always_needs_a_second_factor(
    identity: Identity, db: Database, make_user: UserFactory, method: SignInMethod | None
) -> None:
    user = await make_user(sign_in_method=method)
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is None and result.password_change is None
    assert result.challenge is not None and result.challenge.purpose == "enrol"
    assert await _sessions(db, user.id) == 0
    signed_in = await audit_rows(db, "warden.identity.sign_in")
    assert [r for r in signed_in if r["outcome"] == "success"] == []


# Allowed second factors: enrolment and the challenge


@DB
async def test_forced_enrolment_names_the_allowed_factors(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None
    assert result.challenge.methods == ("totp", "webauthn")
    await _allow(identity, "passkey")
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "enrol"
    assert result.challenge.methods == ("webauthn",)


@DB
async def test_a_disallowed_totp_is_not_enrolled_under_a_challenge(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    await _allow(identity, "passkey")
    user = await make_user()
    challenge = (await identity.sign_in(user.email, PASSWORD)).challenge
    assert challenge is not None and challenge.purpose == "enrol"
    with pytest.raises(AuthenticationRefused):
        await identity.begin_enrolment(challenge=challenge.token, source_ip="192.0.2.9")
    rows = await audit_rows(db, "warden.identity.mfa.verify")
    assert rows[-1]["details"] == {"reason": "factor_not_allowed", "method": "enrolment"}
    assert await audit_rows(db, "warden.identity.mfa.enrolment_started") == []


@DB
async def test_a_disallowed_totp_is_not_enrolled_by_a_signed_in_user(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await _allow(identity, "passkey")
    user = await make_user()
    principal = await _principal(identity, user, ("hwk", "mfa"))
    with pytest.raises(SecondFactorNotAllowed):
        await identity.begin_enrolment(principal=principal)
    pair = await direct_session(identity, user.id, ("hwk", "mfa"))
    response = await client.post(
        "/auth/totp/enrolment", headers={"authorization": f"Bearer {pair.access_token}"}
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "TOTP is not allowed as a second factor"}


@DB
async def test_totp_disallowed_between_begin_and_confirm_is_not_confirmed(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user()
    challenge = (await identity.sign_in(user.email, PASSWORD)).challenge
    assert challenge is not None
    enrolment = await identity.begin_enrolment(challenge=challenge.token)
    await _allow(identity, "passkey")
    with pytest.raises(AuthenticationRefused):
        await identity.confirm_enrolment(current_code(enrolment.secret), challenge=challenge.token)
    assert not await identity.mfa.has_confirmed_totp(user.id)


@DB
async def test_a_disallowed_totp_is_not_accepted_at_sign_in(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """A user whose only factor is a removed TOTP enrols an allowed one instead."""
    user = await make_user()
    await enrol_totp(identity, user)
    verify = (await identity.sign_in(user.email, PASSWORD)).challenge
    assert verify is not None and verify.purpose == "verify"
    await _allow(identity, "passkey")
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(verify.token, await fresh_totp_code(identity, user.id))
    rows = await audit_rows(db, "warden.identity.mfa.verify")
    assert rows[-1]["details"] == {"reason": "factor_not_allowed", "method": "totp"}
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None and result.challenge.purpose == "enrol"
    assert result.challenge.methods == ("webauthn",)


@DB
async def test_removing_a_factor_deletes_no_enrolment(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    await _allow(identity, "passkey")
    assert await identity.mfa.has_confirmed_totp(user.id)
    assert await _unused_codes(db, user.id) == 10
    await _allow(identity, "totp", "passkey")
    tokens = await sign_in_tokens(identity, user.email)
    assert (await identity.authenticate(tokens.access_token)).amr == ("pwd", "otp")


@DB
@pytest.mark.parametrize("factors", [[], (), set(), frozenset()], ids=repr)
async def test_the_allowed_set_may_not_be_emptied(
    identity: Identity, db: Database, factors: object
) -> None:
    before = await identity.sign_in_methods.read_now()
    with pytest.raises(SignInSettingsError):
        await identity.update_sign_in_settings(actor="admin-1", allowed_second_factors=factors)
    after = await identity.sign_in_methods.read_now()
    assert after.allowed_second_factors == before.allowed_second_factors
    assert after.allowed_second_factors == {SecondFactorKind.TOTP, SecondFactorKind.PASSKEY}


# Recovery codes: self-service regeneration (CS22)


@DB
async def test_regeneration_replaces_every_code_and_is_audited(
    identity: Identity, db: Database, make_user: UserFactory, mail: RecordingSender
) -> None:
    user = await make_user(display_name="Rosa")
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    old = await identity.mfa.confirm_enrolment(user.id, current_code(enrolment.secret))
    assert old is not None and len(old) == 10
    # Spend one code, so both used and unused codes are present.
    challenge = (await identity.sign_in(user.email, PASSWORD)).challenge
    assert challenge is not None
    await identity.use_recovery_code(challenge.token, old[0])
    assert await _unused_codes(db, user.id) == 9
    principal = await _principal(identity, user, ("pwd", "otp"))
    codes = await identity.regenerate_recovery_codes(principal, source_ip="192.0.2.44")
    assert len(codes) == 10 and len(set(codes)) == 10
    assert await _unused_codes(db, user.id) == 10
    # The new codes work; the old unused ones do not.
    challenge = (await identity.sign_in(user.email, PASSWORD)).challenge
    assert challenge is not None
    with pytest.raises(AuthenticationRefused):
        await identity.use_recovery_code(challenge.token, old[1])
    challenge = (await identity.sign_in(user.email, PASSWORD)).challenge
    assert challenge is not None
    assert await identity.use_recovery_code(challenge.token, codes[0]) is not None
    rows = await audit_rows(db, "warden.identity.mfa.recovery_codes_regenerated")
    assert rows == [
        {
            "action": "warden.identity.mfa.recovery_codes_regenerated",
            "outcome": "success",
            "actor": str(user.id),
            "resource_type": "user",
            "resource_id": str(user.id),
            "details": {"codes_removed": 10, "codes_issued": 10},
        }
    ]
    notices = [m for m in mail.sent if m.kind is MailKind.RECOVERY_CODES_REGENERATED]
    assert len(notices) == 1 and notices[0].to == user.email
    for code in codes:
        assert code not in notices[0].text


@DB
@pytest.mark.parametrize(
    ("amr", "age", "reason"),
    [
        (("pwd", "otp"), 301, "stale_second_factor"),
        (("pwd", "hwk"), 3600, "stale_second_factor"),
        (("pwd", "recovery_code"), 0, "no_second_factor"),
        (("pwd",), 0, "no_second_factor"),
        (("sso",), 0, "no_second_factor"),
    ],
    ids=["otp-stale", "hwk-stale", "recovery-code", "password-only", "sso"],
)
async def test_regeneration_needs_a_fresh_second_factor(
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    mail: RecordingSender,
    amr: tuple[str, ...],
    age: int,
    reason: str,
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    principal = await _principal(identity, user, amr)
    await age_sessions(identity, user.id, age)
    with pytest.raises(FreshSecondFactorRequired):
        await identity.regenerate_recovery_codes(principal, source_ip="192.0.2.44")
    assert await _unused_codes(db, user.id) == 10
    rows = await audit_rows(db, "warden.identity.mfa.recovery_codes_regenerated")
    assert [(r["outcome"], r["details"]) for r in rows] == [("failure", {"reason": reason})]
    assert [m for m in mail.sent if m.kind is MailKind.RECOVERY_CODES_REGENERATED] == []


@DB
@pytest.mark.parametrize("amr", [("pwd", "otp"), ("pwd", "hwk"), ("hwk", "mfa")], ids=str)
async def test_a_second_factor_within_the_window_is_fresh(
    identity: Identity, make_user: UserFactory, amr: tuple[str, ...]
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    principal = await _principal(identity, user, amr)
    await age_sessions(identity, user.id, 290)
    assert len(await identity.regenerate_recovery_codes(principal)) == 10


@DB
async def test_an_api_key_cannot_regenerate_codes(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user(roles=("viewer",))
    await enrol_totp(identity, user)
    issued = await identity.api_keys.create(user.id, "ci", ["cases.read"], actor="t")
    principal = await identity.api_keys.authenticate(issued.key)
    assert principal is not None and principal.api_key_id is not None
    with pytest.raises(FreshSecondFactorRequired):
        await identity.regenerate_recovery_codes(principal)
    # Even one claiming a fresh second factor: a key is not a session.
    fresh = await _principal(identity, user, ("pwd", "otp"))
    keyed = dataclasses.replace(fresh, api_key_id=principal.api_key_id)
    with pytest.raises(FreshSecondFactorRequired):
        await identity.regenerate_recovery_codes(keyed)


@DB
async def test_regeneration_without_a_mail_sender(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    from identity_support import FAST_HASHER

    identity = Identity(make_config(), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    user = await identity.users.create("nomail@example.com", actor="t", password=PASSWORD)
    await enrol_totp(identity, user)
    principal = await _principal(identity, user, ("pwd", "otp"))
    assert len(await identity.regenerate_recovery_codes(principal)) == 10


@DB
async def test_concurrent_regenerations_leave_one_set_of_codes(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    principal = await _principal(identity, user, ("pwd", "otp"))
    outcomes = await race(
        *(lambda: identity.regenerate_recovery_codes(principal) for _ in range(4))
    )
    assert all(isinstance(o, list) and len(o) == 10 for o in outcomes), outcomes
    assert await _unused_codes(db, user.id) == 10
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM warden.recovery_codes WHERE user_id = %s", (user.id,)
        )
        assert (await cur.fetchone()) == (10,)


# The self-service route


@DB
async def test_the_route_regenerates_for_the_signed_in_user(
    identity: Identity, client: httpx.AsyncClient, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    pair = await direct_session(identity, user.id, ("pwd", "otp"))
    response = await client.post(
        "/auth/recovery-codes/regenerate", headers={"authorization": f"Bearer {pair.access_token}"}
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert list(body) == ["recovery_codes"] and len(body["recovery_codes"]) == 10
    rows = await audit_rows(db, "warden.identity.mfa.recovery_codes_regenerated")
    assert rows[-1]["outcome"] == "success"


@DB
async def test_the_route_asks_for_a_fresh_second_factor(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    await enrol_totp(identity, user)
    pair = await direct_session(identity, user.id, ("pwd", "otp"))
    await age_sessions(identity, user.id, 3600)
    response = await client.post(
        "/auth/recovery-codes/regenerate", headers={"authorization": f"Bearer {pair.access_token}"}
    )
    assert response.status_code == 403
    assert response.json() == {
        "detail": "sign in again with a second factor to replace your recovery codes"
    }


@DB
async def test_the_route_refuses_without_a_session(client: httpx.AsyncClient) -> None:
    response = await client.post("/auth/recovery-codes/regenerate")
    assert response.status_code == 401
    assert response.content == b'{"detail":"authentication failed"}'
    response = await client.post(
        "/auth/recovery-codes/regenerate", headers={"authorization": "Bearer nonsense"}
    )
    assert response.status_code == 401
