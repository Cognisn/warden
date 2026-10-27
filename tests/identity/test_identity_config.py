"""Identity reads its tunable values from ``IdentityConfig``.

Each value was hard-coded in 0.1.0a3; the defaults keep that behaviour, and
a configured value takes effect.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qs, urlsplit

import pytest
from identity_support import (
    FAST_HASHER,
    PASSWORD,
    MemorySecrets,
    UserFactory,
    current_code,
    enrol_totp,
    make_config,
)

from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, PermissionRegistry, SecretKeyError
from warden.identity.crypto import new_totp_key
from warden.keys import KeyStore

pytestmark = pytest.mark.db

IP = ipaddress.ip_address("192.0.2.50")


def _identity(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    **identity: object,
) -> Identity:
    return Identity(
        make_config(**identity), db, keys, permissions, secrets=secrets, hasher=FAST_HASHER
    )


async def test_the_sign_in_limit_comes_from_configuration(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    make_user: UserFactory,
) -> None:
    identity = _identity(db, keys, permissions, secrets, sign_in_attempt_limit=2)
    await make_user("limit@example.com")
    for _ in range(2):
        with pytest.raises(AuthenticationRefused):
            await identity.sign_in("limit@example.com", "wrong", source_ip=IP)
    with pytest.raises(AuthenticationRefused) as refused:
        await identity.sign_in("limit@example.com", PASSWORD, source_ip=IP)
    assert refused.value.reason == "throttled"


async def test_the_challenge_lifetime_comes_from_configuration(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    make_user: UserFactory,
) -> None:
    identity = _identity(db, keys, permissions, secrets, mfa_challenge_ttl_seconds=45)
    user = await make_user("ttl@example.com")
    await enrol_totp(identity, user)
    result = await identity.sign_in("ttl@example.com", PASSWORD, source_ip=IP)
    assert result.challenge is not None
    assert result.challenge.expires_in == 45
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT extract(epoch FROM expires_at - now()) FROM warden.mfa_challenges"
        )
        row = await cur.fetchone()
    assert row is not None and 30 < float(row[0]) <= 45


async def test_the_challenge_failure_limit_comes_from_configuration(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    make_user: UserFactory,
) -> None:
    identity = _identity(db, keys, permissions, secrets, mfa_max_failures=1)
    user = await make_user("fail@example.com")
    secret = await enrol_totp(identity, user)
    result = await identity.sign_in("fail@example.com", PASSWORD, source_ip=IP)
    assert result.challenge is not None
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(result.challenge.token, "000000", source_ip=IP)
    with pytest.raises(AuthenticationRefused):
        await identity.verify_totp(result.challenge.token, current_code(secret, 1), source_ip=IP)


async def test_the_recovery_code_count_comes_from_configuration(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    make_user: UserFactory,
) -> None:
    identity = _identity(db, keys, permissions, secrets, recovery_code_count=6)
    user = await make_user("codes@example.com")
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(
        user.id, current_code(enrolment.secret), actor="test"
    )
    assert codes is not None and len(codes) == 6


async def test_the_totp_issuer_comes_from_configuration(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    make_user: UserFactory,
) -> None:
    default = _identity(db, keys, permissions, secrets)
    named = _identity(db, keys, permissions, secrets, totp_issuer="Example Corp")
    user = await make_user("issuer@example.com")

    def issuer(uri: str) -> str:
        return parse_qs(urlsplit(uri).query)["issuer"][0]

    first = await default.mfa.begin_enrolment(user.id, account=user.email)
    assert issuer(first.uri) == "app.example.com"
    second = await named.mfa.begin_enrolment(user.id, account=user.email)
    assert issuer(second.uri) == "Example Corp"


def test_the_totp_key_secret_names_come_from_configuration(
    db: Database, keys: KeyStore, permissions: PermissionRegistry
) -> None:
    store = MemorySecrets()
    store.set("vor.totp", new_totp_key())
    _identity(db, keys, permissions, store, totp_key_secret="vor.totp")
    with pytest.raises(SecretKeyError) as refused:
        _identity(db, keys, permissions, store)
    assert "warden.totp-key" in str(refused.value)
