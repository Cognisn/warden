"""Key store: Ed25519 by key id, rotation, retirement, private halves in secrets only."""

from __future__ import annotations

import asyncio
import base64
from typing import Any

import pytest

from warden.config import KeysConfig
from warden.db import Database
from warden.keys import KeyStore, KeyStoreError

pytestmark = pytest.mark.db

MESSAGE = b"checkpoint 42"


class FakeSecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


@pytest.fixture
def secrets() -> FakeSecrets:
    return FakeSecrets()


@pytest.fixture
def store(pool: Any, secrets: FakeSecrets) -> KeyStore:
    return KeyStore(Database(pool), secrets)


async def test_rotate_stores_private_half_in_secrets_and_public_half_in_db(
    store: KeyStore, secrets: FakeSecrets, pool: Any
) -> None:
    key = await store.rotate()
    assert list(secrets.values) == [KeysConfig().secret_prefix + key.key_id]
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT key_id, public_key FROM warden.signing_keys")
        rows = await cur.fetchall()
    assert rows == [(key.key_id, key.public_key)]
    assert len(key.public_key) == 32
    stored_private = secrets.values[KeysConfig().secret_prefix + key.key_id]
    assert stored_private.encode() not in key.public_key


async def test_sign_and_verify_round_trip(store: KeyStore) -> None:
    key = await store.rotate()
    signature = await store.sign(MESSAGE)
    assert signature.key_id == key.key_id
    assert await store.verify(MESSAGE, signature.signature, signature.key_id)


async def test_tampered_signature_fails(store: KeyStore) -> None:
    await store.rotate()
    signature = await store.sign(MESSAGE)
    tampered = bytes([signature.signature[0] ^ 0x01]) + signature.signature[1:]
    assert not await store.verify(MESSAGE, tampered, signature.key_id)


async def test_tampered_message_fails(store: KeyStore) -> None:
    await store.rotate()
    signature = await store.sign(MESSAGE)
    assert not await store.verify(MESSAGE + b"!", signature.signature, signature.key_id)


@pytest.mark.parametrize("bad", [b"", b"\0" * 63, b"\0" * 65])
async def test_malformed_signature_fails_cleanly(store: KeyStore, bad: bytes) -> None:
    key = await store.rotate()
    assert not await store.verify(MESSAGE, bad, key.key_id)


async def test_unknown_key_id_fails(store: KeyStore) -> None:
    await store.rotate()
    signature = await store.sign(MESSAGE)
    assert not await store.verify(MESSAGE, signature.signature, "no-such-key")


async def test_signature_under_another_key_id_fails(store: KeyStore) -> None:
    first = await store.rotate()
    signature = await store.sign(MESSAGE)
    await store.rotate()
    assert await store.verify(MESSAGE, signature.signature, first.key_id)
    second = (await store.active_key()).key_id
    assert not await store.verify(MESSAGE, signature.signature, second)


async def test_rotated_out_key_still_verifies_and_new_key_signs(store: KeyStore) -> None:
    old = await store.rotate()
    old_signature = await store.sign(MESSAGE)
    new = await store.rotate()
    assert new.key_id != old.key_id
    assert (await store.active_key()).key_id == new.key_id
    assert (await store.sign(MESSAGE)).key_id == new.key_id
    assert await store.verify(MESSAGE, old_signature.signature, old.key_id)


async def test_retired_key_no_longer_verifies_or_lists(store: KeyStore) -> None:
    old = await store.rotate()
    old_signature = await store.sign(MESSAGE)
    new = await store.rotate()
    await store.retire(old.key_id)
    assert not await store.verify(MESSAGE, old_signature.signature, old.key_id)
    assert [k.key_id for k in await store.public_keys()] == [new.key_id]
    listed = await store.public_keys(include_retired=True)
    assert {k.key_id for k in listed} == {old.key_id, new.key_id}


async def test_retiring_the_active_key_hands_signing_to_the_next(store: KeyStore) -> None:
    old = await store.rotate()
    new = await store.rotate()
    await store.retire(new.key_id)
    assert (await store.sign(MESSAGE)).key_id == old.key_id


async def test_the_last_unretired_key_cannot_be_retired(store: KeyStore) -> None:
    key = await store.rotate()
    with pytest.raises(KeyStoreError):
        await store.retire(key.key_id)
    assert (await store.active_key()).key_id == key.key_id


async def test_concurrent_retirements_never_leave_no_signing_key(
    pool: Any, secrets: FakeSecrets
) -> None:
    store = KeyStore(Database(pool), secrets)
    await store.rotate()
    barrier = asyncio.Barrier(2)

    async def retire(key_id: str) -> bool:
        await barrier.wait()
        try:
            await store.retire(key_id)
        except KeyStoreError:
            return False
        return True

    for _ in range(5):
        await store.rotate()
        first, second = await store.public_keys()
        outcomes = await asyncio.gather(retire(first.key_id), retire(second.key_id))
        assert sorted(outcomes) == [False, True]
        assert len(await store.public_keys()) == 1


async def test_retiring_an_unknown_or_retired_key_fails(store: KeyStore) -> None:
    old = await store.rotate()
    await store.rotate()
    await store.retire(old.key_id)
    with pytest.raises(KeyStoreError):
        await store.retire(old.key_id)
    with pytest.raises(KeyStoreError):
        await store.retire("no-such-key")


async def test_signing_without_any_key_fails(store: KeyStore) -> None:
    with pytest.raises(KeyStoreError):
        await store.sign(MESSAGE)


async def test_private_key_missing_from_secrets_fails_without_detail(
    store: KeyStore, secrets: FakeSecrets
) -> None:
    await store.rotate()
    secrets.values.clear()
    with pytest.raises(KeyStoreError) as caught:
        await KeyStore(store.db, secrets).sign(MESSAGE)
    assert "secret" in str(caught.value).lower()


async def test_private_key_that_does_not_match_its_public_half_is_refused(
    store: KeyStore, secrets: FakeSecrets
) -> None:
    await store.rotate()
    (name,) = secrets.values
    wrong = base64.urlsafe_b64encode(b"\x07" * 32).rstrip(b"=").decode()
    secrets.values[name] = wrong
    with pytest.raises(KeyStoreError) as caught:
        await KeyStore(store.db, secrets).sign(MESSAGE)
    assert wrong not in str(caught.value)


async def test_key_id_is_a_thumbprint_of_the_public_key(store: KeyStore) -> None:
    import hashlib

    key = await store.rotate()
    expected = base64.urlsafe_b64encode(hashlib.sha256(key.public_key).digest()[:16])
    assert key.key_id == expected.rstrip(b"=").decode()


async def test_public_key_publishes_as_an_okp_jwk(store: KeyStore) -> None:
    key = await store.rotate()
    jwk = key.jwk()
    assert jwk == {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "kid": key.key_id,
        "x": base64.urlsafe_b64encode(key.public_key).rstrip(b"=").decode(),
    }


async def test_custom_secret_prefix_is_used(pool: Any, secrets: FakeSecrets) -> None:
    store = KeyStore(Database(pool), secrets, KeysConfig(secret_prefix="product/warden/"))
    key = await store.rotate()
    assert list(secrets.values) == ["product/warden/" + key.key_id]


async def test_retired_key_verifies_historical_signatures_only(store: KeyStore) -> None:
    old = await store.rotate()
    checkpoint = await store.sign(MESSAGE)
    await store.rotate()
    await store.retire(old.key_id)
    assert not await store.verify(MESSAGE, checkpoint.signature, old.key_id)
    assert await store.verify_historical(MESSAGE, checkpoint.signature, old.key_id)


async def test_verify_historical_still_checks_the_signature(store: KeyStore) -> None:
    old = await store.rotate()
    checkpoint = await store.sign(MESSAGE)
    await store.rotate()
    await store.retire(old.key_id)
    tampered = bytes([checkpoint.signature[0] ^ 0x01]) + checkpoint.signature[1:]
    assert not await store.verify_historical(MESSAGE, tampered, old.key_id)
    assert not await store.verify_historical(MESSAGE + b"!", checkpoint.signature, old.key_id)
    assert not await store.verify_historical(MESSAGE, b"\0" * 63, old.key_id)
    assert not await store.verify_historical(MESSAGE, checkpoint.signature, "no-such-key")


async def test_revoked_key_fails_live_and_historical_verification(store: KeyStore) -> None:
    old = await store.rotate()
    signature = await store.sign(MESSAGE)
    await store.rotate()
    await store.revoke(old.key_id)
    assert not await store.verify(MESSAGE, signature.signature, old.key_id)
    assert not await store.verify_historical(MESSAGE, signature.signature, old.key_id)


async def test_a_retired_key_can_still_be_revoked(store: KeyStore) -> None:
    old = await store.rotate()
    signature = await store.sign(MESSAGE)
    await store.rotate()
    await store.retire(old.key_id)
    await store.revoke(old.key_id)
    assert not await store.verify_historical(MESSAGE, signature.signature, old.key_id)


async def test_revoked_keys_are_never_published(store: KeyStore) -> None:
    revoked = await store.rotate()
    retired = await store.rotate()
    live = await store.rotate()
    await store.retire(retired.key_id)
    await store.revoke(revoked.key_id)
    assert [k.key_id for k in await store.public_keys()] == [live.key_id]
    listed = {k.key_id for k in await store.public_keys(include_retired=True)}
    assert listed == {live.key_id, retired.key_id}


async def test_revoking_the_active_key_hands_signing_to_the_next(store: KeyStore) -> None:
    old = await store.rotate()
    new = await store.rotate()
    await store.revoke(new.key_id)
    assert (await store.sign(MESSAGE)).key_id == old.key_id


async def test_revoke_also_retires_the_key(store: KeyStore, pool: Any) -> None:
    old = await store.rotate()
    await store.rotate()
    await store.revoke(old.key_id)
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT retired_at IS NOT NULL, revoked_at IS NOT NULL"
            " FROM warden.signing_keys WHERE key_id = %s",
            (old.key_id,),
        )
        assert await cur.fetchone() == (True, True)


async def test_the_last_usable_key_cannot_be_revoked(store: KeyStore) -> None:
    key = await store.rotate()
    with pytest.raises(KeyStoreError):
        await store.revoke(key.key_id)
    assert (await store.active_key()).key_id == key.key_id


async def test_revoking_an_unknown_or_revoked_key_fails(store: KeyStore) -> None:
    old = await store.rotate()
    await store.rotate()
    await store.revoke(old.key_id)
    with pytest.raises(KeyStoreError):
        await store.revoke(old.key_id)
    with pytest.raises(KeyStoreError):
        await store.revoke("no-such-key")


async def test_a_revoked_key_cannot_be_retired(store: KeyStore) -> None:
    old = await store.rotate()
    await store.rotate()
    await store.revoke(old.key_id)
    with pytest.raises(KeyStoreError):
        await store.retire(old.key_id)


async def test_concurrent_revocations_never_leave_no_signing_key(
    pool: Any, secrets: FakeSecrets
) -> None:
    store = KeyStore(Database(pool), secrets)
    await store.rotate()
    barrier = asyncio.Barrier(2)

    async def revoke(key_id: str) -> bool:
        await barrier.wait()
        try:
            await store.revoke(key_id)
        except KeyStoreError:
            return False
        return True

    for _ in range(5):
        await store.rotate()
        first, second = await store.public_keys()
        outcomes = await asyncio.gather(revoke(first.key_id), revoke(second.key_id))
        assert sorted(outcomes) == [False, True]
        assert len(await store.public_keys()) == 1


async def test_a_revocation_racing_a_retirement_never_leaves_no_signing_key(
    pool: Any, secrets: FakeSecrets
) -> None:
    store = KeyStore(Database(pool), secrets)
    await store.rotate()
    barrier = asyncio.Barrier(2)

    async def attempt(operation: Any, key_id: str) -> bool:
        await barrier.wait()
        try:
            await operation(key_id)
        except KeyStoreError:
            return False
        return True

    for _ in range(5):
        await store.rotate()
        first, second = await store.public_keys()
        outcomes = await asyncio.gather(
            attempt(store.revoke, first.key_id), attempt(store.retire, second.key_id)
        )
        assert sorted(outcomes) == [False, True]
        assert len(await store.public_keys()) == 1
