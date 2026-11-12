"""Encryption of TOTP secrets at rest. No database."""

from __future__ import annotations

import base64

import pytest
from identity_support import MemorySecrets

from warden.identity.crypto import (
    TOTP_KEY_SECRET,
    TOTP_PREVIOUS_KEY_SECRET,
    SecretBox,
    SecretKeyError,
    new_totp_key,
)


def _key(seed: int) -> bytes:
    return bytes([seed]) * 32


def test_seal_and_open_round_trip() -> None:
    box = SecretBox(_key(1))
    key_id, sealed = box.seal(b"twenty byte secret!!", context=b"user-1")
    assert key_id == box.current_key_id
    assert b"twenty byte secret!!" not in sealed
    assert len(sealed) == 12 + 20 + 16
    assert box.open(key_id, sealed, context=b"user-1") == b"twenty byte secret!!"


def test_each_seal_uses_a_fresh_nonce() -> None:
    box = SecretBox(_key(1))
    assert box.seal(b"same", context=b"u")[1] != box.seal(b"same", context=b"u")[1]


def test_a_sealed_secret_is_bound_to_its_context() -> None:
    """Copying one user's ciphertext onto another user's row must not work."""
    box = SecretBox(_key(1))
    key_id, sealed = box.seal(b"secret", context=b"user-1")
    assert box.open(key_id, sealed, context=b"user-2") is None


def test_tampering_and_wrong_keys_are_refused() -> None:
    box = SecretBox(_key(1))
    key_id, sealed = box.seal(b"secret", context=b"u")
    flipped = bytes([sealed[0] ^ 1]) + sealed[1:]
    assert box.open(key_id, flipped, context=b"u") is None
    assert box.open(key_id, sealed[:-1], context=b"u") is None
    assert box.open("unknown-key", sealed, context=b"u") is None
    assert SecretBox(_key(2)).open(key_id, sealed, context=b"u") is None


def test_the_previous_key_still_opens_during_rotation() -> None:
    old = SecretBox(_key(1))
    key_id, sealed = old.seal(b"secret", context=b"u")
    rotated = SecretBox(_key(2), previous=_key(1))
    assert rotated.current_key_id != key_id
    assert rotated.open(key_id, sealed, context=b"u") == b"secret"
    assert rotated.seal(b"x", context=b"u")[0] == rotated.current_key_id


def test_keys_come_from_the_secrets_store() -> None:
    secrets = MemorySecrets()
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    box = SecretBox.from_secrets(secrets)
    assert box.previous_key_id is None
    secrets.set(TOTP_PREVIOUS_KEY_SECRET, new_totp_key())
    assert SecretBox.from_secrets(secrets).previous_key_id is not None


def test_new_keys_are_256_bits_and_distinct() -> None:
    first, second = new_totp_key(), new_totp_key()
    assert first != second
    assert len(base64.urlsafe_b64decode(first + "=" * (-len(first) % 4))) == 32


@pytest.mark.parametrize(
    "value",
    [None, "", "not base64 !!", base64.urlsafe_b64encode(b"short").decode(), new_totp_key() + "\n"],
)
def test_a_missing_or_malformed_key_fails_at_start_up(value: str | None) -> None:
    secrets = MemorySecrets()
    if value is not None:
        secrets.set(TOTP_KEY_SECRET, value)
    with pytest.raises(SecretKeyError) as raised:
        SecretBox.from_secrets(secrets)
    assert TOTP_KEY_SECRET in str(raised.value)
    if value:
        assert value.strip() not in str(raised.value)  # never echo key material


def test_a_malformed_previous_key_fails_too() -> None:
    secrets = MemorySecrets()
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    secrets.set(TOTP_PREVIOUS_KEY_SECRET, "garbage")
    with pytest.raises(SecretKeyError, match="previous"):
        SecretBox.from_secrets(secrets)
