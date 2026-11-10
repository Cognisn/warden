"""Sealed password fingerprints (ruling PW8): SHA-1 sealed per user, rotating keys."""

from __future__ import annotations

import hashlib
import uuid

import pytest

from warden.identity.crypto import SecretBox, new_totp_key
from warden.identity.password_policy.fingerprint import (
    SEALED_LENGTH,
    Fingerprints,
    SealedFingerprint,
    password_digest,
)

PASSWORD = "Tr0ub4dor&3 synthetic"


def _key() -> bytes:
    import base64

    return base64.urlsafe_b64decode(new_totp_key() + "=")


def test_the_digest_is_the_sha1_of_the_password_as_typed() -> None:
    expected = hashlib.sha1(PASSWORD.encode()).digest()  # noqa: S324 - the HIBP format
    assert password_digest(PASSWORD) == expected
    assert len(password_digest(PASSWORD)) == 20


def test_seal_and_open_round_trip_bound_to_the_user() -> None:
    box = Fingerprints(SecretBox(_key()))
    user, other = uuid.uuid4(), uuid.uuid4()
    sealed = box.seal(user, PASSWORD)
    assert len(sealed.sealed) == SEALED_LENGTH == 48
    assert password_digest(PASSWORD) not in sealed.sealed
    opened = box.open(user, sealed)
    assert opened is not None
    assert opened.digest == password_digest(PASSWORD)
    assert opened.resealed is None
    # Copied onto another user's row, it does not open.
    assert box.open(other, sealed) is None


def test_sealing_twice_gives_different_ciphertexts() -> None:
    box = Fingerprints(SecretBox(_key()))
    user = uuid.uuid4()
    assert box.seal(user, PASSWORD).sealed != box.seal(user, PASSWORD).sealed


def test_tampering_or_an_unknown_key_does_not_open() -> None:
    box = Fingerprints(SecretBox(_key()))
    user = uuid.uuid4()
    sealed = box.seal(user, PASSWORD)
    flipped = bytes([sealed.sealed[0] ^ 1]) + sealed.sealed[1:]
    assert box.open(user, SealedFingerprint(sealed.key_id, flipped)) is None
    assert box.open(user, SealedFingerprint("unknown", sealed.sealed)) is None


def test_rotation_opens_with_the_previous_key_and_reseals_with_the_current() -> None:
    old, new = _key(), _key()
    user = uuid.uuid4()
    sealed = Fingerprints(SecretBox(old)).seal(user, PASSWORD)
    rotating = Fingerprints(SecretBox(new, old))
    opened = rotating.open(user, sealed)
    assert opened is not None and opened.digest == password_digest(PASSWORD)
    assert opened.resealed is not None
    assert opened.resealed.key_id == rotating.current_key_id != sealed.key_id
    # After the previous key is removed, only the re-sealed value opens.
    after = Fingerprints(SecretBox(new))
    assert after.open(user, sealed) is None
    reopened = after.open(user, opened.resealed)
    assert reopened is not None and reopened.digest == password_digest(PASSWORD)


def test_without_a_key_nothing_is_sealed() -> None:
    box = Fingerprints(None)
    assert not box.available
    with pytest.raises(RuntimeError):
        box.seal(uuid.uuid4(), PASSWORD)
    assert box.open(uuid.uuid4(), SealedFingerprint("k", b"\0" * 48)) is None


def test_a_sealed_fingerprint_does_not_show_its_bytes() -> None:
    sealed = Fingerprints(SecretBox(_key())).seal(uuid.uuid4(), PASSWORD)
    assert sealed.sealed.hex() not in repr(sealed)
