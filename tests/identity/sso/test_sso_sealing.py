"""Sealing an invitation token into a single sign-on login transaction.

The token is sealed with AES-256-GCM under a key derived (HKDF-SHA256) from
the browser's login binding, which the database holds only as a hash, with
the transaction's state hash as associated data. So the database alone
cannot open it, and a sealed value moved to another transaction does not
open. No database is needed here.
"""

from __future__ import annotations

import hashlib
import secrets

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from warden.identity.sso import sealing
from warden.identity.sso.sealing import SEALED_LENGTH, open_invitation, seal_invitation


def _token() -> str:
    return secrets.token_urlsafe(32)


def _sha(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii")).digest()


@pytest.fixture
def token() -> str:
    return _token()


@pytest.fixture
def binding() -> str:
    return _token()


@pytest.fixture
def state_hash() -> bytes:
    return _sha(_token())


def test_a_sealed_token_opens_with_its_binding_and_state(
    token: str, binding: str, state_hash: bytes
) -> None:
    sealed = seal_invitation(token, binding=binding, state_hash=state_hash)
    assert open_invitation(sealed, binding=binding, state_hash=state_hash) == token


def test_the_sealed_value_has_a_fixed_length_and_shows_nothing_of_the_token(
    token: str, binding: str, state_hash: bytes
) -> None:
    first = seal_invitation(token, binding=binding, state_hash=state_hash)
    second = seal_invitation(token, binding=binding, state_hash=state_hash)
    assert len(first) == len(second) == SEALED_LENGTH == 12 + 43 + 16
    # A fresh nonce each time, so two seals of one token differ.
    assert first != second
    for sealed in (first, second):
        assert token.encode("ascii") not in sealed
        assert _sha(token) not in sealed
        assert binding.encode("ascii") not in sealed


def test_another_binding_does_not_open(token: str, binding: str, state_hash: bytes) -> None:
    sealed = seal_invitation(token, binding=binding, state_hash=state_hash)
    assert open_invitation(sealed, binding=_token(), state_hash=state_hash) is None


def test_another_transaction_does_not_open(token: str, binding: str, state_hash: bytes) -> None:
    # The same browser binding, but another transaction's state: the
    # associated data differs, so the value is bound to its own row.
    sealed = seal_invitation(token, binding=binding, state_hash=state_hash)
    assert open_invitation(sealed, binding=binding, state_hash=_sha(_token())) is None


def test_a_tampered_value_does_not_open(token: str, binding: str, state_hash: bytes) -> None:
    sealed = seal_invitation(token, binding=binding, state_hash=state_hash)
    for index in range(len(sealed)):
        tampered = bytearray(sealed)
        tampered[index] ^= 0x01
        assert open_invitation(bytes(tampered), binding=binding, state_hash=state_hash) is None
    for cut in (b"", sealed[:12], sealed[:-1], sealed + b"\x00"):
        assert open_invitation(cut, binding=binding, state_hash=state_hash) is None


def test_a_database_reader_cannot_open_it(token: str, binding: str, state_hash: bytes) -> None:
    """Everything the login transaction's row holds, used as key material, fails.

    The row holds the state and binding hashes, the nonce, the verifier, the
    issuer and the sealed value; the binding itself lives only in the
    browser's cookie.
    """
    sealed = seal_invitation(token, binding=binding, state_hash=state_hash)
    row: list[bytes] = [
        state_hash,
        _sha(binding),
        _sha(binding).hex().encode("ascii"),
        _token().encode("ascii"),  # the OIDC nonce
        secrets.token_urlsafe(48).encode("ascii"),  # the PKCE verifier
        b"https://idp.example.org",
        sealed,
        b"",
    ]
    nonce, body = sealed[:12], sealed[12:]
    for material in row:
        key = sealing._derive_key(material)
        for associated in (state_hash, b"", None):
            with pytest.raises(InvalidTag):
                AESGCM(key).decrypt(nonce, body, associated)


def test_the_key_is_derived_from_the_binding(token: str, binding: str, state_hash: bytes) -> None:
    # The construction the rulings name, rebuilt from its parts: AES-256-GCM
    # under HKDF-SHA256 of the binding, with the state hash as associated data.
    sealed = seal_invitation(token, binding=binding, state_hash=state_hash)
    key = sealing._derive_key(binding.encode("ascii"))
    assert len(key) == 32
    assert AESGCM(key).decrypt(sealed[:12], sealed[12:], state_hash) == token.encode("ascii")


@pytest.mark.parametrize("value", [None, "", "nope", "A" * 44, "A" * 42 + "\n", b"x" * 43])
def test_only_a_well_formed_token_is_sealed(value: object, binding: str, state_hash: bytes) -> None:
    with pytest.raises(ValueError):
        seal_invitation(value, binding=binding, state_hash=state_hash)  # type: ignore[arg-type]


def test_a_value_that_opens_to_something_other_than_a_token_is_refused(
    binding: str, state_hash: bytes
) -> None:
    # Sealed correctly, but not a token: defence in depth if the sealer changes.
    key = sealing._derive_key(binding.encode("ascii"))
    nonce = secrets.token_bytes(12)
    odd = nonce + AESGCM(key).encrypt(nonce, b"!" * 43, state_hash)
    assert len(odd) == SEALED_LENGTH
    assert open_invitation(odd, binding=binding, state_hash=state_hash) is None
