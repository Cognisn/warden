"""Encryption at rest for TOTP secrets.

A TOTP secret lets anyone who holds it mint codes, so it is stored sealed
with AES-256-GCM under a key from konfig's secrets store. The user's id is
bound in as associated data, so a ciphertext copied onto another user's row
does not open. Each sealed value records the id of the key that sealed it.

Rotation: put the new key in ``warden.totp-key`` and the old one in
``warden.totp-key.previous``; both open, only the new one seals. Then call
``Mfa.reseal_all()`` and remove the previous key.

The secret names are fixed for now; configuring them is an integration
change to ``config.py``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets as _secrets
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "TOTP_KEY_SECRET",
    "TOTP_PREVIOUS_KEY_SECRET",
    "SecretBox",
    "SecretKeyError",
    "SecretStore",
    "new_totp_key",
]

TOTP_KEY_SECRET = "warden.totp-key"  # noqa: S105 - a secret name, not a secret
TOTP_PREVIOUS_KEY_SECRET = "warden.totp-key.previous"  # noqa: S105

_NONCE = 12
_B64URL = re.compile(r"[A-Za-z0-9_-]{43}=?")


class SecretKeyError(Exception):
    """A TOTP key is missing or malformed. Names the secret, never its value."""


class SecretStore(Protocol):
    def get(self, key: str) -> str | None: ...


def new_totp_key() -> str:
    """A fresh 256-bit key, encoded for the secrets store."""
    return base64.urlsafe_b64encode(_secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _decode(name: str, value: str) -> bytes:
    if _B64URL.fullmatch(value) is None:
        raise SecretKeyError(f"secret {name} is not a base64url-encoded 256-bit key")
    try:
        key = base64.urlsafe_b64decode(value.rstrip("=") + "=")
    except (ValueError, binascii.Error):
        raise SecretKeyError(f"secret {name} is not a base64url-encoded 256-bit key") from None
    if len(key) != 32:
        raise SecretKeyError(f"secret {name} is not a base64url-encoded 256-bit key")
    return key


def _key_id(key: bytes) -> str:
    digest = hashlib.sha256(b"warden totp key\0" + key).digest()[:9]
    return base64.urlsafe_b64encode(digest).decode("ascii")


class SecretBox:
    """Seals and opens small secrets with the current (and, while rotating, previous) key."""

    def __init__(self, current: bytes, previous: bytes | None = None) -> None:
        self._current = (_key_id(current), AESGCM(current))
        self._keys = {self._current[0]: self._current[1]}
        self._previous_id: str | None = None
        if previous is not None:
            self._previous_id = _key_id(previous)
            self._keys[self._previous_id] = AESGCM(previous)

    @classmethod
    def from_secrets(cls, store: SecretStore) -> SecretBox:
        """Read the keys from konfig's secrets store; fails if the current key is unusable."""
        current = store.get(TOTP_KEY_SECRET)
        if not current:
            raise SecretKeyError(
                f"secret {TOTP_KEY_SECRET} is not set; store a key from"
                " warden.identity.crypto.new_totp_key()"
            )
        previous = store.get(TOTP_PREVIOUS_KEY_SECRET)
        return cls(
            _decode(TOTP_KEY_SECRET, current),
            _decode(TOTP_PREVIOUS_KEY_SECRET, previous) if previous else None,
        )

    @property
    def current_key_id(self) -> str:
        return self._current[0]

    @property
    def previous_key_id(self) -> str | None:
        return self._previous_id

    def seal(self, plaintext: bytes, *, context: bytes) -> tuple[str, bytes]:
        """``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``."""
        nonce = _secrets.token_bytes(_NONCE)
        return self._current[0], nonce + self._current[1].encrypt(nonce, plaintext, context)

    def open(self, key_id: str, sealed: bytes, *, context: bytes) -> bytes | None:
        """The plaintext, or None for an unknown key, wrong context or tampering."""
        aead = self._keys.get(key_id)
        if aead is None or len(sealed) <= _NONCE:
            return None
        try:
            return aead.decrypt(sealed[:_NONCE], sealed[_NONCE:], context)
        except InvalidTag:
            return None
