"""Sealed password fingerprints (ruling PW8).

A fingerprint is the SHA-1 of the password as typed (the Pwned Passwords
format), sealed with AES-256-GCM under the fingerprint key from konfig's
secrets store, with the user's id bound in, so a value copied onto another
user's row does not open. It lets ``recheck`` compare passwords in use with
watch lists that changed after the user last signed in.

The trade-off is stated plainly: anyone holding both the database and the
key can recover a fast hash of each fingerprinted password. A policy enables
the fingerprint only by choice; the seeded default does not.

Rotation works as for TOTP secrets: put the new key in the current secret
and the old one in the previous secret. Both open; only the current seals;
``open`` returns a re-sealed value for anything sealed with the previous key.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from warden.identity.crypto import SecretBox

__all__ = [
    "SEALED_LENGTH",
    "Fingerprints",
    "OpenedFingerprint",
    "SealedFingerprint",
    "password_digest",
]

# Nonce (12) + SHA-1 (20) + GCM tag (16).
SEALED_LENGTH = 48
_CONTEXT = b"warden password fingerprint\0"


def password_digest(password: str) -> bytes:
    """The SHA-1 of ``password`` as UTF-8: the form watch lists and the range API use."""
    return hashlib.sha1(password.encode("utf-8", "surrogatepass")).digest()  # noqa: S324


@dataclass(frozen=True, slots=True)
class SealedFingerprint:
    """A fingerprint as stored: the sealing key's id and the sealed bytes."""

    key_id: str
    sealed: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class OpenedFingerprint:
    """An opened fingerprint, held in memory only for the length of a check."""

    digest: bytes = field(repr=False)
    resealed: SealedFingerprint | None = None
    """Set when the value was sealed with the previous key: store it in place."""


class Fingerprints:
    """Seals and opens fingerprints; ``available`` is False without a configured key."""

    def __init__(self, box: SecretBox | None) -> None:
        self._box = box

    @property
    def available(self) -> bool:
        return self._box is not None

    @property
    def current_key_id(self) -> str | None:
        return None if self._box is None else self._box.current_key_id

    def seal(self, user_id: uuid.UUID, password: str) -> SealedFingerprint:
        return self.seal_digest(user_id, password_digest(password))

    def seal_digest(self, user_id: uuid.UUID, digest: bytes) -> SealedFingerprint:
        if self._box is None:
            raise RuntimeError("no fingerprint key is configured")
        key_id, sealed = self._box.seal(digest, context=_CONTEXT + user_id.bytes)
        return SealedFingerprint(key_id, sealed)

    def open(self, user_id: uuid.UUID, fingerprint: SealedFingerprint) -> OpenedFingerprint | None:
        """The digest, or None for an unknown key, another user's value or tampering."""
        if self._box is None:
            return None
        digest = self._box.open(
            fingerprint.key_id, bytes(fingerprint.sealed), context=_CONTEXT + user_id.bytes
        )
        if digest is None or len(digest) != 20:
            return None
        resealed = None
        if fingerprint.key_id != self._box.current_key_id:
            resealed = self.seal_digest(user_id, digest)
        return OpenedFingerprint(digest, resealed)
