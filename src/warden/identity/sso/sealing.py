"""Sealing an invitation token into a single sign-on login transaction.

An invitation accepted through single sign-on must wait, between
``POST /sso/start`` and the callback, somewhere the callback can read it.
It waits in the login transaction's row, sealed:

- AES-256-GCM, under a key derived with HKDF-SHA256 from the browser's login
  binding (the value in its HttpOnly cookie). The database holds only the
  binding's SHA-256 hash, so someone who can read the database cannot open
  the token.
- The transaction's state hash is the associated data, so a sealed value
  moved to another transaction does not open there.
- A fresh 96-bit nonce for every seal. The stored value is
  ``nonce || ciphertext || tag``, always ``SEALED_LENGTH`` bytes, since a
  token is always 43 characters.

A value that does not open, for whatever reason, opens to None. No server
key is involved, so there is nothing to configure or rotate: the key exists
only while the browser holds its cookie, for the transaction's lifetime.
"""

from __future__ import annotations

import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["SEALED_LENGTH", "open_invitation", "seal_invitation"]

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_TOKEN_LENGTH = 43
_NONCE = 12
_TAG = 16
_INFO = b"warden.sso.invitation.v1"

SEALED_LENGTH = _NONCE + _TOKEN_LENGTH + _TAG
"""The length of every sealed invitation, in bytes."""


def _derive_key(material: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(material)


def seal_invitation(token: str, *, binding: str, state_hash: bytes) -> bytes:
    """Seal ``token`` to the browser's ``binding`` and the transaction's ``state_hash``."""
    if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
        raise ValueError("not an invitation token")
    nonce = secrets.token_bytes(_NONCE)
    aead = AESGCM(_derive_key(binding.encode("ascii")))
    return nonce + aead.encrypt(nonce, token.encode("ascii"), state_hash)


def open_invitation(sealed: bytes, *, binding: str, state_hash: bytes) -> str | None:
    """The token sealed in ``sealed``, or None if it does not open to one."""
    if len(sealed) != SEALED_LENGTH:
        return None
    aead = AESGCM(_derive_key(binding.encode("ascii")))
    try:
        plaintext = aead.decrypt(sealed[:_NONCE], sealed[_NONCE:], state_hash)
    except InvalidTag:
        return None
    try:
        token = plaintext.decode("ascii")
    except UnicodeDecodeError:
        return None
    return token if _TOKEN.fullmatch(token) else None
