"""Ed25519 signing keys, identified by key id, with rotation (design D14).

Private halves live only in konfig's secrets store, under
``<keys.secret_prefix><key_id>``. Public halves live in
``warden.signing_keys`` so any component can verify without being able to
sign. One key family signs both session tokens and audit checkpoints.

Rotation adds a key, which becomes the signing key at once; earlier keys
keep verifying until they are retired, so rotating signs nobody out. The
last unretired key cannot be retired.

This module is shared: after the Foundation arc only the integration session
edits it.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from psycopg import AsyncConnection, sql

from warden.config import KeysConfig
from warden.db import SIGNING_KEYS, Database, table

__all__ = ["KeyStore", "KeyStoreError", "PublicKey", "SecretStore", "Signature", "key_id_for"]

_SIGNING_KEYS = table(SIGNING_KEYS)


class KeyStoreError(Exception):
    """A key operation could not be completed. Messages never carry key material."""


class SecretStore(Protocol):
    """What the key store needs from konfig's ``Secrets``."""

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...


@dataclass(frozen=True, slots=True)
class PublicKey:
    """The public half of a signing key, as published."""

    key_id: str
    public_key: bytes
    created_at: datetime
    retired_at: datetime | None

    def jwk(self) -> dict[str, str]:
        """The key as an RFC 8037 OKP JSON Web Key."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": self.key_id,
            "x": _b64url(self.public_key),
        }


@dataclass(frozen=True, slots=True)
class Signature:
    key_id: str
    signature: bytes


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id_for(public_key: bytes) -> str:
    """The key id: a truncated SHA-256 thumbprint of the raw public key."""
    return _b64url(hashlib.sha256(public_key).digest()[:16])


def _raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _row_to_key(row: tuple[Any, ...]) -> PublicKey:
    return PublicKey(key_id=row[0], public_key=bytes(row[1]), created_at=row[2], retired_at=row[3])


_COLUMNS = sql.SQL("key_id, public_key, created_at, retired_at")


class KeyStore:
    """Sign and verify with warden's Ed25519 keys."""

    def __init__(
        self, db: Database, secrets: SecretStore, config: KeysConfig | None = None
    ) -> None:
        self._db = db
        self._secrets = secrets
        self._prefix = (config or KeysConfig()).secret_prefix
        self._private: dict[str, Ed25519PrivateKey] = {}

    @property
    def db(self) -> Database:
        return self._db

    def _secret_name(self, key_id: str) -> str:
        return self._prefix + key_id

    async def rotate(self) -> PublicKey:
        """Generate a key and make it the signing key. Earlier keys keep verifying."""
        private = Ed25519PrivateKey.generate()
        public = _raw_public(private)
        key_id = key_id_for(public)
        seed = private.private_bytes_raw()
        # Secret first: a public row without its private half would break signing,
        # whereas an orphaned secret is harmless.
        await asyncio.to_thread(self._secrets.set, self._secret_name(key_id), _b64url(seed))
        async with self._db.transaction() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "INSERT INTO {} (key_id, public_key, created_at)"
                    " VALUES (%s, %s, clock_timestamp()) RETURNING {}"
                ).format(_SIGNING_KEYS, _COLUMNS),
                (key_id, public),
            )
            row = await cur.fetchone()
        if row is None:
            raise KeyStoreError("the new key was not recorded")
        self._private[key_id] = private
        return _row_to_key(row)

    async def active_key(self) -> PublicKey:
        """The key that signs now: the newest unretired key."""
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT {} FROM {} WHERE retired_at IS NULL"
                    " ORDER BY created_at DESC, key_id DESC LIMIT 1"
                ).format(_COLUMNS, _SIGNING_KEYS)
            )
            row = await cur.fetchone()
        if row is None:
            raise KeyStoreError("no signing key exists; run `warden keys rotate`")
        return _row_to_key(row)

    async def public_keys(self, *, include_retired: bool = False) -> list[PublicKey]:
        """Published keys, newest first."""
        where = sql.SQL("") if include_retired else sql.SQL(" WHERE retired_at IS NULL")
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL("SELECT {} FROM {}{} ORDER BY created_at DESC, key_id DESC").format(
                    _COLUMNS, _SIGNING_KEYS, where
                )
            )
            rows = await cur.fetchall()
        return [_row_to_key(row) for row in rows]

    async def _private_key(self, key: PublicKey) -> Ed25519PrivateKey:
        cached = self._private.get(key.key_id)
        if cached is not None:
            return cached
        encoded = await asyncio.to_thread(self._secrets.get, self._secret_name(key.key_id))
        if encoded is None:
            raise KeyStoreError(f"private key {key.key_id} is missing from the secrets store")
        try:
            private = Ed25519PrivateKey.from_private_bytes(_b64url_decode(encoded))
        except (ValueError, binascii.Error):
            raise KeyStoreError(
                f"private key {key.key_id} in the secrets store is malformed"
            ) from None
        if _raw_public(private) != key.public_key:
            raise KeyStoreError(
                f"private key {key.key_id} in the secrets store does not match its public key"
            )
        self._private[key.key_id] = private
        return private

    async def sign(self, message: bytes) -> Signature:
        """Sign with the active key."""
        key = await self.active_key()
        private = await self._private_key(key)
        return Signature(key_id=key.key_id, signature=private.sign(message))

    async def verify(self, message: bytes, signature: bytes, key_id: str) -> bool:
        """True only if ``signature`` is valid for ``message`` under an unretired ``key_id``."""
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT public_key FROM {} WHERE key_id = %s AND retired_at IS NULL"
                ).format(_SIGNING_KEYS),
                (key_id,),
            )
            row = await cur.fetchone()
        if row is None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(bytes(row[0])).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True

    async def retire(self, key_id: str, *, conn: AsyncConnection[Any] | None = None) -> None:
        """Stop a key verifying. Refuses the last unretired key.

        The unretired rows are locked before the count is taken, so two
        concurrent retirements cannot both pass the check and leave no key.
        """
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT key_id FROM {} WHERE retired_at IS NULL FOR UPDATE").format(
                    _SIGNING_KEYS
                )
            )
            live = {row[0] for row in await cur.fetchall()}
            if key_id not in live:
                raise KeyStoreError(f"key {key_id} is unknown or already retired")
            if len(live) == 1:
                raise KeyStoreError("refusing to retire the last unretired signing key")
            await tx.execute(
                sql.SQL("UPDATE {} SET retired_at = clock_timestamp() WHERE key_id = %s").format(
                    _SIGNING_KEYS
                ),
                (key_id,),
            )
        self._private.pop(key_id, None)
