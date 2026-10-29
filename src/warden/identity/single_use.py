"""Single-use tokens: invitation and password reset links.

A token is 32 random bytes, base64url-encoded, handed out once (in a link)
and stored only as its SHA-256 hash. It expires, and it is used up by one
guarded ``UPDATE``: ``consume`` sets ``consumed_at`` only where the token is
still live, so of any number of concurrent submits exactly one succeeds.

``lock_live`` reads a live token under a row lock, for decisions that must
be made before the consume (an invitation's sign-in method, say) without a
concurrent request using the token meanwhile. Callers that also lock the
token's user lock the user first, so a revocation that deletes the user
(and so its tokens) takes its locks in the same order.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, TypeGuard

from psycopg import AsyncConnection, sql

from warden.db import Database, table
from warden.db.schema import SINGLE_USE_TOKENS

__all__ = ["SINGLE_USE_TOKENS", "IssuedToken", "LiveToken", "Purpose", "SingleUseTokens"]


# secrets.token_urlsafe(32): 43 base64url characters.
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")

_TOKENS = table(SINGLE_USE_TOKENS)
_LIVE = sql.SQL("consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()")


class Purpose(StrEnum):
    INVITATION = "invitation"
    PASSWORD_RESET = "password_reset"  # noqa: S105 - a purpose name, not a password


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """A new token. ``token`` is shown once and never stored."""

    token: str
    id: uuid.UUID
    user_id: uuid.UUID
    purpose: Purpose
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class LiveToken:
    id: uuid.UUID
    user_id: uuid.UUID
    purpose: Purpose
    expires_at: datetime


def well_formed(token: object) -> TypeGuard[str]:
    return isinstance(token, str) and _TOKEN.fullmatch(token) is not None


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def _live_token(row: tuple[Any, ...]) -> LiveToken:
    return LiveToken(id=row[0], user_id=row[1], purpose=Purpose(row[2]), expires_at=row[3])


class SingleUseTokens:
    """Tokens in ``warden.single_use_tokens``. Every method works in the caller's transaction."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def issue(
        self,
        conn: AsyncConnection[Any],
        user_id: uuid.UUID,
        purpose: Purpose,
        *,
        ttl_seconds: int,
        created_by: str | None,
    ) -> IssuedToken:
        """A new token for ``user_id``, live for ``ttl_seconds``."""
        token = secrets.token_urlsafe(32)
        cur = await conn.execute(
            sql.SQL(
                "INSERT INTO {} (token_hash, purpose, user_id, created_by, expires_at)"
                " VALUES (%s, %s, %s, %s, now() + %s * interval '1 second')"
                " RETURNING id, expires_at"
            ).format(_TOKENS),
            (token_hash(token), purpose.value, user_id, created_by, ttl_seconds),
        )
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError("the token was not recorded")
        return IssuedToken(token, row[0], user_id, purpose, row[1])

    async def owner(
        self, conn: AsyncConnection[Any], token: object, purpose: Purpose
    ) -> uuid.UUID | None:
        """The user a token was issued to, live or not, without locking anything."""
        if not well_formed(token):
            return None
        cur = await conn.execute(
            sql.SQL("SELECT user_id FROM {} WHERE token_hash = %s AND purpose = %s").format(
                _TOKENS
            ),
            (token_hash(token), purpose.value),
        )
        row = await cur.fetchone()
        return None if row is None else row[0]

    async def lock_live(
        self, conn: AsyncConnection[Any], token: object, purpose: Purpose
    ) -> LiveToken | None:
        """The live token, locked until the caller's transaction ends; None if not live.

        A concurrent ``lock_live`` or ``consume`` of the same token waits, and
        then sees the token as the holder left it.
        """
        if not well_formed(token):
            return None
        cur = await conn.execute(
            sql.SQL(
                "SELECT id, user_id, purpose, expires_at FROM {}"
                " WHERE token_hash = %s AND purpose = %s AND {} FOR UPDATE"
            ).format(_TOKENS, _LIVE),
            (token_hash(token), purpose.value),
        )
        row = await cur.fetchone()
        return None if row is None else _live_token(row)

    async def consume(
        self, conn: AsyncConnection[Any], token: object, purpose: Purpose
    ) -> LiveToken | None:
        """Use the token up; None unless it was live. One guarded write."""
        if not well_formed(token):
            return None
        cur = await conn.execute(
            sql.SQL(
                "UPDATE {} SET consumed_at = now() WHERE token_hash = %s AND purpose = %s AND {}"
                " RETURNING id, user_id, purpose, expires_at"
            ).format(_TOKENS, _LIVE),
            (token_hash(token), purpose.value),
        )
        row = await cur.fetchone()
        return None if row is None else _live_token(row)

    async def revoke_live(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, purpose: Purpose
    ) -> int:
        """Revoke the user's live tokens for ``purpose``; returns how many."""
        cur = await conn.execute(
            sql.SQL(
                "UPDATE {} SET revoked_at = now() WHERE user_id = %s AND purpose = %s AND {}"
            ).format(_TOKENS, _LIVE),
            (user_id, purpose.value),
        )
        return cur.rowcount

    async def live_expiry(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, purpose: Purpose
    ) -> datetime | None:
        """When the user's latest live token for ``purpose`` expires, or None."""
        cur = await conn.execute(
            sql.SQL(
                "SELECT max(expires_at) FROM {} WHERE user_id = %s AND purpose = %s AND {}"
            ).format(_TOKENS, _LIVE),
            (user_id, purpose.value),
        )
        row = await cur.fetchone()
        return None if row is None else row[0]

    async def prune(self) -> int:
        """Delete expired tokens, whatever their state; returns how many."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE expires_at <= now()").format(_TOKENS)
            )
            return cur.rowcount
