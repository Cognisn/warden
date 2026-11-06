"""Ceremony challenges: 32 random bytes, stored as a hash, used up once.

A challenge is bound to its ceremony (registration or sign-in), to its user
(none for a discoverable sign-in) and to whether the ceremony requires user
verification and a discoverable credential. ``consume`` uses it up with one
guarded ``UPDATE`` in a transaction of its own, so of any number of
concurrent responses carrying it exactly one gets through, and a refused
response cannot be retried with the same challenge even when the caller's
transaction rolls back.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from psycopg import AsyncConnection, sql

from warden.db import Database, table
from warden.db.schema import WEBAUTHN_CHALLENGES
from warden.identity.webauthn.errors import WebAuthnError, WebAuthnRefusal

_CHALLENGES = table(WEBAUTHN_CHALLENGES)
CHALLENGE_BYTES = 32


class Ceremony(StrEnum):
    REGISTRATION = "registration"
    AUTHENTICATION = "authentication"


@dataclass(frozen=True, slots=True)
class IssuedChallenge:
    challenge: bytes
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ConsumedChallenge:
    id: uuid.UUID
    user_id: uuid.UUID | None
    user_verification_required: bool
    resident_key_required: bool


def _hash(challenge: bytes) -> bytes:
    return hashlib.sha256(challenge).digest()


class Challenges:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def issue(
        self,
        conn: AsyncConnection[Any],
        ceremony: Ceremony,
        user_id: uuid.UUID | None,
        *,
        user_verification_required: bool,
        resident_key_required: bool,
        ttl_seconds: int,
    ) -> IssuedChallenge:
        challenge = secrets.token_bytes(CHALLENGE_BYTES)
        cur = await conn.execute(
            sql.SQL(
                "INSERT INTO {} (challenge_hash, purpose, user_id, user_verification_required,"
                " resident_key_required, expires_at)"
                " VALUES (%s, %s, %s, %s, %s, now() + %s * interval '1 second')"
                " RETURNING expires_at"
            ).format(_CHALLENGES),
            (
                _hash(challenge),
                ceremony.value,
                user_id,
                user_verification_required,
                resident_key_required,
                ttl_seconds,
            ),
        )
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError("the challenge was not recorded")
        return IssuedChallenge(challenge, row[0])

    async def consume(
        self, challenge: bytes, ceremony: Ceremony, user_id: uuid.UUID | None
    ) -> ConsumedChallenge:
        """Use the challenge up, or raise the reason it cannot be. One guarded write."""
        digest = _hash(challenge)
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET consumed_at = now()"
                    " WHERE challenge_hash = %s AND purpose = %s"
                    " AND user_id IS NOT DISTINCT FROM %s::uuid"
                    " AND consumed_at IS NULL AND expires_at > now()"
                    " RETURNING id, user_id, user_verification_required, resident_key_required"
                ).format(_CHALLENGES),
                (digest, ceremony.value, user_id),
            )
            row = await cur.fetchone()
            if row is not None:
                return ConsumedChallenge(row[0], row[1], row[2], row[3])
            # Only to name the reason: nothing below changes any state.
            cur = await tx.execute(
                sql.SQL(
                    "SELECT purpose, user_id, consumed_at IS NOT NULL, expires_at <= now()"
                    " FROM {} WHERE challenge_hash = %s"
                ).format(_CHALLENGES),
                (digest,),
            )
            found = await cur.fetchone()
        raise WebAuthnError(_reason(found, ceremony, user_id), user_id=user_id)

    async def prune(self) -> int:
        """Delete expired challenges, used or not; returns how many."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE expires_at <= now()").format(_CHALLENGES)
            )
            return cur.rowcount


def _reason(
    found: tuple[Any, ...] | None, ceremony: Ceremony, user_id: uuid.UUID | None
) -> WebAuthnRefusal:
    if found is None:
        return WebAuthnRefusal.CHALLENGE_UNKNOWN
    purpose, owner, consumed, expired = found
    if purpose != ceremony.value:
        return WebAuthnRefusal.CHALLENGE_PURPOSE
    if owner != user_id:
        return WebAuthnRefusal.CHALLENGE_USER
    if consumed:
        return WebAuthnRefusal.CHALLENGE_USED
    if expired:
        return WebAuthnRefusal.CHALLENGE_EXPIRED
    # Used or expired between the guarded write and this read.
    return WebAuthnRefusal.CHALLENGE_USED
