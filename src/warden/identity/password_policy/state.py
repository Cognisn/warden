"""Each user's password state (rulings PW5, PW8, PW9 and PW11).

What is stored: the tier the password met (its name only), when it was set,
when it expires, whether a change is required and why (``expired``,
``watch_list``, ``administrator`` or ``policy``), the watch list that
matched (its id and source only) and the sealed fingerprint. Never the
password's length or makeup, and never an unsealed digest.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from psycopg import AsyncConnection, sql

from warden.db import PASSWORD_STATES, Database, table
from warden.identity.password_policy.fingerprint import SealedFingerprint
from warden.identity.password_policy.watchlists import WatchListMatch, WatchListSource

__all__ = ["ChangeReason", "PasswordState", "PasswordStates"]

_STATES = table(PASSWORD_STATES)


class ChangeReason(StrEnum):
    """Why a user must change their password before a session is issued (PW9)."""

    EXPIRED = "expired"
    WATCH_LIST = "watch_list"
    ADMINISTRATOR = "administrator"
    POLICY = "policy"


@dataclass(frozen=True, slots=True)
class PasswordState:
    user_id: uuid.UUID
    tier: str | None
    password_set_at: datetime | None
    expires_at: datetime | None
    change_reason: ChangeReason | None
    watch_list_source: WatchListSource | None
    watch_list_id: uuid.UUID | None
    has_fingerprint: bool


class PasswordStates:
    """Reads and writes ``warden.password_states``; one row per user, created on first write."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def get(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> PasswordState | None:
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT tier, password_set_at, expires_at, change_reason, watch_list_source,"
                    " watch_list_id, fingerprint_sealed IS NOT NULL FROM {} WHERE user_id = %s"
                ).format(_STATES),
                (user_id,),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        tier, set_at, expires_at, reason, source, list_id, fingerprinted = row
        return PasswordState(
            user_id=user_id,
            tier=tier,
            password_set_at=set_at,
            expires_at=expires_at,
            change_reason=None if reason is None else ChangeReason(reason),
            watch_list_source=None if source is None else WatchListSource(source),
            watch_list_id=list_id,
            has_fingerprint=bool(fingerprinted),
        )

    async def record_set(
        self,
        user_id: uuid.UUID,
        *,
        tier: str | None,
        set_at: datetime,
        expires_at: datetime | None,
        fingerprint: SealedFingerprint | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> None:
        """A new password was set: its tier and expiry, its fingerprint, and no change required."""
        async with self._db.transaction(conn) as tx:
            await tx.execute(
                sql.SQL(
                    "INSERT INTO {} AS s (user_id, tier, password_set_at, expires_at,"
                    " fingerprint_sealed, fingerprint_key_id, updated_at)"
                    " VALUES (%(user)s, %(tier)s, %(set_at)s, %(expires)s, %(sealed)s, %(key)s,"
                    " now())"
                    " ON CONFLICT (user_id) DO UPDATE SET tier = EXCLUDED.tier,"
                    " password_set_at = EXCLUDED.password_set_at,"
                    " expires_at = EXCLUDED.expires_at,"
                    " fingerprint_sealed = EXCLUDED.fingerprint_sealed,"
                    " fingerprint_key_id = EXCLUDED.fingerprint_key_id,"
                    " change_reason = NULL, watch_list_source = NULL, watch_list_id = NULL,"
                    " updated_at = now()"
                ).format(_STATES),
                {
                    "user": user_id,
                    "tier": tier,
                    "set_at": set_at,
                    "expires": expires_at,
                    "sealed": None if fingerprint is None else fingerprint.sealed,
                    "key": None if fingerprint is None else fingerprint.key_id,
                },
            )

    async def set_tier(
        self,
        user_id: uuid.UUID,
        *,
        tier: str | None,
        expires_at: datetime | None,
        set_at: datetime | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> None:
        """Re-evaluation at sign-in (PW11): a new tier and expiry for the same password.

        ``set_at`` records when the password was set only where that is not
        yet known (a password set before enforcement began); a known time is
        never moved. A required change is left as it is.
        """
        async with self._db.transaction(conn) as tx:
            await tx.execute(
                sql.SQL(
                    "INSERT INTO {} AS s (user_id, tier, expires_at, password_set_at)"
                    " VALUES (%s, %s, %s, %s)"
                    " ON CONFLICT (user_id) DO UPDATE SET tier = EXCLUDED.tier,"
                    " expires_at = EXCLUDED.expires_at,"
                    " password_set_at = coalesce(s.password_set_at, EXCLUDED.password_set_at),"
                    " updated_at = now()"
                ).format(_STATES),
                (user_id, tier, expires_at, set_at),
            )

    async def require_change(
        self,
        user_id: uuid.UUID,
        reason: ChangeReason,
        *,
        match: WatchListMatch | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> bool:
        """Flag a required change; False if one was already required (the first reason stands)."""
        if (match is not None) != (reason is ChangeReason.WATCH_LIST):
            raise ValueError("a watch list match goes with the watch_list reason, and only it")
        source = None if match is None else match.source.value
        list_id = None if match is None else match.list_id
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "INSERT INTO {} AS s (user_id, change_reason, watch_list_source,"
                    " watch_list_id) VALUES (%s, %s, %s, %s)"
                    " ON CONFLICT (user_id) DO UPDATE SET change_reason = EXCLUDED.change_reason,"
                    " watch_list_source = EXCLUDED.watch_list_source,"
                    " watch_list_id = EXCLUDED.watch_list_id, updated_at = now()"
                    " WHERE s.change_reason IS NULL RETURNING 1"
                ).format(_STATES),
                (user_id, reason.value, source, list_id),
            )
            return await cur.fetchone() is not None

    async def clear_change(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> None:
        async with self._db.transaction(conn) as tx:
            await tx.execute(
                sql.SQL(
                    "UPDATE {} SET change_reason = NULL, watch_list_source = NULL,"
                    " watch_list_id = NULL, updated_at = now() WHERE user_id = %s"
                ).format(_STATES),
                (user_id,),
            )

    async def store_fingerprint(
        self,
        user_id: uuid.UUID,
        fingerprint: SealedFingerprint | None,
        *,
        conn: AsyncConnection[Any] | None = None,
    ) -> None:
        """Write, replace or (with None) remove the user's sealed fingerprint."""
        async with self._db.transaction(conn) as tx:
            await tx.execute(
                sql.SQL(
                    "INSERT INTO {} (user_id, fingerprint_sealed, fingerprint_key_id)"
                    " VALUES (%s, %s, %s) ON CONFLICT (user_id) DO UPDATE SET"
                    " fingerprint_sealed = EXCLUDED.fingerprint_sealed,"
                    " fingerprint_key_id = EXCLUDED.fingerprint_key_id, updated_at = now()"
                ).format(_STATES),
                (
                    user_id,
                    None if fingerprint is None else fingerprint.sealed,
                    None if fingerprint is None else fingerprint.key_id,
                ),
            )

    async def fingerprint(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> SealedFingerprint | None:
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT fingerprint_key_id, fingerprint_sealed FROM {}"
                    " WHERE user_id = %s AND fingerprint_sealed IS NOT NULL"
                ).format(_STATES),
                (user_id,),
            )
            row = await cur.fetchone()
        return None if row is None else SealedFingerprint(row[0], bytes(row[1]))
