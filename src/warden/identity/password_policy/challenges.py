"""Forced-change challenges (ruling PW9).

After a correct password and the second factor, a user who must change
their password receives a short-lived opaque token instead of a session.
The token is held only as its SHA-256 hash; it tolerates a few failed
attempts, and is used up by one guarded, atomic write, so two requests
racing with the same token cannot both succeed. Someone holding only the
password cannot reach this step.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from psycopg import AsyncConnection, sql

from warden.db import PASSWORD_CHANGE_CHALLENGES, Database, table
from warden.identity.password_policy.state import ChangeReason
from warden.identity.password_policy.watchlists import WatchListMatch, WatchListSource

__all__ = ["ChangeChallenge", "PasswordChangeChallenges"]

_CHALLENGES = table(PASSWORD_CHANGE_CHALLENGES)
_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}")


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


@dataclass(frozen=True, slots=True)
class ChangeChallenge:
    id: uuid.UUID
    user_id: uuid.UUID
    reason: ChangeReason
    watch_list_source: WatchListSource | None
    watch_list_id: uuid.UUID | None


class PasswordChangeChallenges:
    """Issues, opens and uses up forced-change challenges."""

    def __init__(self, db: Database, *, ttl_seconds: int, max_failures: int) -> None:
        self._db = db
        self.ttl_seconds = ttl_seconds
        self._live = sql.SQL(
            "consumed_at IS NULL AND expires_at > now() AND failed_attempts < {}"
        ).format(sql.Literal(max_failures))

    async def create(
        self,
        conn: AsyncConnection[Any],
        user_id: uuid.UUID,
        reason: ChangeReason,
        *,
        match: WatchListMatch | None = None,
    ) -> str:
        """A fresh token for ``user_id``, in the caller's transaction."""
        token = secrets.token_urlsafe(32)
        await conn.execute(
            sql.SQL(
                "INSERT INTO {} (token_hash, user_id, reason, watch_list_source, watch_list_id,"
                " expires_at) VALUES (%s, %s, %s, %s, %s, now() + %s * interval '1 second')"
            ).format(_CHALLENGES),
            (
                _hash(token),
                user_id,
                reason.value,
                None if match is None else match.source.value,
                None if match is None else match.list_id,
                self.ttl_seconds,
            ),
        )
        return token

    async def open(self, conn: AsyncConnection[Any], token: object) -> ChangeChallenge | None:
        """The live challenge ``token`` names, or None. Does not use it up."""
        if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
            return None
        cur = await conn.execute(
            sql.SQL(
                "SELECT id, user_id, reason, watch_list_source, watch_list_id FROM {}"
                " WHERE token_hash = %s AND {}"
            ).format(_CHALLENGES, self._live),
            (_hash(token),),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        return ChangeChallenge(
            id=row[0],
            user_id=row[1],
            reason=ChangeReason(row[2]),
            watch_list_source=None if row[3] is None else WatchListSource(row[3]),
            watch_list_id=row[4],
        )

    async def consume(self, conn: AsyncConnection[Any], challenge: ChangeChallenge) -> bool:
        """Use the challenge up; False if another request already did, or it lapsed."""
        cur = await conn.execute(
            sql.SQL("UPDATE {} SET consumed_at = now() WHERE id = %s AND {} RETURNING 1").format(
                _CHALLENGES, self._live
            ),
            (challenge.id,),
        )
        return await cur.fetchone() is not None

    async def record_failure(self, challenge: ChangeChallenge) -> None:
        """Count a refused attempt against the challenge, in its own transaction."""
        async with self._db.transaction() as tx:
            await tx.execute(
                sql.SQL("UPDATE {} SET failed_attempts = failed_attempts + 1 WHERE id = %s").format(
                    _CHALLENGES
                ),
                (challenge.id,),
            )

    async def prune(self) -> int:
        """Delete expired challenges, used or not."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE expires_at <= now()").format(_CHALLENGES)
            )
            return cur.rowcount
