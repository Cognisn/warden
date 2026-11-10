"""Password history (ruling PW6).

Each password a user sets is kept as its Argon2id hash, and only that: no
fast hash is ever kept for history. A check verifies the candidate against
each of the last N hashes with a real Argon2id verification, run in a worker
thread so it never stalls the event loop. History is checked only when a
password is submitted, never by the live check route (PW10).

Pruning removes history beyond the largest count any policy keeps, under
the password-policy lock so a policy raised meanwhile is honoured.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from psycopg import AsyncConnection, sql

from warden.db import PASSWORD_HISTORY, PASSWORD_STATES, Database, table
from warden.identity.passwords import PasswordHasher

if TYPE_CHECKING:
    from warden.identity.password_policy.store import PasswordPolicies

__all__ = ["PasswordHistory"]

_HISTORY = table(PASSWORD_HISTORY)
_STATES = table(PASSWORD_STATES)
_MAX_HISTORY = 24


class PasswordHistory:
    """Previous Argon2id hashes per user."""

    def __init__(self, db: Database, hasher: PasswordHasher) -> None:
        self._db = db
        self._hasher = hasher

    async def record(
        self, user_id: uuid.UUID, password_hash: str, *, conn: AsyncConnection[Any] | None = None
    ) -> None:
        """Keep ``password_hash`` (Argon2id only) as the user's newest previous password."""
        if not password_hash.startswith("$argon2id$"):
            raise ValueError("history keeps Argon2id hashes only")
        async with self._db.transaction(conn) as tx:
            await tx.execute(
                sql.SQL("INSERT INTO {} (user_id, password_hash) VALUES (%s, %s)").format(_HISTORY),
                (user_id, password_hash),
            )

    async def reused(
        self,
        user_id: uuid.UUID,
        password: str,
        *,
        count: int,
        conn: AsyncConnection[Any] | None = None,
    ) -> bool:
        """Whether ``password`` matches any of the user's last ``count`` passwords."""
        if count <= 0:
            return False
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT password_hash FROM {} WHERE user_id = %s"
                    " ORDER BY set_at DESC, id DESC LIMIT %s"
                ).format(_HISTORY),
                (user_id, min(count, _MAX_HISTORY)),
            )
            hashes = [row[0] for row in await cur.fetchall()]
        for encoded in hashes:
            if (await self._hasher.verify(encoded, password)).ok:
                return True
        return False

    async def too_soon(
        self,
        user_id: uuid.UUID,
        *,
        min_age_hours: int,
        now: datetime | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> bool:
        """Whether the current password is younger than ``min_age_hours``."""
        if min_age_hours <= 0:
            return False
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT coalesce((SELECT password_set_at FROM {} WHERE user_id = %s),"
                    " (SELECT max(set_at) FROM {} WHERE user_id = %s))"
                ).format(_STATES, _HISTORY),
                (user_id, user_id),
            )
            row = await cur.fetchone()
        set_at = None if row is None else row[0]
        if set_at is None:
            return False
        moment = now if now is not None else datetime.now(UTC)
        return bool(moment < set_at + timedelta(hours=min_age_hours))

    async def prune(self, policies: PasswordPolicies) -> int:
        """Delete history beyond the largest count any policy keeps; returns how many."""
        from warden.identity.password_policy.store import lock_policies

        async with self._db.transaction() as tx:
            await lock_policies(tx)
            keep = await policies.largest_history(conn=tx)
            cur = await tx.execute(
                sql.SQL(
                    "DELETE FROM {history} h USING ("
                    " SELECT id, row_number() OVER"
                    " (PARTITION BY user_id ORDER BY set_at DESC, id DESC) AS rank FROM {history}"
                    ") r WHERE h.id = r.id AND r.rank > %s"
                ).format(history=_HISTORY),
                (keep,),
            )
            return cur.rowcount
