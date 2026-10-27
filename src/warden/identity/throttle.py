"""Sign-in throttling per (identifier, source address).

Each password attempt reserves one slot in a fixed window with a single
atomic upsert, before the password is checked, so concurrent attempts can
never exceed the limit. Attempts beyond it are refused, with the same
response as any other failure, without checking the password.

Keyed on the pair, so an attacker elsewhere cannot lock a user out, and on
the identifier as typed (lower-cased) whether or not an account exists, so
throttling reveals nothing about which accounts exist. Only issuing a
session clears the count: a correct password followed by an MFA challenge
does not, or a password holder would get unlimited code guesses.

The source address is the client's, resolved through the trusted-proxy
resolver (``audit.trusted_proxies``), so clients behind one proxy are
throttled separately. A per-address ceiling across identifiers is not
implemented.
"""

from __future__ import annotations

import hashlib
from typing import Any

from psycopg import AsyncConnection, sql

from warden.db import Database, table
from warden.identity import schema
from warden.identity.http import SourceIp

__all__ = ["SignInThrottle"]

_ATTEMPTS = table(schema.SIGN_IN_ATTEMPTS)
_IN_WINDOW = sql.SQL("t.window_started_at > now() - %(window)s * interval '1 second'")


def throttle_key(identifier: str, source_ip: SourceIp) -> bytes:
    material = f"{identifier.lower()}\0{source_ip if source_ip is not None else '-'}"
    return hashlib.sha256(material.encode("utf-8")).digest()


class SignInThrottle:
    def __init__(self, db: Database, *, limit: int, window_seconds: int) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("sign-in throttle limit and window must be positive")
        self._db = db
        self._limit = limit
        self._window = window_seconds

    async def reserve(self, identifier: str, source_ip: SourceIp) -> bool:
        """Take one attempt; False if the pair has used up its window."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL(
                    "INSERT INTO {} AS t (key_hash, window_started_at, attempts)"
                    " VALUES (%(key)s, now(), 1)"
                    " ON CONFLICT (key_hash) DO UPDATE SET"
                    " attempts = CASE WHEN {} THEN t.attempts + 1 ELSE 1 END,"
                    " window_started_at = CASE WHEN {} THEN t.window_started_at ELSE now() END"
                    " RETURNING attempts"
                ).format(_ATTEMPTS, _IN_WINDOW, _IN_WINDOW),
                {"key": throttle_key(identifier, source_ip), "window": self._window},
            )
            row = await cur.fetchone()
        return row is not None and int(row[0]) <= self._limit

    async def clear(self, conn: AsyncConnection[Any], identifier: str, source_ip: SourceIp) -> None:
        """Forget the pair's attempts; call in the transaction that issues a session."""
        await conn.execute(
            sql.SQL("DELETE FROM {} WHERE key_hash = %s").format(_ATTEMPTS),
            (throttle_key(identifier, source_ip),),
        )

    async def prune(self) -> int:
        """Delete records whose window has ended; returns how many."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} t WHERE NOT ({})").format(_ATTEMPTS, _IN_WINDOW),
                {"window": self._window},
            )
            return cur.rowcount
