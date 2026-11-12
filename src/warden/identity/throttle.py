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
implemented for passwords.

A passkey sign-in names no identifier, so it is throttled on two keys of
its own, each with the same limit and window: the source address, and the
hash of the credential id the response offers, so that neither one address
nor one credential gets unlimited attempts. Both are reserved for every
attempt and both are cleared by a passkey sign-in that issues a session.
Their key material starts with a byte no UTF-8 text contains, so they can
never equal a password attempt's key.

The live password feedback routes (ruling PW10) are throttled on two keys
of their own: the credential they are bound to (a session, a link's token
or a forced-change challenge, hashed) and the source address. A check is
made as the user types, so their budgets are larger than sign-in's: by
default ten times ``limit`` per credential and fifty times per address,
in the same window. Nothing clears them; the window ends.

The passkey options route is throttled on a third key of its own, the
source address, with the same limit and window. It is separate from the
passkey sign-in address key, so fetching options (on every sign-in page
load, with conditional mediation) does not spend the sign-in budget, and
sign-in failures do not spend the options budget. A passkey sign-in that
issues a session clears it for its address along with the other two.
"""

from __future__ import annotations

import hashlib
from typing import Any

from psycopg import AsyncConnection, sql

from warden.db import Database, schema, table
from warden.identity.http import SourceIp

__all__ = ["SignInThrottle"]

_ATTEMPTS = table(schema.SIGN_IN_ATTEMPTS)
_IN_WINDOW = sql.SQL("t.window_started_at > now() - %(window)s * interval '1 second'")


def throttle_key(identifier: str, source_ip: SourceIp) -> bytes:
    material = f"{identifier.lower()}\0{source_ip if source_ip is not None else '-'}"
    return hashlib.sha256(material.encode("utf-8")).digest()


# 0xFF never occurs in UTF-8, so these keys cannot equal a password key.
_PASSKEY_ADDRESS = b"\xffpasskey-address\x00"
_PASSKEY_CREDENTIAL = b"\xffpasskey-credential\x00"
_PASSKEY_OPTIONS = b"\xffpasskey-options\x00"
_CHECK_ADDRESS = b"\xffpassword-check-address\x00"
_CHECK_CREDENTIAL = b"\xffpassword-check-credential\x00"
# The password check budgets, as multiples of the sign-in limit.
CHECK_CREDENTIAL_FACTOR = 10
CHECK_ADDRESS_FACTOR = 50


def _address(source_ip: SourceIp) -> bytes:
    return str(source_ip if source_ip is not None else "-").encode("ascii")


def passkey_keys(source_ip: SourceIp, credential_id: bytes) -> tuple[bytes, bytes]:
    """The passkey throttle's keys: the source address, and the credential id's hash."""
    return (
        hashlib.sha256(_PASSKEY_ADDRESS + _address(source_ip)).digest(),
        hashlib.sha256(_PASSKEY_CREDENTIAL + hashlib.sha256(credential_id).digest()).digest(),
    )


def passkey_options_key(source_ip: SourceIp) -> bytes:
    """The passkey options throttle's key: the source address, apart from sign-in's."""
    return hashlib.sha256(_PASSKEY_OPTIONS + _address(source_ip)).digest()


def password_check_keys(source_ip: SourceIp, credential: bytes) -> tuple[bytes, bytes]:
    """The password check throttle's keys: the credential's hash, and the source address."""
    return (
        hashlib.sha256(_CHECK_CREDENTIAL + hashlib.sha256(credential).digest()).digest(),
        hashlib.sha256(_CHECK_ADDRESS + _address(source_ip)).digest(),
    )


class SignInThrottle:
    def __init__(
        self,
        db: Database,
        *,
        limit: int,
        window_seconds: int,
        check_limit: int | None = None,
    ) -> None:
        """``check_limit`` is the password check budget per credential (by default
        ``CHECK_CREDENTIAL_FACTOR`` times ``limit``); an address gets five times it."""
        if limit < 1 or window_seconds < 1:
            raise ValueError("sign-in throttle limit and window must be positive")
        if check_limit is not None and check_limit < 1:
            raise ValueError("the password check limit must be positive")
        self._db = db
        self._limit = limit
        self._window = window_seconds
        self._check_limit = check_limit or limit * CHECK_CREDENTIAL_FACTOR
        self._check_address_limit = self._check_limit * (
            CHECK_ADDRESS_FACTOR // CHECK_CREDENTIAL_FACTOR
        )

    async def reserve(self, identifier: str, source_ip: SourceIp) -> bool:
        """Take one attempt; False if the pair has used up its window."""
        return await self._reserve(throttle_key(identifier, source_ip))

    async def reserve_passkey(self, source_ip: SourceIp, credential_id: bytes) -> bool:
        """Take one passkey attempt on both keys; False if either has used up its window.

        Both are always taken, so a throttled address still counts against
        the credential and the other way round.
        """
        address, credential = passkey_keys(source_ip, credential_id)
        by_address = await self._reserve(address)
        by_credential = await self._reserve(credential)
        return by_address and by_credential

    async def reserve_passkey_options(self, source_ip: SourceIp) -> bool:
        """Take one passkey options request; False if the address has used up its window."""
        return await self._reserve(passkey_options_key(source_ip))

    async def reserve_password_check(self, source_ip: SourceIp, credential: bytes) -> bool:
        """Take one password check or policy read on both keys; False if either is used up.

        Both are always taken, as for a passkey attempt. ``credential`` is the
        session id or the token the route is bound to; only its hash is kept.
        """
        by_credential, by_address = password_check_keys(source_ip, credential)
        first = await self._reserve(by_credential, self._check_limit)
        second = await self._reserve(by_address, self._check_address_limit)
        return first and second

    async def _reserve(self, key: bytes, limit: int | None = None) -> bool:
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
                {"key": key, "window": self._window},
            )
            row = await cur.fetchone()
        return row is not None and int(row[0]) <= (self._limit if limit is None else limit)

    async def clear(self, conn: AsyncConnection[Any], identifier: str, source_ip: SourceIp) -> None:
        """Forget the pair's attempts; call in the transaction that issues a session."""
        await conn.execute(
            sql.SQL("DELETE FROM {} WHERE key_hash = %s").format(_ATTEMPTS),
            (throttle_key(identifier, source_ip),),
        )

    async def clear_passkey(
        self, conn: AsyncConnection[Any], source_ip: SourceIp, credential_id: bytes
    ) -> None:
        """Forget the passkey keys' attempts; call in the transaction that issues a session.

        Both sign-in keys, and the options key for the same address.
        """
        keys = [*passkey_keys(source_ip, credential_id), passkey_options_key(source_ip)]
        await conn.execute(
            sql.SQL("DELETE FROM {} WHERE key_hash = ANY(%s)").format(_ATTEMPTS), (keys,)
        )

    async def prune(self) -> int:
        """Delete records whose window has ended; returns how many."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} t WHERE NOT ({})").format(_ATTEMPTS, _IN_WINDOW),
                {"window": self._window},
            )
            return cur.rowcount
