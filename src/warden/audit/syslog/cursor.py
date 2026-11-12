"""The forwarder's cursor: the id of the last audit row handed to the transport.

It lives in ``warden.settings`` under ``SYSLOG_CURSOR_SETTING``. Stores are
monotonic (the stored value only ever increases), so a forwarder that lost
its leadership mid-batch can never move a newer leader's cursor backwards.

This module touches only the settings table. It is kept apart from the code
that reads the audit table so the single-writer tripwire stays exact.
"""

from __future__ import annotations

from typing import Any

from psycopg import AsyncConnection, sql

from warden.db import SETTINGS, SYSLOG_CURSOR_SETTING, table

__all__ = ["initialise_cursor", "load_cursor", "store_cursor"]

_LOAD = sql.SQL("SELECT (value #>> '{{}}')::bigint FROM {} WHERE key = %s").format(table(SETTINGS))

_INITIALISE = sql.SQL(
    "INSERT INTO {} (key, value) VALUES (%s, to_jsonb(%s::bigint)) ON CONFLICT (key) DO NOTHING"
).format(table(SETTINGS))

_STORE = sql.SQL(
    "INSERT INTO {} AS s (key, value) VALUES (%s, to_jsonb(%s::bigint))"
    " ON CONFLICT (key) DO UPDATE SET"
    " value = to_jsonb(GREATEST("
    "(s.value #>> '{{}}')::bigint, (EXCLUDED.value #>> '{{}}')::bigint)),"
    " updated_at = now()"
).format(table(SETTINGS))


async def load_cursor(conn: AsyncConnection[Any]) -> int | None:
    """The stored cursor, or ``None`` if the forwarder has never run."""
    cur = await conn.execute(_LOAD, (SYSLOG_CURSOR_SETTING,))
    row = await cur.fetchone()
    return None if row is None or row[0] is None else int(row[0])


async def initialise_cursor(conn: AsyncConnection[Any], start: int) -> int:
    """Store ``start`` if no cursor exists yet, and return the cursor in force."""
    await conn.execute(_INITIALISE, (SYSLOG_CURSOR_SETTING, start))
    stored = await load_cursor(conn)
    if stored is None:
        raise RuntimeError("syslog cursor could not be initialised")
    return stored


async def store_cursor(conn: AsyncConnection[Any], value: int) -> None:
    """Advance the stored cursor to ``value``; never moves it backwards."""
    await conn.execute(_STORE, (SYSLOG_CURSOR_SETTING, value))
