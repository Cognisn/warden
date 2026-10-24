"""Database access over the product's own psycopg 3 async pool.

warden never opens a pool. The product passes in the ``AsyncConnectionPool``
it already runs, so a product write and the audit event that records it can
commit in one transaction.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Protocol

from psycopg import AsyncConnection

__all__ = ["ConnectionSource", "Database"]


class ConnectionSource(Protocol):
    """Anything that lends async connections; ``psycopg_pool.AsyncConnectionPool`` fits."""

    def connection(self) -> AbstractAsyncContextManager[AsyncConnection[Any]]: ...


class Database:
    """warden's handle on the product's connection pool."""

    def __init__(self, pool: ConnectionSource) -> None:
        self._pool = pool

    @property
    def pool(self) -> ConnectionSource:
        return self._pool

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection[Any]]:
        """Borrow a connection from the product's pool."""
        async with self._pool.connection() as conn:
            yield conn

    @asynccontextmanager
    async def transaction(
        self, conn: AsyncConnection[Any] | None = None
    ) -> AsyncIterator[AsyncConnection[Any]]:
        """Run a block in a transaction.

        With ``conn``, the block joins the caller's transaction (as a
        savepoint), so it commits or rolls back with the caller's work.
        Without it, a connection is borrowed and its transaction commits when
        the block exits cleanly and rolls back if it raises.
        """
        if conn is not None:
            async with conn.transaction():
                yield conn
            return
        async with self._pool.connection() as borrowed, borrowed.transaction():
            yield borrowed
