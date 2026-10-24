"""The pool adapter and transaction helper over a product-supplied pool."""

from __future__ import annotations

from typing import Any

import pytest

from warden.db import Database

pytestmark = pytest.mark.db


async def _count(db: Database) -> int:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.settings")
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def test_transaction_commits_on_success(pool: Any) -> None:
    db = Database(pool)
    async with db.transaction() as conn:
        await conn.execute("INSERT INTO warden.settings (key, value) VALUES ('a', '1')")
    assert await _count(db) == 1


async def test_transaction_rolls_back_on_error(pool: Any) -> None:
    db = Database(pool)
    with pytest.raises(RuntimeError):
        async with db.transaction() as conn:
            await conn.execute("INSERT INTO warden.settings (key, value) VALUES ('a', '1')")
            raise RuntimeError("boom")
    assert await _count(db) == 0


async def test_transaction_joins_the_callers_transaction(pool: Any) -> None:
    db = Database(pool)
    async with pool.connection() as outer:
        with pytest.raises(RuntimeError):
            async with outer.transaction():
                async with db.transaction(outer) as conn:
                    assert conn is outer
                    await conn.execute("INSERT INTO warden.settings (key, value) VALUES ('a', '1')")
                raise RuntimeError("caller rolls back")
    assert await _count(db) == 0


async def test_database_uses_the_pool_it_was_given(pool: Any) -> None:
    db = Database(pool)
    assert db.pool is pool
