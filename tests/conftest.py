"""Shared fixtures. Database tests use a real Postgres through testcontainers."""

from __future__ import annotations

import asyncio
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest

if sys.platform == "win32":
    # psycopg's async driver cannot run on the Proactor event loop.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

POSTGRES_IMAGE = "postgres:17-alpine"


@pytest.fixture(scope="session")
def pg_admin_url() -> Iterator[str]:
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer(POSTGRES_IMAGE, driver=None) as container:
        yield container.get_connection_url()


@pytest.fixture
def dsn(pg_admin_url: str) -> Iterator[str]:
    """A fresh, empty database for one test."""
    import psycopg
    from psycopg import sql

    name = "t_" + uuid.uuid4().hex[:16]
    with psycopg.connect(pg_admin_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    base, _, _ = pg_admin_url.rpartition("/")
    yield f"{base}/{name}"
    with psycopg.connect(pg_admin_url, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


@pytest.fixture
def migrated_dsn(dsn: str) -> str:
    from warden.db import migrate

    migrate(dsn)
    return dsn


@pytest.fixture
async def pool(migrated_dsn: str) -> AsyncIterator[Any]:
    from psycopg_pool import AsyncConnectionPool

    pool: Any = AsyncConnectionPool(migrated_dsn, min_size=1, max_size=6, open=False)
    await pool.open(wait=True)
    try:
        yield pool
    finally:
        await pool.close()
