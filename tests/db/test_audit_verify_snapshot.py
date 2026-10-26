"""Verification reads one snapshot: a purge committing mid-verification breaks nothing."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest

from chain_support import age
from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.actions import PURGE_ACTION, register_audit_actions
from warden.audit.retention import MIN_RETENTION_DAYS, purge
from warden.audit.verify import verify_chain
from warden.db import Database
from warden.keys import KeyStore

pytestmark = pytest.mark.db


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


class _AfterFirstQuery:
    """Delegates to a connection, running ``hook`` once after the checkpoint listing."""

    def __init__(self, conn: Any, hook: Callable[[], Awaitable[None]]) -> None:
        self._conn = conn
        self._hook: Callable[[], Awaitable[None]] | None = hook

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        cur = await self._conn.execute(*args, **kwargs)
        if args[1:] == ((PURGE_ACTION,),) and self._hook is not None:
            hook, self._hook = self._hook, None
            await hook()
        return cur


class _HookedPool:
    def __init__(self, pool: Any, hook: Callable[[], Awaitable[None]]) -> None:
        self._pool = pool
        self._hook = hook

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[Any]:
        async with self._pool.connection() as conn:
            yield _AfterFirstQuery(conn, self._hook)


async def test_a_purge_committing_during_verification_breaks_nothing(
    pool: Any, migrated_dsn: str
) -> None:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor}")
    register_audit_actions(registry)
    recorder = AuditRecorder(Database(pool), registry)
    keys = KeyStore(Database(pool), MemorySecrets())
    await keys.rotate()
    ids = [
        await recorder.record(AuditEvent(action="product.export", outcome="success"))
        for _ in range(4)
    ]
    age(migrated_dsn, ids[:2], MIN_RETENTION_DAYS + 10)
    purged: list[int] = []

    async def purge_now() -> None:
        result = await purge(recorder, keys, retention_days=MIN_RETENTION_DAYS)
        purged.append(result.purged_rows)

    report = await verify_chain(Database(_HookedPool(pool, purge_now)), keys)
    assert purged == [2]
    assert report.ok, report.broken
    # The snapshot predates the purge, so every original row was verified.
    assert (report.first_id, report.rows) == (ids[0], 4)
