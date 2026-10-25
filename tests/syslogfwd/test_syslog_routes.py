"""Status and test-send routes, authorised by a dependency the product supplies."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Header, HTTPException

from syslogfwd.collector import StreamCollector
from warden.audit import ActionRegistry, AuditRecorder, Severity
from warden.audit.syslog import (
    SYSLOG_TEST_ACTION,
    SyslogForwarder,
    SyslogSettings,
    register_syslog_actions,
    syslog_router,
)
from warden.db import Database

pytestmark = pytest.mark.db


def authorise(x_test_actor: str | None = Header(default=None)) -> str:
    if x_test_actor != "admin-1":
        raise HTTPException(status_code=403, detail="forbidden")
    return x_test_actor


def _settings(port: int, **kw: Any) -> SyslogSettings:
    values: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port,
        "transport": "tcp",
        "sd_id": "warden@99999",
        "hostname": "app-1.example.com",
        # Windows retries a refused loopback connection for about two seconds.
        "connect_timeout_seconds": 5,
    }
    values.update(kw)
    return SyslogSettings(**values)


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    register_syslog_actions(registry)
    return registry


@pytest.fixture
async def collector() -> AsyncIterator[StreamCollector]:
    collector = StreamCollector()
    await collector.start()
    yield collector
    await collector.stop()


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _audit_rows(pool: Any) -> list[tuple[Any, ...]]:
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT action, outcome, actor, details FROM warden.audit_events ORDER BY id"
        )
        return list(await cur.fetchall())


async def test_status_reports_the_forwarder(
    pool: Any, registry: ActionRegistry, collector: StreamCollector
) -> None:
    forwarder = SyslogForwarder(Database(pool), _settings(collector.port), registry)
    app = FastAPI()
    app.include_router(syslog_router(forwarder, authorise=authorise), prefix="/audit")
    async with await _client(app) as client:
        response = await client.get("/audit/syslog/status", headers={"x-test-actor": "admin-1"})
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "stopped"
    assert body["cursor"] is None and body["lag"] is None
    assert set(body) >= {"connected", "last_error", "last_error_at", "sent", "gaps_skipped"}
    assert "dropped" not in body


async def test_routes_refuse_without_authorisation(
    pool: Any, registry: ActionRegistry, collector: StreamCollector
) -> None:
    forwarder = SyslogForwarder(Database(pool), _settings(collector.port), registry)
    app = FastAPI()
    app.include_router(syslog_router(forwarder, authorise=authorise))
    async with await _client(app) as client:
        assert (await client.get("/syslog/status")).status_code == 403
        assert (await client.post("/syslog/test")).status_code == 403
    assert collector.connections == 0


async def test_test_send_delivers_one_message_and_audits_it(
    pool: Any, registry: ActionRegistry, collector: StreamCollector
) -> None:
    db = Database(pool)
    forwarder = SyslogForwarder(db, _settings(collector.port), registry)
    recorder = AuditRecorder(db, registry)
    app = FastAPI()
    app.include_router(syslog_router(forwarder, authorise=authorise, recorder=recorder))
    async with await _client(app) as client:
        response = await client.post("/syslog/test", headers={"x-test-actor": "admin-1"})
    assert response.status_code == 200
    assert response.json() == {"delivered": True, "error": None}
    (frame,) = await collector.wait_for_frames(1)
    assert b' warden - test [warden@99999 test="true"]' in frame
    assert await _audit_rows(pool) == [(SYSLOG_TEST_ACTION, "success", "admin-1", {})]


async def test_test_send_reports_a_fixed_error_category(
    pool: Any, registry: ActionRegistry
) -> None:
    stopped = StreamCollector()
    port = await stopped.start()
    await stopped.stop()
    db = Database(pool)
    forwarder = SyslogForwarder(db, _settings(port), registry)
    recorder = AuditRecorder(db, registry)
    app = FastAPI()
    app.include_router(syslog_router(forwarder, authorise=authorise, recorder=recorder))
    async with await _client(app) as client:
        response = await client.post("/syslog/test", headers={"x-test-actor": "admin-1"})
    assert response.status_code == 200
    assert response.json() == {"delivered": False, "error": "connection refused"}
    assert await _audit_rows(pool) == [
        (SYSLOG_TEST_ACTION, "failure", "admin-1", {"error": "connection refused"})
    ]


def test_the_syslog_actions_register_idempotently() -> None:
    registry = ActionRegistry()
    register_syslog_actions(registry)
    register_syslog_actions(registry)
    assert SYSLOG_TEST_ACTION in registry
