"""Audit routers: list, export and verify, behind the product's own authorisation."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import psycopg
import pytest
from fastapi import FastAPI, Header, HTTPException

from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.actions import EXPORT_ACTION
from warden.audit.query import AuditQuery, list_events
from warden.audit.router import audit_router
from warden.db import Database
from warden.proxy import TrustedProxyMiddleware

pytestmark = pytest.mark.db


class NoKeys:
    async def verify_historical(self, message: bytes, signature: bytes, key_id: str) -> bool:
        return False


async def reader(x_test_user: str | None = Header(default=None)) -> str:
    """A stand-in for the product's own authorisation dependency."""
    if x_test_user is None:
        raise HTTPException(status_code=403, detail="forbidden")
    return x_test_user


async def exporter(x_test_user: str | None = Header(default=None)) -> str:
    if x_test_user != "auditor-1":
        raise HTTPException(status_code=403, detail="forbidden")
    return x_test_user


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.login", severity=Severity.INFO, summary="{actor}")
    return registry


@pytest.fixture
async def client(pool: Any, registry: ActionRegistry) -> AsyncIterator[httpx.AsyncClient]:
    recorder = AuditRecorder(Database(pool), registry)
    for actor in ("alice", "bob", "alice"):
        await recorder.record(AuditEvent(action="product.login", outcome="success", actor=actor))
    app = FastAPI()
    app.include_router(
        audit_router(recorder=recorder, keys=NoKeys(), authorise=reader, authorise_export=exporter),
        prefix="/audit",
    )
    wrapped = TrustedProxyMiddleware(app, trusted_proxies=["127.0.0.0/8"])
    transport = httpx.ASGITransport(app=wrapped, client=("127.0.0.1", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


USER = {"x-test-user": "alice"}
AUDITOR = {"x-test-user": "auditor-1", "x-forwarded-for": "203.0.113.5"}


@pytest.mark.parametrize("path", ["/audit/events", "/audit/export?format=csv", "/audit/verify"])
async def test_every_route_needs_the_products_authorisation(
    client: httpx.AsyncClient, path: str
) -> None:
    response = await client.get(path)
    assert response.status_code == 403


async def test_list_returns_events_newest_first_with_a_cursor(client: httpx.AsyncClient) -> None:
    response = await client.get("/audit/events", params={"limit": 2}, headers=USER)
    assert response.status_code == 200
    body = response.json()
    assert [e["actor"] for e in body["events"]] == ["alice", "bob"]
    assert body["next_before_id"] == body["events"][-1]["id"]
    older = await client.get(
        "/audit/events", params={"limit": 2, "before_id": body["next_before_id"]}, headers=USER
    )
    assert [e["actor"] for e in older.json()["events"]] == ["alice"]
    assert older.json()["next_before_id"] is None


async def test_list_filters(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/audit/events", params={"actor": "bob", "action": ["product.login"]}, headers=USER
    )
    assert [e["actor"] for e in response.json()["events"]] == ["bob"]


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 1001},
        {"outcome": "maybe"},
        {"since": "2026-10-02T00:00:00Z", "until": "2026-10-01T00:00:00Z"},
        {"since": "2026-10-01T00:00:00"},
    ],
)
async def test_invalid_filters_are_refused(
    client: httpx.AsyncClient, params: dict[str, Any]
) -> None:
    response = await client.get("/audit/events", params=params, headers=USER)
    assert response.status_code == 422


async def test_export_needs_the_export_authorisation(client: httpx.AsyncClient) -> None:
    response = await client.get("/audit/export", params={"format": "csv"}, headers=USER)
    assert response.status_code == 403


async def test_csv_export_is_audited_with_actor_and_real_client_address(
    client: httpx.AsyncClient, pool: Any
) -> None:
    response = await client.get(
        "/audit/export", params={"format": "csv", "actor": "alice"}, headers=AUDITOR
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(response.text)))
    assert [r[5] for r in rows[1:]] == ["alice", "alice"]

    page = await list_events(Database(pool), AuditQuery(actions=(EXPORT_ACTION,)))
    (event,) = page.rows
    assert event.actor == "auditor-1"
    assert str(event.source_ip) == "203.0.113.5"
    assert event.details == {"format": "csv", "filter": {"actor": "alice"}}


async def test_ndjson_export(client: httpx.AsyncClient) -> None:
    response = await client.get("/audit/export", params={"format": "ndjson"}, headers=AUDITOR)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    actors = [json.loads(line)["actor"] for line in response.text.splitlines()]
    assert actors[:3] == ["alice", "bob", "alice"]


async def test_an_unknown_export_format_is_refused_and_not_audited(
    client: httpx.AsyncClient, pool: Any
) -> None:
    response = await client.get("/audit/export", params={"format": "xlsx"}, headers=AUDITOR)
    assert response.status_code == 422
    page = await list_events(Database(pool), AuditQuery(actions=(EXPORT_ACTION,)))
    assert page.rows == []


async def test_verify_reports_an_intact_chain(client: httpx.AsyncClient) -> None:
    response = await client.get("/audit/verify", headers=USER)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["rows"] == 3
    assert body["broken"] is None
    assert len(bytes.fromhex(body["head_hash"])) == 32


async def test_verify_names_the_first_broken_link(
    client: httpx.AsyncClient, migrated_dsn: str
) -> None:
    with psycopg.connect(migrated_dsn) as conn:
        row = conn.execute("SELECT min(id) + 1 FROM warden.audit_events").fetchone()
        assert row is not None
        conn.execute("UPDATE warden.audit_events SET actor = 'mallory' WHERE id = %s", row)
    body = (await client.get("/audit/verify", headers=USER)).json()
    assert body["ok"] is False
    assert body["broken"]["row_id"] == row[0]
    assert body["broken"]["reason"] == "row_hash"
    assert body["broken"]["description"]
