"""Query and export against a real trail: filters, paging, streaming, and auditing exports."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.actions import EXPORT_ACTION
from warden.audit.export import export
from warden.audit.query import MAX_PAGE_SIZE, AuditQuery, iter_events, list_events
from warden.db import Database

pytestmark = pytest.mark.db

T0 = datetime(2026, 10, 1, tzinfo=UTC)


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    for action in ("product.export", "product.login", "product.delete"):
        registry.register(action, severity=Severity.INFO, summary="{action}")
    return registry


@pytest.fixture
async def trail(pool: Any, registry: ActionRegistry) -> list[int]:
    recorder = AuditRecorder(Database(pool), registry)
    specs: list[dict[str, Any]] = [
        {"action": "product.login", "outcome": "success", "actor": "alice"},
        {"action": "product.login", "outcome": "failure", "actor": "bob"},
        {"action": "product.export", "outcome": "success", "actor": "alice",
         "resource_type": "report", "resource_id": "r-1"},
        {"action": "product.delete", "outcome": "success", "actor": "carol",
         "resource_type": "report", "resource_id": "r-2"},
        {"action": "product.export", "outcome": "failure", "actor": "bob",
         "resource_type": "invoice", "resource_id": "i-1"},
    ]  # fmt: skip
    return [
        await recorder.record(AuditEvent(occurred_at=T0 + timedelta(days=n), **spec))
        for n, spec in enumerate(specs)
    ]


async def _ids(db: Database, **filters: Any) -> list[int]:
    return [row.id async for row in iter_events(db, AuditQuery(**filters))]


@pytest.mark.parametrize(
    ("filters", "positions"),
    [
        ({}, [0, 1, 2, 3, 4]),
        ({"actor": "alice"}, [0, 2]),
        ({"outcome": "failure"}, [1, 4]),
        ({"actions": ("product.export",)}, [2, 4]),
        ({"actions": ("product.export", "product.delete")}, [2, 3, 4]),
        ({"resource_type": "report"}, [2, 3]),
        ({"resource_type": "report", "resource_id": "r-2"}, [3]),
        ({"since": T0 + timedelta(days=1)}, [1, 2, 3, 4]),
        ({"until": T0 + timedelta(days=2)}, [0, 1]),
        ({"since": T0 + timedelta(days=1), "until": T0 + timedelta(days=3)}, [1, 2]),
        ({"actor": "alice", "outcome": "failure"}, []),
        ({"actor": "'; DROP TABLE warden.audit_events; --"}, []),
    ],
)
async def test_filters(
    pool: Any, trail: list[int], filters: dict[str, Any], positions: list[int]
) -> None:
    assert await _ids(Database(pool), **filters) == [trail[p] for p in positions]


def test_an_empty_or_inverted_time_range_is_refused() -> None:
    with pytest.raises(ValidationError):
        AuditQuery(since=T0, until=T0)


async def test_pages_run_newest_first_and_end(pool: Any, trail: list[int]) -> None:
    db = Database(pool)
    first = await list_events(db, AuditQuery(), limit=2)
    assert [r.id for r in first.rows] == [trail[4], trail[3]]
    second = await list_events(db, AuditQuery(), limit=2, before_id=first.next_before_id)
    assert [r.id for r in second.rows] == [trail[2], trail[1]]
    last = await list_events(db, AuditQuery(), limit=2, before_id=second.next_before_id)
    assert [r.id for r in last.rows] == [trail[0]]
    assert last.next_before_id is None


async def test_page_size_is_bounded(pool: Any) -> None:
    with pytest.raises(ValueError, match="limit"):
        await list_events(Database(pool), AuditQuery(), limit=MAX_PAGE_SIZE + 1)


async def _collect(lines: Any) -> str:
    return "".join([line async for line in lines])


async def test_an_export_is_itself_audited_before_it_streams(
    pool: Any, registry: ActionRegistry, trail: list[int]
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    lines = await export(
        recorder, AuditQuery(actor="alice"), "csv", actor="auditor-1", source_ip="192.0.2.10"
    )
    # Recorded before a single line is read.
    page = await list_events(Database(pool), AuditQuery(actions=(EXPORT_ACTION,)))
    (event,) = page.rows
    assert (event.actor, event.outcome, str(event.source_ip)) == (
        "auditor-1",
        "success",
        "192.0.2.10",
    )
    assert event.details == {"format": "csv", "filter": {"actor": "alice"}}

    parsed = list(csv.reader(io.StringIO(await _collect(lines))))
    assert [int(r[0]) for r in parsed[1:]] == [trail[0], trail[2]]


async def test_ndjson_export_streams_every_matching_row_in_chain_order(
    pool: Any, registry: ActionRegistry, trail: list[int]
) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    lines = await export(recorder, AuditQuery(), "ndjson", actor="auditor-1")
    ids = [json.loads(line)["id"] for line in (await _collect(lines)).splitlines()]
    # The export's own audit event is committed first, so it is the last row.
    assert ids[:-1] == trail
    assert len(ids) == len(trail) + 1


async def test_a_large_export_streams_across_batches(pool: Any, registry: ActionRegistry) -> None:
    recorder = AuditRecorder(Database(pool), registry)
    for n in range(23):
        await recorder.record(AuditEvent(action="product.login", outcome="success", actor=str(n)))
    rows = [r async for r in iter_events(Database(pool), AuditQuery(), batch_size=5)]
    assert [r.actor for r in rows] == [str(n) for n in range(23)]
