"""Export audit rows as CSV or NDJSON, streamed.

CSV cells beginning with ``=``, ``+``, ``-``, ``@``, a tab or a carriage
return are prefixed with ``'`` so a spreadsheet shows them as text rather
than evaluating a formula. NDJSON is written with ASCII escapes, so no
character in a value (U+2028 included) can split a record.

``export`` records the export itself in the audit trail before the first
line is produced.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterable, AsyncIterator
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Literal

from warden.audit.actions import EXPORT_ACTION, register_audit_actions
from warden.audit.chain import canonical_json, timestamp_text
from warden.audit.events import AuditEvent
from warden.audit.query import AuditQuery, iter_events
from warden.audit.recorder import AuditRecorder
from warden.audit.store import AuditRow

__all__ = [
    "CSV_COLUMNS",
    "ExportFormat",
    "csv_lines",
    "escape_cell",
    "export",
    "ndjson_lines",
    "row_to_json",
]

ExportFormat = Literal["csv", "ndjson"]

CSV_COLUMNS = (
    "id",
    "recorded_at",
    "occurred_at",
    "action",
    "outcome",
    "actor",
    "resource_type",
    "resource_id",
    "source_ip",
    "details",
    "key_id",
    "prev_hash",
    "row_hash",
)

_FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r")


def escape_cell(value: str) -> str:
    """``value``, made safe to open in a spreadsheet."""
    return "'" + value if value.startswith(_FORMULA_LEADS) else value


def row_to_json(row: AuditRow) -> dict[str, Any]:
    """A row as a JSON-ready object: ISO timestamps (UTC), hex hashes."""
    address: IPv4Address | IPv6Address | None = row.source_ip
    return {
        "id": row.id,
        "recorded_at": timestamp_text(row.recorded_at),
        "occurred_at": timestamp_text(row.occurred_at),
        "action": row.action,
        "outcome": row.outcome,
        "actor": row.actor,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "source_ip": None if address is None else str(address),
        "details": dict(row.details),
        "key_id": row.key_id,
        "prev_hash": row.prev_hash.hex(),
        "row_hash": row.row_hash.hex(),
    }


def _csv_record(values: list[str]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\r\n").writerow([escape_cell(v) for v in values])
    return buffer.getvalue()


async def csv_lines(rows: AsyncIterable[AuditRow]) -> AsyncIterator[str]:
    """A header line, then one CSV record per row."""
    yield _csv_record(list(CSV_COLUMNS))
    async for row in rows:
        data = row_to_json(row)
        data["details"] = canonical_json(row.details).decode("utf-8")
        yield _csv_record(["" if data[c] is None else str(data[c]) for c in CSV_COLUMNS])


async def ndjson_lines(rows: AsyncIterable[AuditRow]) -> AsyncIterator[str]:
    """One JSON object per line."""
    async for row in rows:
        yield json.dumps(row_to_json(row), ensure_ascii=True, separators=(",", ":")) + "\n"


async def export(
    recorder: AuditRecorder,
    query: AuditQuery,
    fmt: ExportFormat,
    *,
    actor: str | None,
    source_ip: str | None = None,
) -> AsyncIterator[str]:
    """Record the export, then stream the matching rows in chain order.

    The export event is committed before the first line is produced, so an
    export is audited even if the reader stops early.
    """
    register_audit_actions(recorder.registry)
    await recorder.record(
        AuditEvent(
            action=EXPORT_ACTION,
            outcome="success",
            actor=actor,
            source_ip=None if source_ip is None else ip_address(source_ip),
            details={"format": fmt, "filter": query.model_dump(mode="json", exclude_defaults=True)},
        )
    )
    rows = iter_events(recorder.db, query)
    lines = csv_lines(rows) if fmt == "csv" else ndjson_lines(rows)
    return lines
