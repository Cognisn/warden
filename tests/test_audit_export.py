"""Export formatting: CSV formula-injection escaping and NDJSON (no database)."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

import pytest

from warden.audit.chain import GENESIS_HASH
from warden.audit.export import CSV_COLUMNS, csv_lines, escape_cell, ndjson_lines
from warden.audit.store import AuditRow

T0 = datetime(2026, 10, 25, 1, 2, 3, 456789, tzinfo=UTC)


def _row(**kw: Any) -> AuditRow:
    values: dict[str, Any] = {
        "id": 7,
        "prev_hash": GENESIS_HASH,
        "recorded_at": T0,
        "occurred_at": T0,
        "actor": "user-1",
        "action": "product.export",
        "resource_type": "report",
        "resource_id": "r-1",
        "outcome": "success",
        "source_ip": ip_address("192.0.2.7"),
        "details": {"rows": 3},
        "key_id": None,
        "row_hash": b"\x01" * 32,
    }
    values.update(kw)
    return AuditRow(**values)


async def _rows(*rows: AuditRow) -> AsyncIterator[AuditRow]:
    for row in rows:
        yield row


async def _collect(lines: AsyncIterator[str]) -> str:
    return "".join([line async for line in lines])


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r"])
def test_formula_leading_cells_are_escaped(lead: str) -> None:
    assert escape_cell(lead + "SUM(A1)") == "'" + lead + "SUM(A1)"


@pytest.mark.parametrize("value", ["", "plain", "a=b", " =x", "1-2", "'quoted"])
def test_other_cells_are_unchanged(value: str) -> None:
    assert escape_cell(value) == value


async def test_csv_has_a_header_and_one_line_per_row() -> None:
    text = await _collect(csv_lines(_rows(_row(), _row(id=8, actor=None))))
    parsed = list(csv.reader(io.StringIO(text)))
    assert parsed[0] == list(CSV_COLUMNS)
    assert len(parsed) == 3
    first = dict(zip(CSV_COLUMNS, parsed[1], strict=True))
    assert first["id"] == "7"
    assert first["recorded_at"] == "2026-10-25T01:02:03.456789Z"
    assert first["source_ip"] == "192.0.2.7"
    assert json.loads(first["details"]) == {"rows": 3}
    assert first["row_hash"] == "01" * 32
    assert dict(zip(CSV_COLUMNS, parsed[2], strict=True))["actor"] == ""


async def test_every_csv_cell_is_escaped() -> None:
    hostile = _row(
        actor='=HYPERLINK("http://example.com")',
        resource_type="+1",
        resource_id="-2",
        action="@SUM",
        details={"x": "=1"},
    )
    text = await _collect(csv_lines(_rows(hostile)))
    cells = dict(zip(CSV_COLUMNS, list(csv.reader(io.StringIO(text)))[1], strict=True))
    for column in ("actor", "resource_type", "resource_id", "action"):
        assert cells[column].startswith("'"), column
    # A details object starts with "{", so it needs no escape and stays valid JSON.
    assert json.loads(cells["details"]) == {"x": "=1"}


async def test_embedded_newlines_stay_inside_one_csv_record() -> None:
    text = await _collect(csv_lines(_rows(_row(actor="a\nb"))))
    parsed = list(csv.reader(io.StringIO(text)))
    assert len(parsed) == 2
    assert dict(zip(CSV_COLUMNS, parsed[1], strict=True))["actor"] == "a\nb"


async def test_ndjson_is_one_object_per_line() -> None:
    text = await _collect(ndjson_lines(_rows(_row(), _row(id=8, source_ip=None))))
    lines = text.splitlines()
    assert len(lines) == 2
    first, second = (json.loads(line) for line in lines)
    assert first["id"] == 7
    assert first["details"] == {"rows": 3}
    assert first["prev_hash"] == "00" * 32
    assert second["source_ip"] is None
    assert set(first) == set(CSV_COLUMNS)


async def test_ndjson_escapes_line_separators() -> None:
    text = await _collect(ndjson_lines(_rows(_row(actor="a\u2028b\nc"))))
    assert len(text.splitlines()) == 1
    assert json.loads(text)["actor"] == "a\u2028b\nc"
