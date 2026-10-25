"""Chain verification: any altered, deleted or reordered row is found, by id."""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.verify import verify_chain
from warden.db import Database

pytestmark = pytest.mark.db


class NoKeys:
    """A historical verifier that must never be consulted (no checkpoints exist)."""

    async def verify_historical(self, message: bytes, signature: bytes, key_id: str) -> bool:
        raise AssertionError("no checkpoint should be verified")


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    return registry


@pytest.fixture
async def ids(pool: Any, registry: ActionRegistry) -> list[int]:
    recorder = AuditRecorder(Database(pool), registry)
    return [
        await recorder.record(
            AuditEvent(
                action="product.export",
                outcome="success",
                actor=f"user-{n}",
                resource_type="report",
                resource_id=f"r-{n}",
                source_ip="198.51.100.4",
                details={"n": n},
            )
        )
        for n in range(5)
    ]


def _sql(dsn: str, statement: str, params: tuple[Any, ...] = ()) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute(statement, params)


async def test_an_empty_trail_verifies(pool: Any) -> None:
    report = await verify_chain(Database(pool), NoKeys())
    assert report.ok
    assert report.rows == 0
    assert report.broken is None


async def test_an_intact_chain_verifies(pool: Any, ids: list[int]) -> None:
    report = await verify_chain(Database(pool), NoKeys())
    assert report.ok
    assert report.rows == 5
    assert (report.first_id, report.last_id) == (ids[0], ids[-1])
    assert report.head_hash is not None and len(report.head_hash) == 32


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("actor", "'intruder'"),
        ("actor", "NULL"),
        ("action", "'product.import'"),
        ("resource_type", "'invoice'"),
        ("resource_id", "'r-99'"),
        ("outcome", "'failure'"),
        ("source_ip", "'203.0.113.9'"),
        ("details", "'{\"n\": 99}'"),
        ("occurred_at", "occurred_at - interval '1 day'"),
        ("recorded_at", "recorded_at + interval '1 microsecond'"),
        ("key_id", "'k-forged'"),
        ("row_hash", "sha256('forged')"),
        ("prev_hash", "sha256('forged')"),
    ],
)
async def test_altering_any_column_names_that_row(
    pool: Any, migrated_dsn: str, ids: list[int], column: str, value: str
) -> None:
    _sql(
        migrated_dsn,
        f"UPDATE warden.audit_events SET {column} = {value} WHERE id = %s",  # noqa: S608
        (ids[2],),
    )
    report = await verify_chain(Database(pool), NoKeys())
    assert not report.ok
    assert report.broken is not None
    assert report.broken.row_id == ids[2]


async def test_rewriting_a_row_with_a_fresh_hash_breaks_the_next_link(
    pool: Any, migrated_dsn: str, ids: list[int]
) -> None:
    """A forger who recomputes the altered row's hash is caught at the next row."""
    from warden.audit.chain import row_hash
    from warden.audit.store import ROW_COLUMNS, row_from_record

    with psycopg.connect(migrated_dsn) as conn:
        conn.execute("UPDATE warden.audit_events SET actor = 'intruder' WHERE id = %s", (ids[2],))
        query = psycopg.sql.SQL("SELECT {} FROM warden.audit_events WHERE id = %s").format(
            ROW_COLUMNS
        )
        record = conn.execute(query, (ids[2],)).fetchone()
        assert record is not None
        forged = row_hash(row_from_record(record))
        conn.execute("UPDATE warden.audit_events SET row_hash = %s WHERE id = %s", (forged, ids[2]))
    report = await verify_chain(Database(pool), NoKeys())
    assert report.broken is not None
    assert (report.broken.row_id, report.broken.reason) == (ids[3], "prev_hash")


async def test_deleting_a_row_names_the_row_after_it(
    pool: Any, migrated_dsn: str, ids: list[int]
) -> None:
    _sql(migrated_dsn, "DELETE FROM warden.audit_events WHERE id = %s", (ids[2],))
    report = await verify_chain(Database(pool), NoKeys())
    assert report.broken is not None
    assert (report.broken.row_id, report.broken.reason) == (ids[3], "prev_hash")


async def test_deleting_the_first_row_leaves_the_chain_unanchored(
    pool: Any, migrated_dsn: str, ids: list[int]
) -> None:
    _sql(migrated_dsn, "DELETE FROM warden.audit_events WHERE id = %s", (ids[0],))
    report = await verify_chain(Database(pool), NoKeys())
    assert report.broken is not None
    assert (report.broken.row_id, report.broken.reason) == (ids[1], "unanchored")


async def test_reordering_rows_is_detected(pool: Any, migrated_dsn: str, ids: list[int]) -> None:
    """Swap every stored column of two rows except their ids."""
    columns = (
        "recorded_at, occurred_at, actor, action, resource_type, resource_id, outcome,"
        " source_ip, details, key_id, prev_hash, row_hash"
    )
    a, b = ids[1], ids[2]
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute("DROP INDEX warden.audit_events_prev_hash_unique")
        conn.execute(
            f"UPDATE warden.audit_events t SET ({columns}) = (SELECT {columns}"  # noqa: S608
            " FROM warden.audit_events s WHERE s.id = CASE t.id WHEN %s THEN %s ELSE %s END)"
            " WHERE t.id IN (%s, %s)",
            (a, b, a, a, b),
        )
    report = await verify_chain(Database(pool), NoKeys())
    assert report.broken is not None
    assert report.broken.row_id == a


async def test_deleting_the_tail_is_not_detected_by_the_chain_alone(
    pool: Any, migrated_dsn: str, ids: list[int]
) -> None:
    """A documented limit (docs/design/audit-chain.md, section 5): anchoring closes it."""
    _sql(migrated_dsn, "DELETE FROM warden.audit_events WHERE id = %s", (ids[-1],))
    report = await verify_chain(Database(pool), NoKeys())
    assert report.ok
    assert report.last_id == ids[-2]


async def test_verification_can_stop_at_a_given_row(
    pool: Any, migrated_dsn: str, ids: list[int]
) -> None:
    _sql(migrated_dsn, "UPDATE warden.audit_events SET actor = 'x' WHERE id = %s", (ids[4],))
    report = await verify_chain(Database(pool), NoKeys(), through_id=ids[3])
    assert report.ok
    assert (report.rows, report.last_id) == (4, ids[3])
