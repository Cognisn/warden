"""Reading stored audit rows back, in the form the chain hashes them."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Any

from psycopg import sql

from warden.audit.chain import GENESIS_HASH, ChainRow

__all__ = ["ROW_COLUMNS", "AuditRow", "row_from_record"]

# ``host()`` gives the bare address: an inet read directly would carry a prefix.
ROW_COLUMNS = sql.SQL(
    "id, prev_hash, recorded_at, occurred_at, actor, action, resource_type, resource_id,"
    " outcome, host(source_ip), details, key_id, row_hash"
)


@dataclass(frozen=True, slots=True)
class AuditRow(ChainRow):
    """A stored audit row: every hashed column plus the stored ``row_hash``."""

    row_hash: bytes

    @property
    def is_genesis(self) -> bool:
        return self.prev_hash == GENESIS_HASH


def row_from_record(record: tuple[Any, ...]) -> AuditRow:
    """An ``AuditRow`` from a result row selected with ``ROW_COLUMNS``."""
    details: Mapping[str, Any] = record[10]
    recorded_at: datetime = record[2]
    return AuditRow(
        id=int(record[0]),
        prev_hash=bytes(record[1]),
        recorded_at=recorded_at,
        occurred_at=record[3],
        actor=record[4],
        action=record[5],
        resource_type=record[6],
        resource_id=record[7],
        outcome=record[8],
        source_ip=None if record[9] is None else ip_address(record[9]),
        details=details,
        key_id=record[11],
        row_hash=bytes(record[12]),
    )
