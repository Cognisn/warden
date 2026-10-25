"""The audit hash chain: canonical form, row hash and the details cap.

Each row stores ``prev_hash`` (the ``row_hash`` of the row before it, or
``GENESIS_HASH`` for the first row ever written) and its own ``row_hash``:

    row_hash = SHA-256(b"warden.audit.row.v1\\n" + canonical_json(fields))

where ``fields`` is an object holding every stored column: ``id``,
``prev_hash`` and ``key_id``, the timestamps ``recorded_at`` and
``occurred_at``, and ``action``, ``outcome``, ``actor``, ``resource_type``,
``resource_id``, ``source_ip`` and ``details``. Altering, deleting or
reordering any row therefore breaks a link. The full specification is in
``docs/design/audit-chain.md``; a verifier written in another language can be
built from it.

Canonical JSON is UTF-8, keys sorted by code point, no insignificant
whitespace, and one text per number: Postgres keeps jsonb numbers as
``numeric``, so ``1e20`` comes back as an integer and ``-0.0`` as ``0``, and
both must hash as they did when recorded. Non-finite numbers and NUL
characters are refused, because jsonb cannot store them.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import JsonValue

__all__ = [
    "CHAIN_LOCK_KEY",
    "GENESIS_HASH",
    "TRUNCATION_MARKER",
    "ChainRow",
    "address_text",
    "canonical_json",
    "cap_details",
    "row_hash",
    "timestamp_text",
]

# Transaction-scoped advisory lock serialising appends to the chain. It is
# taken before a row's id is drawn and held until the transaction ends, so
# rows commit in id order. ASCII "warden" + 0x0003. Belongs in
# ``warden.db.schema`` beside the other lock keys; see the session notes.
CHAIN_LOCK_KEY = 0x7761_7264_656E_0003

GENESIS_HASH = bytes(32)

# Replaces details that exceed ``audit.details_max_bytes``. Reserved: a
# product may not supply it.
TRUNCATION_MARKER = "warden.truncated"

_ROW_DOMAIN = b"warden.audit.row.v1\n"


@dataclass(frozen=True, slots=True)
class ChainRow:
    """Every stored column of one audit row, as the hash covers it."""

    id: int
    prev_hash: bytes
    recorded_at: datetime
    occurred_at: datetime
    actor: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: str
    source_ip: IPv4Address | IPv6Address | None
    details: Mapping[str, Any]
    key_id: str | None


def timestamp_text(value: datetime) -> str:
    """A timestamp as hashed and exported: UTC, microseconds, ``Z`` suffix."""
    if value.tzinfo is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _number(value: int | float) -> str:
    if isinstance(value, int):
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("audit details may hold only finite numbers")
    if value == 0:
        return "0"
    return format(Decimal(repr(value)).normalize(), "f")


def _string(value: str) -> str:
    if "\x00" in value:
        raise ValueError("audit values may not contain NUL characters")
    return json.dumps(value, ensure_ascii=False)


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int | float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list | tuple):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, Mapping):
        items = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise ValueError("audit details keys must be strings")
            items.append(_string(key) + ":" + _encode(value[key]))
        return "{" + ",".join(items) + "}"
    raise ValueError(f"audit details cannot hold a {type(value).__name__}")


def canonical_json(value: JsonValue | Mapping[str, Any]) -> bytes:
    """The canonical UTF-8 JSON text of ``value``."""
    try:
        return _encode(value).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("audit values must be valid Unicode") from None


def address_text(address: IPv4Address | IPv6Address) -> str:
    """The address as hashed: dotted quad, or eight four-digit lower-case hex groups.

    Built from the packed bytes rather than ``str`` or ``exploded``, whose
    output for IPv4-mapped IPv6 addresses changed in Python 3.13.
    """
    if isinstance(address, IPv4Address):
        return ".".join(str(octet) for octet in address.packed)
    packed = address.packed
    return ":".join(f"{packed[i] << 8 | packed[i + 1]:04x}" for i in range(0, 16, 2))


def _fields(row: ChainRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "prev_hash": row.prev_hash.hex(),
        "recorded_at": timestamp_text(row.recorded_at),
        "occurred_at": timestamp_text(row.occurred_at),
        "actor": row.actor,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "outcome": row.outcome,
        "source_ip": None if row.source_ip is None else address_text(row.source_ip),
        "details": row.details,
        "key_id": row.key_id,
    }


def row_hash(row: ChainRow) -> bytes:
    """The SHA-256 row hash of ``row``."""
    return hashlib.sha256(_ROW_DOMAIN + canonical_json(_fields(row))).digest()


def cap_details(details: Mapping[str, Any], *, max_bytes: int) -> dict[str, Any]:
    """``details``, or the truncation marker if its canonical form exceeds ``max_bytes``.

    Oversized details are replaced whole rather than cut, so a stored value
    is never a fragment that reads as something the product did not say.
    The marker records the original size only, never any of the content.
    """
    if TRUNCATION_MARKER in details:
        raise ValueError(f"the details key {TRUNCATION_MARKER!r} is reserved")
    size = len(canonical_json(details))
    if size <= max_bytes:
        return dict(details)
    return {TRUNCATION_MARKER: {"original_bytes": size}}
