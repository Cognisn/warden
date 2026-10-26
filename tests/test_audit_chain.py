"""The audit chain's canonical form, row hash and details cap (no database)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any

import pytest

from warden.audit.chain import (
    CHAIN_LOCK_KEY,
    GENESIS_HASH,
    TRUNCATION_MARKER,
    ChainRow,
    canonical_json,
    cap_details,
    row_hash,
)
from warden.db import MIGRATION_LOCK_KEY, SYSLOG_FORWARDER_LOCK_KEY

T0 = datetime(2026, 10, 25, 1, 2, 3, 456789, tzinfo=UTC)


def _row(**kw: Any) -> ChainRow:
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
    }
    values.update(kw)
    return ChainRow(**values)


def test_chain_lock_key_is_distinct_from_other_warden_locks() -> None:
    assert len({CHAIN_LOCK_KEY, MIGRATION_LOCK_KEY, SYSLOG_FORWARDER_LOCK_KEY}) == 3


def test_genesis_hash_is_32_zero_bytes() -> None:
    assert bytes(32) == GENESIS_HASH


def test_row_hash_is_sha256_sized_and_deterministic() -> None:
    assert len(row_hash(_row())) == 32
    assert row_hash(_row()) == row_hash(_row())


@pytest.mark.parametrize(
    "change",
    [
        {"id": 8},
        {"prev_hash": b"\x01" * 32},
        {"recorded_at": T0 + timedelta(microseconds=1)},
        {"occurred_at": T0 + timedelta(microseconds=1)},
        {"actor": "user-2"},
        {"actor": None},
        {"action": "product.import"},
        {"resource_type": "invoice"},
        {"resource_id": "r-2"},
        {"outcome": "failure"},
        {"source_ip": ip_address("192.0.2.8")},
        {"source_ip": None},
        {"details": {"rows": 4}},
        {"details": {}},
        {"key_id": "k1"},
    ],
)
def test_every_field_is_covered_by_the_hash(change: dict[str, Any]) -> None:
    assert row_hash(_row(**change)) != row_hash(_row())


def test_none_and_empty_string_hash_differently() -> None:
    assert row_hash(_row(actor=None)) != row_hash(_row(actor=""))


def test_timestamps_hash_by_instant_not_by_offset() -> None:
    aest = timezone(timedelta(hours=10))
    assert row_hash(_row(occurred_at=T0.astimezone(aest))) == row_hash(_row())


def test_ip_addresses_hash_in_one_form() -> None:
    a = _row(source_ip=ip_address("2001:db8::1"))
    b = _row(source_ip=ip_address("2001:0db8:0000:0000:0000:0000:0000:0001"))
    assert row_hash(a) == row_hash(b)


def test_canonical_json_sorts_keys_and_uses_no_whitespace() -> None:
    assert canonical_json({"b": [1, {"d": None, "c": True}], "a": "x"}) == (
        b'{"a":"x","b":[1,{"c":true,"d":null}]}'
    )


def test_canonical_json_keeps_non_ascii_as_utf8() -> None:
    assert canonical_json({"name": "Zoë"}) == '{"name":"Zoë"}'.encode()


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (1, "1"),
        (1.0, "1"),
        (-0.0, "0"),
        (0.0, "0"),
        (1.5, "1.5"),
        (0.1, "0.1"),
        (1e20, "100000000000000000000"),
        (10**20, "100000000000000000000"),
        (1.5e-7, "0.00000015"),
        (-2.5, "-2.5"),
    ],
)
def test_numbers_have_one_canonical_text(value: float, text: str) -> None:
    # Postgres stores jsonb numbers as numeric, so 1e20 comes back as an
    # integer and 1.0 as 1.0; both must hash as they were recorded.
    assert canonical_json([value]) == f"[{text}]".encode()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_are_refused(value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        canonical_json({"x": value})


@pytest.mark.parametrize("details", [{"x": "a\x00b"}, {"a\x00": 1}])
def test_nul_characters_are_refused(details: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="NUL"):
        canonical_json(details)


def test_booleans_are_not_numbers() -> None:
    assert canonical_json([True, 1]) == b"[true,1]"


def test_details_under_the_cap_are_unchanged() -> None:
    details = {"rows": 3, "note": "x" * 100}
    assert cap_details(details, max_bytes=8192) == details


def test_details_at_exactly_the_cap_are_unchanged() -> None:
    details = {"note": ""}
    size = len(canonical_json(details))
    details = {"note": "x" * (300 - size)}
    assert len(canonical_json(details)) == 300
    assert cap_details(details, max_bytes=300) == details


def test_oversized_details_are_replaced_by_the_declared_marker() -> None:
    details = {"note": "x" * 10_000}
    capped = cap_details(details, max_bytes=8192)
    assert capped == {TRUNCATION_MARKER: {"original_bytes": len(canonical_json(details))}}
    assert len(canonical_json(capped)) <= 8192


def test_the_marker_key_is_reserved() -> None:
    with pytest.raises(ValueError, match="reserved"):
        cap_details({TRUNCATION_MARKER: {"original_bytes": 1}}, max_bytes=8192)


def test_canonical_json_matches_a_json_round_trip() -> None:
    details = {"a": [1, 2.5, "three", None, False], "b": {"c": "Zoë"}}
    assert json.loads(canonical_json(details)) == details


@pytest.mark.parametrize(
    ("address", "text"),
    [
        ("192.0.2.7", "192.0.2.7"),
        ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"),
        # Python 3.13 changed how IPv4-mapped addresses print; the hash must not.
        ("::ffff:192.0.2.1", "0000:0000:0000:0000:0000:ffff:c000:0201"),
    ],
)
def test_source_ip_has_one_text_on_every_python_version(address: str, text: str) -> None:
    from warden.audit.chain import address_text

    assert address_text(ip_address(address)) == text
