"""The RFC 5424 formatter: neutralised values, escaping and a byte cap that caps."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from warden.audit import ActionRegistry, Severity
from warden.audit.syslog import AuditRecord, SyslogSettings, format_message, neutralise

BOM = b"\xef\xbb\xbf"
SD_ID = "warden@99999"


@pytest.fixture
def registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register(
        "product.export", severity=Severity.WARNING, summary="{actor} exported {resource_id}"
    )
    return registry


def _settings(**kw: Any) -> SyslogSettings:
    values: dict[str, Any] = {
        "host": "collector.example.com",
        "port": 6514,
        "sd_id": SD_ID,
        "hostname": "app-1.example.com",
    }
    values.update(kw)
    return SyslogSettings(**values)


def _record(**kw: Any) -> AuditRecord:
    values: dict[str, Any] = {
        "id": 42,
        "occurred_at": datetime(2026, 10, 25, 1, 2, 3, 456789, tzinfo=UTC),
        "action": "product.export",
        "outcome": "success",
        "actor": "user-1",
        "resource_type": "report",
        "resource_id": "r-7",
        "source_ip": "192.0.2.7",
        "details": {"rows": 3},
    }
    values.update(kw)
    return AuditRecord(**values)


def _parse(message: bytes) -> dict[str, Any]:
    """Split a formatted message into header fields, SD params and MSG."""
    text = message.decode("utf-8")
    header = re.fullmatch(r"<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) (.*)", text, flags=re.DOTALL)
    assert header is not None, text
    pri, ts, host, app, procid, msgid, rest = header.groups()
    params: dict[str, str] = {}
    msg = rest
    if rest.startswith("["):
        sd = re.match(r"\[(\S+)((?: [^=\s\]\"]+=\"(?:[^\"\\\]]|\\[\"\\\]])*\")*)\]", rest)
        assert sd is not None, rest
        assert sd.group(1) == SD_ID
        for name, value in re.findall(
            r" ([^=\s\]\"]+)=\"((?:[^\"\\\]]|\\[\"\\\]])*)\"", sd.group(2)
        ):
            params[name] = re.sub(r"\\([\"\\\]])", r"\1", value)
        msg = rest[sd.end() :]
    else:
        assert rest.startswith("- ") or rest == "-", rest
        msg = rest[2:]
    msg = msg.removeprefix(" ")
    return {
        "pri": int(pri),
        "timestamp": ts,
        "hostname": host,
        "app_name": app,
        "procid": procid,
        "msgid": msgid,
        "params": params,
        "msg": msg,
    }


def test_header_fields(registry: ActionRegistry) -> None:
    parsed = _parse(format_message(_record(), _settings(), registry))
    assert parsed["pri"] == 13 * 8 + Severity.WARNING
    assert parsed["timestamp"] == "2026-10-25T01:02:03.456789Z"
    assert parsed["hostname"] == "app-1.example.com"
    assert parsed["app_name"] == "warden"
    assert parsed["procid"] == "-"
    assert parsed["msgid"] == "42"


def test_timestamp_is_converted_to_utc(registry: ActionRegistry) -> None:
    aest = timezone(timedelta(hours=10))
    record = _record(occurred_at=datetime(2026, 10, 25, 11, 0, 0, tzinfo=aest))
    assert _parse(format_message(record, _settings(), registry))["timestamp"] == (
        "2026-10-25T01:00:00.000000Z"
    )


def test_facility_is_configurable(registry: ActionRegistry) -> None:
    parsed = _parse(format_message(_record(), _settings(facility=10), registry))
    assert parsed["pri"] == 10 * 8 + Severity.WARNING


def test_structured_data_carries_the_event(registry: ActionRegistry) -> None:
    record = _record(row_hash=bytes.fromhex("ab01"), key_id="k-1")
    params = _parse(format_message(record, _settings(), registry))["params"]
    assert params == {
        "action": "product.export",
        "outcome": "success",
        "actor": "user-1",
        "resourceType": "report",
        "resourceId": "r-7",
        "sourceIp": "192.0.2.7",
        "details": '{"rows":3}',
        "keyId": "k-1",
        "rowHash": "ab01",
    }


def test_absent_fields_are_omitted(registry: ActionRegistry) -> None:
    record = _record(actor=None, resource_type=None, resource_id=None, source_ip=None, details={})
    params = _parse(format_message(record, _settings(), registry))["params"]
    assert params == {"action": "product.export", "outcome": "success"}


def test_msg_is_the_summary_after_a_bom(registry: ActionRegistry) -> None:
    message = format_message(_record(), _settings(), registry)
    assert message.endswith(b"] " + BOM + b"user-1 exported r-7")


def test_an_unregistered_action_still_forwards(registry: ActionRegistry) -> None:
    record = _record(action="other.thing")
    parsed = _parse(format_message(record, _settings(), registry))
    assert parsed["pri"] == 13 * 8 + Severity.NOTICE
    assert parsed["msg"].removeprefix("\ufeff") == "other.thing"


def test_sd_param_values_are_escaped(registry: ActionRegistry) -> None:
    actor = 'a"b\\c]d'
    message = format_message(_record(actor=actor), _settings(), registry)
    assert b'actor="a\\"b\\\\c\\]d"' in message
    assert _parse(message)["params"]["actor"] == actor


# --- neutralisation --------------------------------------------------------

CONTROLS = "".join(chr(c) for c in [*range(0x20), 0x7F])


def test_neutralise_replaces_every_c0_control_and_del() -> None:
    out = neutralise("a" + CONTROLS + "b")
    assert out.startswith("a") and out.endswith("b")
    assert not any(ch in out for ch in CONTROLS)
    assert "\\x0a" in out and "\\x0d" in out and "\\x00" in out and "\\x7f" in out


def test_neutralise_replaces_c1_controls_and_unicode_line_separators() -> None:
    out = neutralise("a\u0085b\u2028c\u2029d\x9be")
    assert out == "a\\x85b\\u2028c\\u2029d\\x9be"


def test_neutralise_leaves_ordinary_text_alone() -> None:
    text = 'Ünïcödé user@example.com [x] "q" \\ tab-free'
    assert neutralise(text) == text


INJECTION = "alice\n<13>1 2026-10-25T00:00:00Z forged - - - - pwned\r\x00\x1b[31m"


@pytest.mark.parametrize(
    "field",
    ["actor", "resource_type", "resource_id", "action_summary", "details", "outcome"],
)
def test_no_control_character_reaches_the_message(registry: ActionRegistry, field: str) -> None:
    if field == "action_summary":
        record = _record(actor=INJECTION, resource_id=INJECTION)
    elif field == "details":
        record = _record(details={"note": INJECTION, INJECTION: [INJECTION]})
    else:
        record = _record(**{field: INJECTION})
    message = format_message(record, _settings(), registry)
    assert not any(b < 0x20 or b == 0x7F for b in message), message


def test_header_values_from_settings_are_printable_ascii(registry: ActionRegistry) -> None:
    settings = _settings(hostname="app-1.example.com")
    message = format_message(_record(), settings, registry)
    header = message.split(b" [", 1)[0]
    assert all(0x21 <= b <= 0x7E or b == 0x20 for b in header)


# --- the byte cap ------------------------------------------------------------


def _oversized() -> AuditRecord:
    big = "x" * 20_000
    return _record(
        actor="é" * 5_000,
        resource_type="t" * 3_000,
        resource_id='"]\\' * 3_000,
        details={"blob": big, "more": ["ü" * 4_000]},
    )


@pytest.mark.parametrize("cap", [1024, 2048, 8192])
def test_an_oversized_event_is_emitted_at_or_under_the_cap(
    registry: ActionRegistry, cap: int
) -> None:
    message = format_message(_oversized(), _settings(max_message_bytes=cap), registry)
    assert len(message) <= cap
    # Still a well-formed message: valid UTF-8, the event's id and action survive.
    parsed = _parse(message)
    assert parsed["msgid"] == "42"
    assert parsed["params"]["action"] == "product.export"
    assert parsed["params"]["truncated"] == "true"


def test_every_field_is_capped(registry: ActionRegistry) -> None:
    record = _record(
        action="a" * 3000,
        outcome="o" * 3000,
        source_ip="i" * 3000,
        key_id="k" * 3000,
        row_hash=b"" * 3000,
    )
    message = format_message(record, _settings(max_message_bytes=1024), registry)
    assert len(message) <= 1024
    assert _parse(message)["params"]["truncated"] == "true"


def test_a_message_under_the_cap_is_not_marked_truncated(registry: ActionRegistry) -> None:
    params = _parse(format_message(_record(), _settings(), registry))["params"]
    assert "truncated" not in params


def test_details_are_cut_before_identity_fields(registry: ActionRegistry) -> None:
    record = _record(details={"blob": "x" * 50_000})
    message = format_message(record, _settings(max_message_bytes=2048), registry)
    params = _parse(message)["params"]
    assert len(message) <= 2048
    assert params["actor"] == "user-1"
    assert params["resourceId"] == "r-7"
    assert params["details"].startswith('{"blob":"xxx')


def test_only_the_oversized_field_is_cut(registry: ActionRegistry) -> None:
    # Quotes expand under JSON and then SD escaping, so the cut must be
    # measured on the escaped bytes or it overshoots into other fields.
    record = _record(details={"q": '"]\\' * 3000})
    message = format_message(record, _settings(max_message_bytes=2048), registry)
    parsed = _parse(message)
    assert len(message) <= 2048
    assert len(message) >= 2048 - 8  # the budget is used, not squandered
    assert parsed["msg"].removeprefix("﻿") == "user-1 exported r-7"
    assert parsed["params"]["actor"] == "user-1"
    assert parsed["params"]["sourceIp"] == "192.0.2.7"


def test_the_cap_never_splits_an_escape_or_a_character(registry: ActionRegistry) -> None:
    for size in range(1500, 1540):
        record = _record(actor='é"' * 2000, details={})
        message = format_message(record, _settings(max_message_bytes=1024 + size % 7), registry)
        assert len(message) <= 1024 + size % 7
        _parse(message)  # decodes as UTF-8 and the SD element still parses


def test_details_json_is_compact_and_sorted(registry: ActionRegistry) -> None:
    record = _record(details={"b": 1, "a": {"y": 2, "x": [1, "z"]}})
    params = _parse(format_message(record, _settings(), registry))["params"]
    assert params["details"] == json.dumps(
        {"a": {"x": [1, "z"], "y": 2}, "b": 1}, separators=(",", ":"), sort_keys=True
    )
