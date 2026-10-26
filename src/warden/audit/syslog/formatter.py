"""RFC 5424 formatting of committed audit rows.

Every value that reaches a message has its control characters replaced
first, whatever the framing, because under LF framing one unescaped newline
in a username forges a second record (Termograph lesson 2). RFC 5424's own
parameter escaping covers only ``"``, ``\\`` and ``]`` and is applied after.

The whole message is held at or under ``max_message_bytes``. Oversized
values are cut, details first and identity fields last, on character and
escape boundaries, and the message is marked ``truncated="true"``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from warden.audit.events import AuditEvent, Severity
from warden.audit.registry import ActionRegistry
from warden.audit.syslog.settings import SyslogSettings

__all__ = ["AuditRecord", "format_message", "format_test_message", "neutralise"]

NILVALUE = "-"
BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"

# C0 controls, DEL, C1 controls (NEL among them), the Unicode line and
# paragraph separators, and lone surrogates: anything a collector might treat
# as a break, or that cannot be encoded.
_CONTROL = re.compile(
    "[\x00-\x1f\x7f-\x9f\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}"
    + chr(0xD800)
    + "-"
    + chr(0xDFFF)
    + "]"
)
_SD_ESCAPE = re.compile(r'(["\\\]])')


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One committed audit row, as the forwarder reads it."""

    id: int
    occurred_at: datetime
    action: str
    outcome: str
    actor: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    source_ip: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    key_id: str | None = None
    row_hash: bytes | None = None


def _replacement(match: re.Match[str]) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def neutralise(value: str) -> str:
    """Replace every control character in ``value`` with a visible ``\\xNN`` escape."""
    return _CONTROL.sub(_replacement, value)


def _sd_escape(value: str) -> str:
    return _SD_ESCAPE.sub(r"\\\1", value)


def _header_field(value: str, limit: int) -> str:
    """A header field: PRINTUSASCII only, at most ``limit`` characters, never empty."""
    cleaned = "".join(ch if "!" <= ch <= "~" else "_" for ch in value)[:limit]
    return cleaned or NILVALUE


def _clip(value: str, budget: int, encode: Callable[[str], str]) -> str:
    """The longest prefix of ``value`` whose encoded UTF-8 form fits in ``budget`` bytes.

    Cutting the raw value and encoding afterwards means a cut never splits a
    character or an escape sequence.
    """
    used = 0
    for index, ch in enumerate(value):
        size = len(encode(ch).encode("utf-8"))
        if used + size > budget:
            return value[:index]
        used += size
    return value


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _summary(record: AuditRecord, registry: ActionRegistry | None) -> tuple[Severity, str]:
    if registry is None or record.action not in registry:
        return Severity.NOTICE, record.action
    spec = registry.get(record.action)
    try:
        event = AuditEvent.model_validate(
            {
                "action": record.action,
                "outcome": record.outcome,
                "occurred_at": record.occurred_at,
                "actor": record.actor,
                "resource_type": record.resource_type,
                "resource_id": record.resource_id,
            }
        )
        return spec.severity, spec.render(event)
    except ValueError:
        return spec.severity, record.action


# Cut first to last: bulk before identity. Every field is listed, so no
# value, however long, can hold a message over the cap.
_TRUNCATABLE = (
    "details",
    "msg",
    "resourceId",
    "resourceType",
    "actor",
    "action",
    "outcome",
    "sourceIp",
    "keyId",
    "rowHash",
)


def format_message(
    record: AuditRecord, settings: SyslogSettings, registry: ActionRegistry | None = None
) -> bytes:
    """The RFC 5424 message for ``record``, at most ``settings.max_message_bytes`` long.

    MSGID is the audit row id, so a collector can discard a resent copy.
    Severity and summary come from the action's registration; an action this
    process does not know still forwards, at NOTICE with the action as MSG.
    """
    severity, summary = _summary(record, registry)
    pri = settings.facility * 8 + int(severity)
    header = " ".join(
        (
            f"<{pri}>1",
            _timestamp(record.occurred_at),
            _header_field(settings.hostname, 255),
            _header_field(settings.app_name, 48),
            NILVALUE,
            _header_field(str(record.id), 32),
        )
    )

    candidates: list[tuple[str, str | None]] = [
        ("action", record.action),
        ("outcome", record.outcome),
        ("actor", record.actor),
        ("resourceType", record.resource_type),
        ("resourceId", record.resource_id),
        ("sourceIp", record.source_ip),
        (
            "details",
            json.dumps(record.details, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
            if record.details
            else None,
        ),
        ("keyId", record.key_id),
        ("rowHash", record.row_hash.hex() if record.row_hash is not None else None),
    ]
    values: dict[str, str] = {name: neutralise(v) for name, v in candidates if v is not None}
    values["msg"] = neutralise(summary)

    def build(truncated: bool) -> bytes:
        params = "".join(
            f' {name}="{_sd_escape(value)}"' for name, value in values.items() if name != "msg"
        )
        if truncated:
            params += ' truncated="true"'
        return f"{header} [{settings.sd_id}{params}] {BOM}{values['msg']}".encode()

    cap = settings.max_message_bytes
    message = build(truncated=False)
    if len(message) <= cap:
        return message

    message = build(truncated=True)
    for name in _TRUNCATABLE:
        excess = len(message) - cap
        if excess <= 0:
            return message
        if name not in values:
            continue
        encode = (lambda s: s) if name == "msg" else _sd_escape
        current = len(encode(values[name]).encode("utf-8"))
        values[name] = _clip(values[name], max(0, current - excess), encode)
        message = build(truncated=True)
    if len(message) <= cap:
        return message
    # Unreachable while the header is bounded and the cap is at least 1024
    # bytes, but the cap holds regardless: drop the structured data entirely.
    return f"{header} {NILVALUE}".encode()[:cap]


def format_test_message(settings: SyslogSettings, moment: datetime | None = None) -> bytes:
    """A NOTICE message with MSGID ``test``, for checking the path to the collector."""
    pri = settings.facility * 8 + int(Severity.NOTICE)
    header = " ".join(
        (
            f"<{pri}>1",
            _timestamp(moment or datetime.now(UTC)),
            _header_field(settings.hostname, 255),
            _header_field(settings.app_name, 48),
            NILVALUE,
            "test",
        )
    )
    return f'{header} [{settings.sd_id} test="true"] {BOM}warden syslog test message'.encode()
