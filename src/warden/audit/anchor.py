"""Signed head attestations ("anchors") that leave the database.

A hash chain shows an altered or deleted row, and a retention checkpoint
vouches for a purged prefix, but neither stops someone who can write to the
audit table from deleting its tail, or from rewriting the whole chain from
genesis. An anchor closes that gap. ``anchor()`` appends an ordinary chained
row, action ``ANCHOR_ACTION``, whose details carry the chain head it saw
(``head_id`` and ``head_hash``) and the time, signed with warden's Ed25519
key:

    message = b"warden.audit.anchor.v1\\n" + canonical_json(payload)

where ``payload`` is the anchor object without its ``signature``. The row is
forwarded to syslog like any other, so the SIEM ends up holding a signed,
timestamped head that a database administrator cannot recall.
``warden.audit.verify.verify_anchors`` later checks anchors read back from the
SIEM (``read_anchors``) against the stored chain.

The package exports the function as ``warden.audit.anchor``, which shadows
this module's name as a package attribute: import from the module with
``from warden.audit.anchor import ...``.

warden ships no scheduler: a product runs ``warden audit anchor`` (or calls
``anchor()``) on its own schedule.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Protocol

from psycopg import sql

from warden.audit.actions import ANCHOR_ACTION, register_audit_actions
from warden.audit.chain import canonical_json, timestamp_text
from warden.audit.events import AuditEvent
from warden.audit.recorder import AuditRecorder
from warden.db import AUDIT_EVENTS, table

__all__ = [
    "ANCHOR_ACTION",
    "ANCHOR_KEY",
    "MAX_ANCHOR_ACTOR",
    "Anchor",
    "AnchorError",
    "AnchorRecord",
    "AnchorSigner",
    "ExternalAnchor",
    "MalformedAnchor",
    "anchor",
    "read_anchors",
]

ANCHOR_KEY = "anchor"
_VERSION = 1
_DOMAIN = b"warden.audit.anchor.v1\n"
_SIGNATURE_BYTES = 64

# The longest actor an anchor may name. Syslog messages are cut details first,
# so this keeps a forwarded anchor whole within the smallest message cap warden
# accepts (1024 bytes), whatever the host and application names.
MAX_ANCHOR_ACTOR = 64

_AUDIT = table(AUDIT_EVENTS)
_HEAD = sql.SQL("SELECT id, row_hash, clock_timestamp() FROM {} ORDER BY id DESC LIMIT 1").format(
    _AUDIT
)
_SINCE_LAST = sql.SQL(
    "SELECT count(*) FROM {audit} WHERE id > coalesce("
    "(SELECT id FROM {audit} WHERE action = %s ORDER BY id DESC LIMIT 1), 0)"
).format(audit=_AUDIT)

_B64URL = re.compile(r"[A-Za-z0-9_-]+")


class MalformedAnchor(ValueError):
    """Details do not hold a well-formed anchor."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    if _B64URL.fullmatch(text) is None:
        raise MalformedAnchor("the anchor signature is not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True, slots=True)
class Anchor:
    """The chain head at ``anchored_at``, signed by ``key_id``."""

    head_id: int
    head_hash: bytes
    anchored_at: datetime
    key_id: str
    signature: bytes = b""

    def payload(self) -> dict[str, Any]:
        return {
            "version": _VERSION,
            "head_id": self.head_id,
            "head_hash": self.head_hash.hex(),
            "anchored_at": timestamp_text(self.anchored_at),
            "key_id": self.key_id,
        }

    def message(self) -> bytes:
        """The bytes the signature covers."""
        return _DOMAIN + canonical_json(self.payload())

    def to_details(self) -> dict[str, Any]:
        return {ANCHOR_KEY: {**self.payload(), "signature": _b64url(self.signature)}}

    @classmethod
    def from_details(cls, details: Mapping[str, Any]) -> Anchor:
        """Parse an anchor row's details; ``MalformedAnchor`` if they do not fit exactly."""
        body = details.get(ANCHOR_KEY)
        try:
            if not isinstance(body, Mapping) or body.get("version") != _VERSION:
                raise MalformedAnchor("unknown anchor version")
            parsed = cls(
                head_id=_int(body["head_id"]),
                head_hash=bytes.fromhex(_str(body["head_hash"])),
                anchored_at=datetime.fromisoformat(_str(body["anchored_at"])),
                key_id=_str(body["key_id"]),
                signature=_b64url_decode(_str(body["signature"])),
            )
            # Only the exact form warden writes is accepted, so one anchor has
            # one signed message.
            canonical = parsed.payload() == {k: v for k, v in body.items() if k != "signature"}
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            if isinstance(exc, MalformedAnchor):
                raise
            raise MalformedAnchor("anchor details are malformed") from None
        if (
            not canonical
            or parsed.head_id < 1
            or len(parsed.head_hash) != 32
            or not parsed.key_id
            or len(parsed.signature) != _SIGNATURE_BYTES
        ):
            raise MalformedAnchor("anchor details are malformed")
        return parsed


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedAnchor("expected an integer")
    return value


def _str(value: Any) -> str:
    if not isinstance(value, str):
        raise MalformedAnchor("expected a string")
    return value


class _SignatureLike(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def signature(self) -> bytes: ...


class _KeyLike(Protocol):
    @property
    def key_id(self) -> str: ...


class AnchorSigner(Protocol):
    """What anchoring needs from the key store: ``KeyStore`` fits."""

    async def active_key(self) -> _KeyLike: ...

    async def sign(self, message: bytes) -> _SignatureLike: ...


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    """An anchor written to the trail, and the id of the row that carries it."""

    row_id: int
    anchor: Anchor


class AnchorError(Exception):
    """An anchor could not be written. The message carries identifiers only."""


async def anchor(
    recorder: AuditRecorder,
    keys: AnchorSigner,
    *,
    actor: str | None = None,
    min_rows: int | None = None,
) -> AnchorRecord | None:
    """Append a signed attestation of the committed chain head.

    Returns None, writing nothing, when the trail is empty or, with
    ``min_rows``, when fewer than ``min_rows`` rows have been appended since
    the last anchor. A scheduler that runs often with ``min_rows`` therefore
    anchors about every ``min_rows`` rows, and never anchors an idle trail
    twice.

    The head is read, signed, and then appended as an ordinary row, without
    holding the chain lock in between: signing borrows connections of its
    own, and holding the lock while waiting for one could starve a pool whose
    other connections are all queued on that lock. Rows recorded meanwhile
    may therefore sit between the head and the anchor row; the anchor
    attests the head as it was committed at ``anchored_at``.
    """
    if min_rows is not None and min_rows < 1:
        raise ValueError("min_rows must be at least 1")
    if actor is not None and len(actor) > MAX_ANCHOR_ACTOR:
        raise ValueError(f"an anchor's actor may be at most {MAX_ANCHOR_ACTOR} characters")
    register_audit_actions(recorder.registry)
    async with recorder.db.connection() as conn:
        cur = await conn.execute(_HEAD)
        head = await cur.fetchone()
        since = None
        if head is not None and min_rows is not None:
            cur = await conn.execute(_SINCE_LAST, (ANCHOR_ACTION,))
            since = await cur.fetchone()
    if head is None:
        return None
    if min_rows is not None and (since is None or int(since[0]) < min_rows):
        return None
    key = await keys.active_key()
    unsigned = Anchor(
        head_id=int(head[0]),
        head_hash=bytes(head[1]),
        anchored_at=head[2],
        key_id=key.key_id,
    )
    signed = await keys.sign(unsigned.message())
    if signed.key_id != key.key_id:
        raise AnchorError("refusing to anchor: the signing key changed while signing")
    attested = replace(unsigned, signature=signed.signature)
    row_id = await recorder.record(
        AuditEvent(
            action=ANCHOR_ACTION,
            outcome="success",
            actor=actor,
            details=attested.to_details(),
        )
    )
    return AnchorRecord(row_id=row_id, anchor=attested)


# Reading anchors back from a SIEM.


@dataclass(frozen=True, slots=True)
class ExternalAnchor:
    """An anchor found in an export: its line, its own row id when known, and the anchor.

    ``anchor`` is None when the line is an anchor row whose details do not
    hold a well-formed anchor.
    """

    line: int
    row_id: int | None
    anchor: Anchor | None


_SYSLOG_START = re.compile(r"<[0-9]{1,3}>1 ")
_DIGITS = re.compile(r"[0-9]{1,18}")


def read_anchors(lines: Iterable[str]) -> list[ExternalAnchor]:
    """The anchors in an export from a SIEM, one record per line, numbered from 1.

    Two forms are read: NDJSON rows as ``warden.audit.export`` writes them,
    and RFC 5424 messages as the syslog forwarder sends them (under any
    SD-ID, with or without an octet count or a collector's prefix before the
    message). Lines holding any other row, or anything else, are skipped. A
    line holding an anchor row whose anchor cannot be read is returned with
    ``anchor`` None, so verification can report it.
    """
    found: list[ExternalAnchor] = []
    for number, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text:
            continue
        parsed = _from_ndjson(text) if text.startswith("{") else _from_syslog(text)
        if parsed is None:
            continue
        row_id, details = parsed
        try:
            value = None if details is None else Anchor.from_details(details)
        except MalformedAnchor:
            value = None
        found.append(ExternalAnchor(line=number, row_id=row_id, anchor=value))
    return found


def _row_id(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _from_ndjson(text: str) -> tuple[int | None, Mapping[str, Any] | None] | None:
    try:
        row = json.loads(text)
    except ValueError:
        return None
    if not isinstance(row, dict) or row.get("action") != ANCHOR_ACTION:
        return None
    details = row.get("details")
    return _row_id(row.get("id")), details if isinstance(details, dict) else None


def _from_syslog(text: str) -> tuple[int | None, Mapping[str, Any] | None] | None:
    start = _SYSLOG_START.search(text)
    if start is None:
        return None
    # PRI and VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, then the rest.
    fields = text[start.start() :].split(" ", 6)
    if len(fields) < 7:
        return None
    msgid, rest = fields[5], fields[6]
    for params in _structured_data(rest):
        if params.get("action") != ANCHOR_ACTION:
            continue
        row_id = int(msgid) if _DIGITS.fullmatch(msgid) else None
        try:
            details = json.loads(params["details"])
        except (KeyError, ValueError):
            return row_id, None
        return row_id, details if isinstance(details, dict) else None
    return None


def _structured_data(text: str) -> list[dict[str, str]]:
    """The parameters of each SD-ELEMENT at the start of ``text`` (RFC 5424 section 6.3).

    An element cut short (a truncated message) is returned with the
    parameters read before the cut, and parsing stops there.
    """
    elements: list[dict[str, str]] = []
    pos, end = 0, len(text)
    while pos < end and text[pos] == "[":
        params: dict[str, str] = {}
        elements.append(params)
        close = _scan_name(text, pos + 1)
        pos = close
        while pos < end and text[pos] == " ":
            eq = text.find('="', pos + 1)
            if eq < 0:
                return elements
            name = text[pos + 1 : eq]
            value, pos = _scan_value(text, eq + 2)
            if value is None:
                return elements
            params[name] = value
        if pos >= end or text[pos] != "]":
            return elements
        pos += 1
    return elements


def _scan_name(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] not in " ]":
        pos += 1
    return pos


def _scan_value(text: str, pos: int) -> tuple[str | None, int]:
    """A PARAM-VALUE from ``pos`` up to its closing quote, unescaped."""
    out: list[str] = []
    while pos < len(text):
        ch = text[pos]
        if ch == "\\" and pos + 1 < len(text) and text[pos + 1] in '"\\]':
            out.append(text[pos + 1])
            pos += 2
        elif ch == '"':
            return "".join(out), pos + 1
        else:
            out.append(ch)
            pos += 1
    return None, pos
