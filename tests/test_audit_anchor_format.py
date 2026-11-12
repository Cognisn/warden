"""Anchors: the signed payload, its domain separation, and reading anchors back from a SIEM.

A SIEM holds anchors in one of two forms: NDJSON rows as ``warden.audit.export``
writes them, or the RFC 5424 messages the syslog forwarder sends. Both are
built here with warden's own writers, so the parser reads what warden emits.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden.audit.actions import ANCHOR_ACTION, register_audit_actions
from warden.audit.anchor import ANCHOR_KEY, Anchor, MalformedAnchor, read_anchors
from warden.audit.chain import canonical_json
from warden.audit.checkpoint import Checkpoint
from warden.audit.registry import ActionRegistry
from warden.audit.syslog import AuditRecord, SyslogSettings, format_message

AT = datetime(2026, 10, 28, 3, 4, 5, 678901, tzinfo=UTC)
HEAD_HASH = bytes(range(32))


def _anchor(**kw: Any) -> Anchor:
    values: dict[str, Any] = {
        "head_id": 41,
        "head_hash": HEAD_HASH,
        "anchored_at": AT,
        "key_id": "k-example",
        "signature": b"\x01" * 64,
    }
    values.update(kw)
    return Anchor(**values)


def test_the_anchor_action_is_wardens_own() -> None:
    assert ANCHOR_ACTION == "warden.audit.anchor"
    registry = ActionRegistry()
    register_audit_actions(registry)
    assert ANCHOR_ACTION in registry


def test_the_signed_message_is_domain_separated() -> None:
    """The exact bytes the signature covers, written out independently of the code."""
    anchor = _anchor()
    payload = {
        "version": 1,
        "head_id": 41,
        "head_hash": HEAD_HASH.hex(),
        "anchored_at": "2026-10-28T03:04:05.678901Z",
        "key_id": "k-example",
    }
    assert anchor.payload() == payload
    assert anchor.message() == b"warden.audit.anchor.v1\n" + canonical_json(payload)


def test_an_anchor_signature_cannot_pass_as_a_checkpoint_signature() -> None:
    """The two signed artefacts never share a message, whatever their fields."""
    checkpoint = Checkpoint(
        first_purged_id=1,
        through_id=41,
        through_hash=HEAD_HASH,
        purged_rows=41,
        cutoff=AT,
        retention_days=365,
        key_id="k-example",
    )
    assert _anchor().message().split(b"\n", 1)[0] == b"warden.audit.anchor.v1"
    assert checkpoint.message().split(b"\n", 1)[0] == b"warden.audit.checkpoint.v1"


def test_details_round_trip() -> None:
    anchor = _anchor()
    details = anchor.to_details()
    assert set(details) == {ANCHOR_KEY}
    assert details[ANCHOR_KEY]["signature"] == "AQEB" * 21 + "AQ"  # base64url, unpadded
    assert Anchor.from_details(details) == anchor
    # The stored form survives JSON, as jsonb and a SIEM both hold it.
    assert Anchor.from_details(json.loads(json.dumps(details))) == anchor


def test_a_signature_made_for_the_message_verifies() -> None:
    private = Ed25519PrivateKey.generate()
    unsigned = _anchor(signature=b"")
    signed = dataclasses.replace(unsigned, signature=private.sign(unsigned.message()))
    private.public_key().verify(
        signed.signature, Anchor.from_details(signed.to_details()).message()
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.pop("head_hash"),
        lambda b: b.update(head_hash="00" * 31),
        lambda b: b.update(head_hash="zz" * 32),
        lambda b: b.update(head_id="41"),
        lambda b: b.update(head_id=True),
        lambda b: b.update(head_id=0),
        lambda b: b.update(version=2),
        lambda b: b.update(anchored_at="yesterday"),
        lambda b: b.update(anchored_at="2026-10-28T03:04:05+00:00"),
        lambda b: b.update(key_id=7),
        lambda b: b.update(signature="***"),
        lambda b: b.update(extra="field"),
    ],
)
def test_malformed_details_are_refused(mutate: Any) -> None:
    details = _anchor().to_details()
    mutate(details[ANCHOR_KEY])
    with pytest.raises(MalformedAnchor):
        Anchor.from_details(details)


def test_details_without_an_anchor_are_refused() -> None:
    with pytest.raises(MalformedAnchor):
        Anchor.from_details({"checkpoint": {}})


# Reading anchors back from a SIEM.


def _ndjson(anchor: Anchor, row_id: int = 42, **kw: Any) -> str:
    row = {
        "id": row_id,
        "recorded_at": "2026-10-28T03:04:05.700000Z",
        "occurred_at": "2026-10-28T03:04:05.700000Z",
        "action": ANCHOR_ACTION,
        "outcome": "success",
        "actor": None,
        "resource_type": None,
        "resource_id": None,
        "source_ip": None,
        "details": anchor.to_details(),
        "key_id": None,
        "prev_hash": HEAD_HASH.hex(),
        "row_hash": "ab" * 32,
    }
    row.update(kw)
    return json.dumps(row, ensure_ascii=True, separators=(",", ":"))


def _syslog(anchor: Anchor, row_id: int = 42, **settings: Any) -> str:
    registry = ActionRegistry()
    register_audit_actions(registry)
    values: dict[str, Any] = {
        "host": "collector.example.com",
        "port": 6514,
        "hostname": "app-1.example.com",
    }
    values.update(settings)
    record = AuditRecord(
        id=row_id,
        occurred_at=AT,
        action=ANCHOR_ACTION,
        outcome="success",
        details=anchor.to_details(),
        row_hash=b"\xab" * 32,
    )
    return format_message(record, SyslogSettings(**values), registry).decode("utf-8")


def test_an_ndjson_export_line_is_read() -> None:
    anchor = _anchor()
    (found,) = read_anchors([_ndjson(anchor)])
    assert (found.line, found.row_id, found.anchor) == (1, 42, anchor)


def test_a_forwarded_syslog_message_is_read() -> None:
    anchor = _anchor()
    (found,) = read_anchors([_syslog(anchor, row_id=77)])
    assert (found.line, found.row_id, found.anchor) == (1, 77, anchor)


def test_a_product_sd_id_is_read() -> None:
    anchor = _anchor()
    (found,) = read_anchors([_syslog(anchor, sd_id="product@99999")])
    assert found.anchor == anchor


def test_a_syslog_message_behind_a_collector_prefix_is_read() -> None:
    """SIEMs often prepend their own receive time and host, or keep the octet count."""
    anchor = _anchor()
    message = _syslog(anchor)
    lines = [
        f"{len(message.encode())} {message}",
        f"Oct 28 03:04:06 relay.example.net {message}",
    ]
    assert [a.anchor for a in read_anchors(lines)] == [anchor, anchor]


def test_other_rows_and_noise_are_skipped_and_lines_are_numbered() -> None:
    anchor = _anchor()
    other = _ndjson(anchor, action="product.export", details={"n": 1})
    lines = ["", other, "not an anchor", _ndjson(anchor), "   ", _syslog(anchor)]
    assert [(a.line, a.anchor) for a in read_anchors(lines)] == [(4, anchor), (6, anchor)]


def test_a_broken_anchor_line_is_reported_not_skipped() -> None:
    """A line naming the anchor action whose details do not parse is kept as malformed."""
    good = _anchor()
    broken = _ndjson(good).replace('"head_id":41', '"head_id":"41"')
    truncated = _syslog(good, max_message_bytes=1024)[:300]
    found = read_anchors([broken, truncated])
    assert [(a.line, a.anchor) for a in found] == [(1, None), (2, None)]


def test_a_truncated_syslog_anchor_is_malformed() -> None:
    """A message the forwarder had to cut cannot carry a whole anchor."""
    anchor = _anchor(key_id="k" * 900)
    message = _syslog(anchor, max_message_bytes=1024)
    assert 'truncated="true"' in message
    (found,) = read_anchors([message])
    assert found.anchor is None


def test_quotes_and_brackets_in_other_parameters_do_not_confuse_the_parser() -> None:
    anchor = _anchor()
    message = _syslog(anchor).replace(' outcome="success"', ' note="a \\"quoted\\" \\] value"', 1)
    (found,) = read_anchors([message])
    assert found.anchor == anchor


def test_an_anchor_action_named_only_in_free_text_is_not_an_anchor() -> None:
    line = '<13>1 2026-10-28T03:04:05Z app-1 warden - 9 [product@99999 action="product.note"] ' + (
        f"mentions {ANCHOR_ACTION}"
    )
    assert read_anchors([line]) == []


def test_a_forwarded_anchor_fits_the_smallest_syslog_cap_whole() -> None:
    """Worst-case header fields, the longest ids and the longest actor allowed: no cut."""
    from warden.audit.anchor import MAX_ANCHOR_ACTOR

    registry = ActionRegistry()
    register_audit_actions(registry)
    widest = _anchor(head_id=2**63 - 2, key_id="k" * 22)
    record = AuditRecord(
        id=2**63 - 1,
        occurred_at=AT,
        action=ANCHOR_ACTION,
        outcome="success",
        actor="a" * MAX_ANCHOR_ACTOR,
        details=widest.to_details(),
        row_hash=b"\xab" * 32,
    )
    settings = SyslogSettings(
        host="collector.example.com",
        port=6514,
        hostname="h" * 255,
        app_name="w" * 48,
        max_message_bytes=1024,
    )
    message = format_message(record, settings, registry)
    assert b'truncated="true"' not in message
    (found,) = read_anchors([message.decode("utf-8")])
    assert found.anchor == widest
