"""Audit event model and the product-registered action registry."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address

import pytest
from pydantic import ValidationError

from warden.audit import ActionRegistry, ActionSpec, AuditEvent, Severity


def test_event_defaults_to_now_in_utc() -> None:
    event = AuditEvent(action="product.thing", outcome="success")
    assert event.occurred_at.tzinfo is not None
    assert abs((datetime.now(UTC) - event.occurred_at).total_seconds()) < 5
    assert event.details == {}


def test_event_rejects_naive_timestamps() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(action="product.thing", outcome="success", occurred_at=datetime(2026, 1, 1))


def test_event_parses_source_ip() -> None:
    event = AuditEvent(action="product.thing", outcome="failure", source_ip="2001:db8::1")
    assert event.source_ip == ip_address("2001:db8::1")


def test_event_outcome_is_constrained() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(action="product.thing", outcome="maybe")  # type: ignore[arg-type]


def test_event_details_must_be_json() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(action="product.thing", outcome="success", details={"x": object()})


def test_event_is_immutable() -> None:
    event = AuditEvent(action="product.thing", outcome="success")
    with pytest.raises(ValidationError):
        event.action = "other.thing"  # type: ignore[misc]


@pytest.mark.parametrize(
    "action",
    [
        "thing",
        "Product.thing",
        "product.",
        ".thing",
        "product..thing",
        "product.thing\n",
        "product.thing ",
    ],
)
def test_action_names_are_validated(action: str) -> None:
    registry = ActionRegistry()
    with pytest.raises(ValueError):
        registry.register(action, severity=Severity.INFO, summary="x")


def test_registration_is_idempotent_for_an_identical_spec() -> None:
    registry = ActionRegistry()
    first = registry.register(
        "product.export", severity=Severity.NOTICE, summary="{actor} exported"
    )
    second = registry.register(
        "product.export", severity=Severity.NOTICE, summary="{actor} exported"
    )
    assert first == second == registry.get("product.export")


def test_conflicting_registration_fails() -> None:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    with pytest.raises(ValueError):
        registry.register("product.export", severity=Severity.WARNING, summary="{actor} exported")


def test_unknown_action_lookup_fails() -> None:
    with pytest.raises(KeyError):
        ActionRegistry().get("product.nope")


def test_summary_template_may_use_only_event_fields() -> None:
    registry = ActionRegistry()
    with pytest.raises(ValueError):
        registry.register("product.x", severity=Severity.INFO, summary="{password}")
    with pytest.raises(ValueError):
        registry.register("product.y", severity=Severity.INFO, summary="{actor!r}")


def test_summary_renders_from_the_event() -> None:
    spec = ActionSpec(
        action="product.export",
        severity=Severity.NOTICE,
        summary="{actor} exported {resource_type} {resource_id}: {outcome}",
    )
    event = AuditEvent(
        action="product.export",
        outcome="success",
        actor="user-1",
        resource_type="report",
        resource_id="r-9",
    )
    assert spec.render(event) == "user-1 exported report r-9: success"


def test_summary_renders_missing_fields_as_a_dash() -> None:
    spec = ActionSpec(
        action="product.export", severity=Severity.NOTICE, summary="{actor} exported {resource_id}"
    )
    assert spec.render(AuditEvent(action="product.export", outcome="success")) == "- exported -"


def test_severity_values_follow_rfc5424() -> None:
    assert [s.value for s in Severity] == [0, 1, 2, 3, 4, 5, 6, 7]
    assert Severity.INFO == 6
