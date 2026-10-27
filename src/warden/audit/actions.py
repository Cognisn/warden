"""The audit actions warden's own audit subsystem records."""

from __future__ import annotations

from warden.audit.events import Severity
from warden.audit.registry import ActionRegistry, register_warden_action

__all__ = ["EXPORT_ACTION", "PURGE_ACTION", "register_audit_actions"]

PURGE_ACTION = "warden.audit.purge"
EXPORT_ACTION = "warden.audit.export"


def register_audit_actions(registry: ActionRegistry) -> None:
    """Register warden's audit actions. Idempotent."""
    register_warden_action(
        registry, PURGE_ACTION, severity=Severity.NOTICE, summary="audit retention purge: {outcome}"
    )
    register_warden_action(
        registry,
        EXPORT_ACTION,
        severity=Severity.NOTICE,
        summary="{actor} exported the audit trail",
    )
