"""warden's audit subsystem.

``warden.audit`` imports nothing from ``warden.identity`` (design D11), so a
product with its own authentication, or a worker process, can use audit
alone. A tripwire test enforces this.
"""

from warden.audit.events import AuditEvent, Outcome, Severity
from warden.audit.recorder import (
    AuditChainConflict,
    AuditRecorder,
    get_recorder,
    record_audit,
    set_recorder,
)
from warden.audit.registry import SUMMARY_FIELDS, ActionRegistry, ActionSpec
from warden.audit.sink import AuditSink

__all__ = [
    "SUMMARY_FIELDS",
    "ActionRegistry",
    "ActionSpec",
    "AuditChainConflict",
    "AuditEvent",
    "AuditRecorder",
    "AuditSink",
    "Outcome",
    "Severity",
    "get_recorder",
    "record_audit",
    "set_recorder",
]
