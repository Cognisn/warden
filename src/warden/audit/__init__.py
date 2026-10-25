"""warden's audit subsystem.

``warden.audit`` imports nothing from ``warden.identity`` (design D11), so a
product with its own authentication, or a worker process, can use audit
alone. A tripwire test enforces this.
"""

from warden.audit.events import AuditEvent, Outcome, Severity
from warden.audit.grants import append_only_grants, grants_sql
from warden.audit.query import AuditPage, AuditQuery, iter_events, list_events
from warden.audit.recorder import (
    AuditChainConflict,
    AuditRecorder,
    get_recorder,
    record_audit,
    set_recorder,
)
from warden.audit.registry import SUMMARY_FIELDS, ActionRegistry, ActionSpec
from warden.audit.retention import MIN_RETENTION_DAYS, PurgeResult, RetentionError, purge
from warden.audit.sink import AuditSink
from warden.audit.verify import BrokenLink, VerificationReport, verify_chain

__all__ = [
    "MIN_RETENTION_DAYS",
    "SUMMARY_FIELDS",
    "ActionRegistry",
    "ActionSpec",
    "AuditChainConflict",
    "AuditEvent",
    "AuditPage",
    "AuditQuery",
    "AuditRecorder",
    "AuditSink",
    "BrokenLink",
    "Outcome",
    "PurgeResult",
    "RetentionError",
    "Severity",
    "VerificationReport",
    "append_only_grants",
    "get_recorder",
    "grants_sql",
    "iter_events",
    "list_events",
    "purge",
    "record_audit",
    "set_recorder",
    "verify_chain",
]
