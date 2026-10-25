"""Syslog forwarding of committed audit rows (RFC 5424 over UDP, TCP or TLS)."""

from warden.audit.syslog.formatter import AuditRecord, format_message, neutralise
from warden.audit.syslog.forwarder import (
    ForwarderSnapshot,
    ForwarderStatus,
    SyslogForwarder,
    TransportFactory,
)
from warden.audit.syslog.settings import SyslogSettings
from warden.audit.syslog.transport import (
    Transport,
    TransportError,
    classify_error,
    frame,
    open_transport,
    tls_context,
)

__all__ = [
    "AuditRecord",
    "ForwarderSnapshot",
    "ForwarderStatus",
    "SyslogForwarder",
    "SyslogSettings",
    "Transport",
    "TransportError",
    "TransportFactory",
    "classify_error",
    "format_message",
    "frame",
    "neutralise",
    "open_transport",
    "tls_context",
]
