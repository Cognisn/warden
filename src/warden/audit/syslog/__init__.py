"""Syslog forwarding of committed audit rows (RFC 5424 over UDP, TCP or TLS)."""

from warden.audit.syslog.formatter import AuditRecord, format_message, neutralise
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
    "SyslogSettings",
    "Transport",
    "TransportError",
    "classify_error",
    "format_message",
    "frame",
    "neutralise",
    "open_transport",
    "tls_context",
]
