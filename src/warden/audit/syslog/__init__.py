"""Syslog forwarding of committed audit rows (RFC 5424 over UDP, TCP or TLS)."""

from warden.audit.syslog.formatter import (
    AuditRecord,
    format_message,
    format_test_message,
    neutralise,
)
from warden.audit.syslog.forwarder import (
    ForwarderSnapshot,
    ForwarderStatus,
    SyslogForwarder,
    TransportFactory,
)
from warden.audit.syslog.routes import (
    SYSLOG_TEST_ACTION,
    TestSendResult,
    register_syslog_actions,
    send_test_message,
    syslog_router,
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
    "SYSLOG_TEST_ACTION",
    "AuditRecord",
    "ForwarderSnapshot",
    "ForwarderStatus",
    "SyslogForwarder",
    "SyslogSettings",
    "TestSendResult",
    "Transport",
    "TransportError",
    "TransportFactory",
    "classify_error",
    "format_message",
    "format_test_message",
    "frame",
    "neutralise",
    "open_transport",
    "register_syslog_actions",
    "send_test_message",
    "syslog_router",
    "tls_context",
]
