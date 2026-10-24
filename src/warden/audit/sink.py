"""Where recorded events go after the database: syslog, for one."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from warden.audit.events import AuditEvent

__all__ = ["AuditSink"]


@runtime_checkable
class AuditSink(Protocol):
    """A consumer of recorded events.

    ``offer`` must never block and never raise into the caller: a sink that
    cannot keep up drops its copy (and counts the drop) rather than slow a
    request. The recorder also guards against a sink that raises anyway.
    """

    def offer(self, event: AuditEvent) -> None: ...
