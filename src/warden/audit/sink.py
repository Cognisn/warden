"""Where recorded events go after the database: syslog, for one."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from warden.audit.events import AuditEvent

__all__ = ["AuditSink"]


@runtime_checkable
class AuditSink(Protocol):
    """An in-process consumer of recorded events.

    The recorder offers an event only after warden's own transaction has
    committed, and never for a record written inside a caller's transaction,
    so a sink sees no rolled-back event but also not every event. Syslog
    forwarding therefore reads committed rows from the table instead.

    ``offer`` must never block and never raise into the caller: a sink that
    cannot keep up drops its copy (and counts the drop) rather than slow a
    request. The recorder also guards against a sink that raises anyway.
    """

    def offer(self, event: AuditEvent) -> None: ...
