"""HTTP routes for syslog forwarding: status and a test send.

warden has no notion of who may call these: the product passes an
``authorise`` dependency that refuses unauthorised callers (raising its own
HTTP error) and returns the caller's actor id, which is recorded on the
audit event for a test send. This keeps ``warden.audit`` free of any
dependency on ``warden.identity``.

FastAPI reads the route signatures at runtime, so this module does not use
postponed annotations.
"""

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from warden.audit.events import AuditEvent, Severity
from warden.audit.recorder import AuditRecorder
from warden.audit.registry import ActionRegistry
from warden.audit.syslog.formatter import format_test_message
from warden.audit.syslog.forwarder import ForwarderStatus, SyslogForwarder
from warden.audit.syslog.transport import TransportError

__all__ = [
    "SYSLOG_TEST_ACTION",
    "TestSendResult",
    "register_syslog_actions",
    "send_test_message",
    "syslog_router",
]

SYSLOG_TEST_ACTION = "warden.syslog.test_sent"


class TestSendResult(BaseModel):
    """Whether the test message reached the transport, and if not, why (a fixed category)."""

    __test__ = False  # not a pytest test class, despite the name
    model_config = ConfigDict(frozen=True)

    delivered: bool
    error: str | None


def register_syslog_actions(registry: ActionRegistry) -> None:
    """Register the audit actions the syslog routes record. Safe to call more than once."""
    registry.register(
        SYSLOG_TEST_ACTION,
        severity=Severity.NOTICE,
        summary="{actor} sent a syslog test message",
    )


async def send_test_message(forwarder: SyslogForwarder) -> TestSendResult:
    """Send one test message over a fresh connection with the forwarder's settings."""
    settings = forwarder.settings
    try:
        transport = await forwarder.transport_factory(settings)
        try:
            await transport.send(format_test_message(settings))
        finally:
            await transport.close()
    except TransportError as exc:
        return TestSendResult(delivered=False, error=exc.category)
    return TestSendResult(delivered=True, error=None)


def syslog_router(
    forwarder: SyslogForwarder,
    *,
    authorise: Callable[..., Any],
    recorder: AuditRecorder | None = None,
) -> APIRouter:
    """``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your choice.

    ``authorise`` is a FastAPI dependency: it raises to refuse the caller and
    returns the caller's actor id. With ``recorder``, each test send is
    audited as ``SYSLOG_TEST_ACTION`` (see ``register_syslog_actions``).
    """
    router = APIRouter()
    Actor = Annotated[Any, Depends(authorise)]

    @router.get("/syslog/status", response_model=ForwarderStatus)
    async def syslog_status(actor: Actor) -> ForwarderStatus:
        return await forwarder.status()

    @router.post("/syslog/test", response_model=TestSendResult)
    async def syslog_test(actor: Actor) -> TestSendResult:
        result = await send_test_message(forwarder)
        if recorder is not None:
            await recorder.record(
                AuditEvent(
                    action=SYSLOG_TEST_ACTION,
                    outcome="success" if result.delivered else "failure",
                    actor=None if actor is None else str(actor),
                    details={} if result.error is None else {"error": result.error},
                )
            )
        return result

    return router
