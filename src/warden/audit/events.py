"""The audit event model."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress, JsonValue

__all__ = ["AuditEvent", "Outcome", "Severity"]

Outcome = Literal["success", "failure"]


class Severity(IntEnum):
    """Event severity, numbered as RFC 5424 syslog severities."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


def _now() -> datetime:
    return datetime.now(UTC)


class AuditEvent(BaseModel):
    """One thing that happened: who did what to which resource, and how it ended."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    outcome: Outcome
    occurred_at: AwareDatetime = Field(default_factory=_now)
    actor: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    source_ip: IPvAnyAddress | None = None
    details: dict[str, JsonValue] = Field(default_factory=dict)
