"""Registry of audit actions: warden's own and the product's.

Every recorded event names a registered action. A registration fixes the
action's severity and a summary template, which may reference only the
event's own fields, so a summary can never pull in a value the event does
not already carry.
"""

from __future__ import annotations

import re
import string
import threading
from dataclasses import dataclass

from warden.audit.events import AuditEvent, Severity

__all__ = ["SUMMARY_FIELDS", "ActionRegistry", "ActionSpec"]

_ACTION = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")

SUMMARY_FIELDS = frozenset({"action", "outcome", "actor", "resource_type", "resource_id"})


def _check_summary(summary: str) -> None:
    try:
        parsed = list(string.Formatter().parse(summary))
    except ValueError:
        raise ValueError("summary template has unbalanced braces") from None
    for _literal, field, spec, conversion in parsed:
        if field is None:
            continue
        if field not in SUMMARY_FIELDS or spec or conversion:
            allowed = ", ".join("{" + f + "}" for f in sorted(SUMMARY_FIELDS))
            raise ValueError(f"summary template may use only {allowed}")


@dataclass(frozen=True, slots=True)
class ActionSpec:
    """A registered action: dotted name, severity and summary template."""

    action: str
    severity: Severity
    summary: str

    def __post_init__(self) -> None:
        if _ACTION.fullmatch(self.action) is None:
            raise ValueError("action must be dotted lower-case words, such as product.export")
        _check_summary(self.summary)

    def render(self, event: AuditEvent) -> str:
        """The one-line summary for ``event``; absent fields render as ``-``."""
        values = {name: getattr(event, name) for name in SUMMARY_FIELDS}
        return self.summary.format_map({k: "-" if v is None else str(v) for k, v in values.items()})


class ActionRegistry:
    """The set of actions this deployment records."""

    def __init__(self) -> None:
        self._specs: dict[str, ActionSpec] = {}
        self._lock = threading.Lock()

    def register(self, action: str, *, severity: Severity, summary: str) -> ActionSpec:
        """Register an action. Re-registering an identical spec is a no-op."""
        spec = ActionSpec(action=action, severity=Severity(severity), summary=summary)
        with self._lock:
            existing = self._specs.get(action)
            if existing is not None and existing != spec:
                raise ValueError(f"action {action} is already registered differently")
            self._specs[action] = spec
        return spec

    def get(self, action: str) -> ActionSpec:
        """The spec for ``action``; ``KeyError`` if it was never registered."""
        try:
            return self._specs[action]
        except KeyError:
            raise KeyError(f"audit action {action!r} is not registered") from None

    def __contains__(self, action: object) -> bool:
        return action in self._specs

    def actions(self) -> list[ActionSpec]:
        return sorted(self._specs.values(), key=lambda spec: spec.action)
