"""Identity's exceptions."""

from __future__ import annotations

__all__ = ["AuthenticationRefused", "MfaError"]


class AuthenticationRefused(Exception):
    """A credential was refused.

    ``reason`` is for the audit trail and tests only. It is never sent to the
    caller: every refusal reaches the caller as the same response.
    """

    def __init__(self, reason: str) -> None:
        super().__init__("authentication refused")
        self.reason = reason


class MfaError(Exception):
    """An MFA enrolment change was refused. Messages carry identifiers only."""
