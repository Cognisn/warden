"""Single sign-on refusals.

``SsoError.reason`` is a fixed category, recorded in the audit trail under
``warden.identity.sso.*``. It never reaches the browser, which always gets
the same failure, and it never carries provider text, tokens or codes.
"""

from __future__ import annotations

__all__ = ["SsoError"]


class SsoError(Exception):
    """A single sign-on step was refused; ``reason`` says why, for the audit trail."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
