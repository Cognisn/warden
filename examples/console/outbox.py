"""A mail sender that keeps messages in memory, so the console can show them.

warden renders invitation, password reset and MFA-enrolled messages and
hands each to the product's ``MailSender``. A real product sends them (SES,
SMTP, Microsoft 365); the sample keeps the latest ones for its outbox page,
so invitation and reset links can be followed without a mail server.
"""

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from typing import Any

from warden.identity import MailMessage

__all__ = ["Outbox"]


class Outbox:
    """A ``MailSender`` holding the last ``limit`` messages, newest last."""

    def __init__(self, limit: int = 100) -> None:
        self._messages: deque[tuple[datetime, MailMessage]] = deque(maxlen=limit)

    async def send(self, message: MailMessage) -> None:
        self._messages.append((datetime.now(UTC), message))

    def messages(self) -> list[dict[str, Any]]:
        """The kept messages, newest first, as the outbox page shows them."""
        return [
            {
                "sent_at": sent_at.isoformat(),
                "kind": message.kind.value,
                "to": message.to,
                "subject": message.subject,
                "text": message.text,
            }
            for sent_at, message in reversed(self._messages)
        ]
