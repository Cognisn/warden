"""Security headers on every answer: a strict Content Security Policy and friends.

The console's pages load scripts and styles only from the app itself, with
no inline script or style, so the policy needs no ``unsafe-`` source. The
only other origin the browser may reach is the identity provider, and only
as the target of the single sign-on form (``form-action``).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

__all__ = ["SecurityHeaders", "content_security_policy"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]


def _origin(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None


def content_security_policy(provider_url: str | None = None) -> str:
    """The policy. ``provider_url`` is the identity provider a sign-in form may go to."""
    form_action = " ".join(filter(None, ("'self'", _origin(provider_url))))
    return "; ".join(
        (
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self'",
            "connect-src 'self'",
            f"form-action {form_action}",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
        )
    )


class SecurityHeaders:
    """ASGI middleware adding the policy and related headers to every HTTP answer."""

    def __init__(self, app: App, *, policy: str) -> None:
        self._app = app
        self._headers = [
            (b"content-security-policy", policy.encode("ascii")),
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"no-referrer"),
            (b"cross-origin-opener-policy", b"same-origin"),
        ]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                names = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(n, v) for n, v in self._headers if n not in names]
                message["headers"] = [*message.get("headers", []), *extra]
            await send(message)

        await self._app(scope, receive, with_headers)
