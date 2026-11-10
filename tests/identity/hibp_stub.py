"""Stubbed range API transports (imported as ``hibp_stub``): no live service in unit tests."""

from __future__ import annotations

import hashlib

import httpx


def failing_transport() -> httpx.MockTransport:
    """A range API that cannot be reached."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("api.example.com is unreachable", request=request)

    return httpx.MockTransport(handler)


def listing_transport(*passwords: str) -> httpx.MockTransport:
    """A range API that lists ``passwords`` (and pads with zero-count entries)."""
    listed = {
        hashlib.sha1(p.encode()).hexdigest().upper()  # noqa: S324 - the range API's format
        for p in passwords
    }

    def handler(request: httpx.Request) -> httpx.Response:
        prefix = request.url.path.rsplit("/", 1)[1]
        lines = [f"{h[5:]}:42" for h in sorted(listed) if h.startswith(prefix)]
        lines.append("0" * 35 + ":0")
        return httpx.Response(200, text="\r\n".join(lines))

    return httpx.MockTransport(handler)
