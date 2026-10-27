"""HTTP helpers shared by identity's routers and dependencies.

Every authentication failure, wherever it happens, is answered with the same
bytes: status 401, ``{"detail":"authentication failed"}``, the same headers.
Request bodies are parsed here rather than by FastAPI's validation, whose
422 responses echo the submitted values (a password, say) and differ by
failure.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Sequence
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import Response

from warden.proxy import Network, resolve_client_ip

__all__ = [
    "FORBIDDEN_BODY",
    "NO_STORE",
    "REFUSAL_BODY",
    "Refused",
    "SourceIp",
    "client_ip",
    "json_response",
    "read_object",
    "refusal",
]

REFUSAL_BODY = b'{"detail":"authentication failed"}'
FORBIDDEN_BODY = b'{"detail":"forbidden"}'
NO_STORE = {"cache-control": "no-store"}
_REFUSAL_HEADERS = {"www-authenticate": "Bearer", **NO_STORE}
_MAX_BODY = 16 * 1024

# The client address recorded with an audit event.
SourceIp = ipaddress.IPv4Address | ipaddress.IPv6Address | None


class Refused(HTTPException):
    """Raised by dependencies; FastAPI's default handler renders the uniform refusal."""

    def __init__(self) -> None:
        super().__init__(status_code=401, detail="authentication failed", headers=_REFUSAL_HEADERS)


def refusal() -> Response:
    return Response(
        content=REFUSAL_BODY,
        status_code=401,
        media_type="application/json",
        headers=_REFUSAL_HEADERS,
    )


def json_response(body: dict[str, Any], status_code: int = 200) -> Response:
    return Response(
        content=json.dumps(body, separators=(",", ":")).encode(),
        status_code=status_code,
        media_type="application/json",
        headers=NO_STORE,
    )


async def read_object(request: Request) -> dict[str, Any] | None:
    """The request body as a JSON object, or None if it is anything else."""
    body = await request.body()
    if len(body) > _MAX_BODY:
        return None
    try:
        value = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def client_ip(request: Request, trusted_proxies: Sequence[Network]) -> SourceIp:
    """The client address, for audit events and the sign-in throttle key.

    Resolved by ``warden.proxy.resolve_client_ip``: ``X-Forwarded-For`` is
    believed only when the peer is one of ``trusted_proxies``
    (``audit.trusted_proxies``). Resolving again after
    ``TrustedProxyMiddleware`` gives the same address, so a product may use
    both.
    """
    if request.client is None:
        return None
    forwarded = request.headers.getlist("x-forwarded-for")
    resolved = resolve_client_ip(request.client.host, forwarded, trusted_proxies)
    if resolved is None:
        return None
    try:
        return ipaddress.ip_address(resolved)
    except ValueError:
        return None
