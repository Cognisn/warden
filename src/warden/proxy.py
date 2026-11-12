"""Trusted-proxy middleware: the real client address behind a reverse proxy.

A forwarded header is believed only when the connection's peer is one of the
configured trusted proxies (``audit.trusted_proxies``). There is one gate:
an empty list believes nothing, and no other setting opens it.

Only ``X-Forwarded-For`` is read; ``Forwarded`` and ``X-Real-IP`` are ignored,
so a client cannot pick a header the proxy does not overwrite. Proxies such
as nginx *append* the address they observed, so the trustworthy entry is the
rightmost. Walking from the right, entries added by further trusted proxies
are skipped, and the first address that is not a trusted proxy is the client.
An entry that is not an address, where an address should be, stops the walk
at the last hop known to be good.

The resolved address replaces ``scope["client"]`` (with port 0), so
``request.client.host`` is right for every route, including audit records.

    app = TrustedProxyMiddleware(app, trusted_proxies=config.audit.trusted_proxies)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, MutableMapping, Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Any

__all__ = ["TrustedProxyMiddleware", "resolve_client_ip"]

Network = IPv4Network | IPv6Network
Address = IPv4Address | IPv6Address

_Scope = MutableMapping[str, Any]
_App = Callable[
    [_Scope, Callable[[], Awaitable[Any]], Callable[..., Awaitable[Any]]], Awaitable[None]
]

_HEADER = b"x-forwarded-for"


def _address(text: str) -> Address | None:
    """Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``."""
    text = text.strip(" \t")
    if text.endswith("\n"):
        text = text[:-1]
    if any(c in text for c in "\r\n\x00"):
        return None
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or (rest and not (rest.startswith(":") and rest[1:].isdigit())):
            return None
        text = host
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
        if not port.isdigit():
            return None
        text = host
    try:
        address = ip_address(text)
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _trusted(address: Address, trusted: Sequence[Network]) -> bool:
    return any(address.version == net.version and address in net for net in trusted)


def resolve_client_ip(
    peer: str | None, forwarded_for: Sequence[str], trusted: Sequence[Network]
) -> str | None:
    """The client address, given the peer and every ``X-Forwarded-For`` value in order."""
    if peer is None:
        return None
    peer_address = _address(peer)
    if peer_address is None or not _trusted(peer_address, trusted):
        return peer
    entries = [e for value in forwarded_for for e in value.split(",")]
    entries = [e for e in entries if e.strip()]
    known = str(peer_address)
    for entry in reversed(entries):
        address = _address(entry)
        if address is None:
            return known
        if not _trusted(address, trusted):
            return str(address)
        known = str(address)
    return known if entries else peer


class TrustedProxyMiddleware:
    """ASGI middleware setting ``scope["client"]`` to the resolved client address."""

    def __init__(self, app: _App, *, trusted_proxies: Iterable[Network | str]) -> None:
        self._app = app
        self._trusted: tuple[Network, ...] = tuple(
            net if isinstance(net, IPv4Network | IPv6Network) else ip_network(net)
            for net in trusted_proxies
        )

    async def __call__(
        self,
        scope: _Scope,
        receive: Callable[[], Awaitable[Any]],
        send: Callable[..., Awaitable[Any]],
    ) -> None:
        if scope.get("type") not in ("http", "websocket") or not scope.get("client"):
            await self._app(scope, receive, send)
            return
        peer_host = scope["client"][0]
        values = [v.decode("latin-1") for k, v in scope.get("headers", ()) if k == _HEADER]
        client = resolve_client_ip(peer_host, values, self._trusted)
        if client is None or client == peer_host:
            await self._app(scope, receive, send)
            return
        await self._app({**scope, "client": (client, 0)}, receive, send)
