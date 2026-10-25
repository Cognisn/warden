"""Trusted-proxy middleware: forwarded headers are believed only from configured proxies."""

from __future__ import annotations

from ipaddress import ip_network
from typing import Any

import pytest

from warden.proxy import TrustedProxyMiddleware, resolve_client_ip

TRUSTED = (ip_network("10.0.0.0/8"), ip_network("2001:db8:ffff::/48"))


@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        # An untrusted peer's forwarded header is ignored entirely.
        ("198.51.100.9", ["203.0.113.5"], "198.51.100.9"),
        # From a trusted proxy, the rightmost entry is the address it observed.
        ("10.0.0.1", ["203.0.113.5"], "203.0.113.5"),
        ("10.0.0.1", ["192.0.2.66, 203.0.113.5"], "203.0.113.5"),
        # A client-supplied header is appended to, so its own entries sit on the left.
        ("10.0.0.1", ["192.0.2.66", "203.0.113.5"], "203.0.113.5"),
        # Entries added by further trusted proxies are skipped.
        ("10.0.0.1", ["203.0.113.5, 10.0.0.2"], "203.0.113.5"),
        ("10.0.0.1", ["10.9.9.9, 10.0.0.2"], "10.9.9.9"),
        # No header, or an empty one, leaves the peer.
        ("10.0.0.1", [], "10.0.0.1"),
        ("10.0.0.1", [""], "10.0.0.1"),
        # A malformed entry where the address should be: fall back to the last known hop.
        ("10.0.0.1", ["203.0.113.5, not-an-ip"], "10.0.0.1"),
        ("10.0.0.1", ["203.0.113.5, 10.0.0.2, bogus"], "10.0.0.1"),
        ("10.0.0.1", ["bogus, 203.0.113.5"], "203.0.113.5"),
        ("10.0.0.1", ["203.0.113.5\n"], "203.0.113.5"),
        ("10.0.0.1", ["203.0.113.5\nX-Injected: 1"], "10.0.0.1"),
        # Ports and IPv6 brackets.
        ("10.0.0.1", ["203.0.113.5:8443"], "203.0.113.5"),
        ("10.0.0.1", ["[2001:db8::7]:443"], "2001:db8::7"),
        ("10.0.0.1", ["2001:db8::7"], "2001:db8::7"),
        ("2001:db8:ffff::1", ["203.0.113.5"], "203.0.113.5"),
        # An IPv4-mapped peer is matched as IPv4.
        ("::ffff:10.0.0.1", ["203.0.113.5"], "203.0.113.5"),
        # A peer that is not an address at all is never trusted.
        ("testclient", ["203.0.113.5"], "testclient"),
    ],
)
def test_resolve_client_ip(peer: str, forwarded: list[str], expected: str) -> None:
    assert resolve_client_ip(peer, forwarded, TRUSTED) == expected


def test_no_trusted_proxies_means_no_header_is_believed() -> None:
    assert resolve_client_ip("10.0.0.1", ["203.0.113.5"], ()) == "10.0.0.1"


def test_no_peer_stays_unknown() -> None:
    assert resolve_client_ip(None, ["203.0.113.5"], TRUSTED) is None


class _App:
    def __init__(self) -> None:
        self.scopes: list[dict[str, Any]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.scopes.append(scope)


def _scope(peer: tuple[str, int] | None, *headers: tuple[bytes, bytes]) -> dict[str, Any]:
    return {"type": "http", "client": peer, "headers": list(headers)}


async def _noop() -> None:
    return None


async def test_middleware_rewrites_the_client_from_a_trusted_proxy() -> None:
    app = _App()
    middleware = TrustedProxyMiddleware(app, trusted_proxies=["10.0.0.0/8"])
    scope = _scope(
        ("10.0.0.1", 5000),
        (b"x-forwarded-for", b"192.0.2.66"),
        (b"x-forwarded-for", b"203.0.113.5"),
    )
    await middleware(scope, _noop, _noop)
    assert app.scopes[0]["client"] == ("203.0.113.5", 0)
    assert scope["client"] == ("10.0.0.1", 5000), "the caller's scope is not mutated"


async def test_middleware_leaves_an_untrusted_peer_alone() -> None:
    app = _App()
    middleware = TrustedProxyMiddleware(app, trusted_proxies=["10.0.0.0/8"])
    await middleware(
        _scope(("198.51.100.9", 5000), (b"x-forwarded-for", b"203.0.113.5")), _noop, _noop
    )
    assert app.scopes[0]["client"] == ("198.51.100.9", 5000)


async def test_middleware_ignores_other_forwarding_headers() -> None:
    """One gate: only X-Forwarded-For, never Forwarded or X-Real-IP."""
    app = _App()
    middleware = TrustedProxyMiddleware(app, trusted_proxies=["10.0.0.0/8"])
    await middleware(
        _scope(
            ("10.0.0.1", 5000),
            (b"forwarded", b"for=203.0.113.5"),
            (b"x-real-ip", b"203.0.113.6"),
        ),
        _noop,
        _noop,
    )
    assert app.scopes[0]["client"] == ("10.0.0.1", 5000)


async def test_middleware_passes_lifespan_scopes_through() -> None:
    app = _App()
    middleware = TrustedProxyMiddleware(app, trusted_proxies=["10.0.0.0/8"])
    scope = {"type": "lifespan"}
    await middleware(scope, _noop, _noop)
    assert app.scopes == [scope]


def test_middleware_refuses_an_invalid_network() -> None:
    with pytest.raises(ValueError):
        TrustedProxyMiddleware(_App(), trusted_proxies=["10.0.0.0/33"])
