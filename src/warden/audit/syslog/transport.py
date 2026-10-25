"""Syslog transports: UDP, and TCP or TLS with octet-counting or LF framing.

TLS verifies the collector's certificate chain and host name and fails
closed: there is no plaintext fallback and no setting that turns
verification off. A tripwire test scans warden's source for the ways
verification is usually disabled.

Failures surface as ``TransportError`` carrying a fixed category, never the
underlying exception text, so a status route can show it without leaking
detail (Termograph lesson 15).
"""

from __future__ import annotations

import asyncio
import errno
import socket
import ssl
from typing import Literal, Protocol

from warden.audit.syslog.settings import SyslogSettings

__all__ = [
    "Transport",
    "TransportError",
    "classify_error",
    "frame",
    "open_transport",
    "tls_context",
]

_REFUSED = {errno.ECONNREFUSED, 10061, 1225}  # POSIX, WSAECONNREFUSED, ERROR_CONNECTION_REFUSED
_CLOSE_TIMEOUT = 2.0


class TransportError(Exception):
    """A send or connection failure, described by a fixed category."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def classify_error(exc: BaseException) -> str:
    """A fixed, detail-free category for ``exc``."""
    if isinstance(exc, TransportError):
        return exc.category
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate verification failed"
    if isinstance(exc, ssl.SSLError):
        return "tls error"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "name resolution failed"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, OSError) and (
        exc.errno in _REFUSED or getattr(exc, "winerror", None) in _REFUSED
    ):
        return "connection refused"
    if isinstance(exc, OSError | EOFError):
        return "connection failed"
    return "send failed"


def frame(message: bytes, framing: Literal["octet-counting", "lf"]) -> bytes:
    """Frame ``message`` for a stream transport (RFC 6587)."""
    if framing == "lf":
        if b"\n" in message:
            raise ValueError("an LF-framed message must not contain a newline")
        return message + b"\n"
    return str(len(message)).encode("ascii") + b" " + message


def tls_context(settings: SyslogSettings) -> ssl.SSLContext:
    """A client context that verifies the chain and host name, TLS 1.2 or later.

    The trust anchors are ``tls_ca_pem`` and ``tls_ca_file`` when either is
    set, otherwise the system trust store.
    """
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=settings.tls_ca_file, cadata=settings.tls_ca_pem
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


class Transport(Protocol):
    """A connection to the collector. ``send`` raises ``TransportError`` on failure."""

    async def send(self, message: bytes) -> None: ...

    async def close(self) -> None: ...


class StreamTransport:
    """TCP or TLS. After any failure the connection is spent and must be replaced."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        settings: SyslogSettings,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._settings = settings
        self._broken = False

    async def send(self, message: bytes) -> None:
        if self._broken:
            raise TransportError("connection closed")
        # A collector that went away shows up as end of stream on our side;
        # writing into it would appear to succeed and silently lose rows.
        if self._reader.at_eof() or self._writer.is_closing():
            self._broken = True
            raise TransportError("connection closed")
        data = frame(message, self._settings.framing)
        try:
            self._writer.write(data)
            async with asyncio.timeout(self._settings.send_timeout_seconds):
                await self._writer.drain()
        except Exception as exc:
            self._broken = True
            raise TransportError(classify_error(exc)) from None

    async def close(self) -> None:
        self._broken = True
        self._writer.close()
        try:
            async with asyncio.timeout(_CLOSE_TIMEOUT):
                await self._writer.wait_closed()
        except Exception:
            # A peer that stopped reading never lets buffered data drain.
            self._writer.transport.abort()


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.error: Exception | None = None

    def error_received(self, exc: Exception) -> None:
        self.error = exc


class UdpTransport:
    """One message per datagram. UDP has no acknowledgement, so delivery is best effort."""

    def __init__(self, transport: asyncio.DatagramTransport, protocol: _UdpProtocol) -> None:
        self._transport = transport
        self._protocol = protocol

    async def send(self, message: bytes) -> None:
        if self._transport.is_closing():
            raise TransportError("connection closed")
        error, self._protocol.error = self._protocol.error, None
        if error is not None:
            raise TransportError(classify_error(error))
        try:
            self._transport.sendto(message)
        except Exception as exc:
            raise TransportError(classify_error(exc)) from None

    async def close(self) -> None:
        self._transport.close()


async def open_transport(settings: SyslogSettings) -> Transport:
    """Connect to the collector named in ``settings``; ``TransportError`` on failure."""
    loop = asyncio.get_running_loop()
    try:
        async with asyncio.timeout(settings.connect_timeout_seconds):
            if settings.transport == "udp":
                udp, protocol = await loop.create_datagram_endpoint(
                    _UdpProtocol, remote_addr=(settings.host, settings.port)
                )
                return UdpTransport(udp, protocol)
            context = tls_context(settings) if settings.transport == "tls" else None
            reader, writer = await asyncio.open_connection(
                settings.host,
                settings.port,
                ssl=context,
                server_hostname=settings.server_name if context is not None else None,
                ssl_handshake_timeout=(
                    settings.connect_timeout_seconds if context is not None else None
                ),
            )
            return StreamTransport(reader, writer, settings)
    except Exception as exc:
        raise TransportError(classify_error(exc)) from None
