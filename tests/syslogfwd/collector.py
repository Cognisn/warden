"""In-process syslog collectors for tests: stream (TCP or TLS), UDP and a blackhole.

The stream collector keeps every raw byte it receives and splits frames
itself, so a test can assert how many frames a sender produced rather than
trusting the sender's own idea of a frame.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from typing import Literal

Framing = Literal["octet-counting", "lf"]

_OCTET = re.compile(rb"([1-9][0-9]*) ")


def split_frames(raw: bytes, framing: Framing) -> tuple[list[bytes], bytes]:
    """Complete frames in ``raw`` and the incomplete remainder."""
    frames: list[bytes] = []
    if framing == "lf":
        *complete, rest = raw.split(b"\n")
        return complete, rest
    pos = 0
    while True:
        match = _OCTET.match(raw, pos)
        if match is None:
            break
        length = int(match.group(1))
        start = match.end()
        if start + length > len(raw):
            break
        frames.append(raw[start : start + length])
        pos = start + length
    return frames, raw[pos:]


class StreamCollector:
    """A TCP (or, with ``ssl``, TLS) collector that records raw bytes and frames."""

    def __init__(self, framing: Framing = "octet-counting", ssl: ssl.SSLContext | None = None):
        self.framing = framing
        self.ssl = ssl
        self.raw = bytearray()
        self.connections = 0
        self.handshake_failures = 0
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._changed = asyncio.Event()
        self.port = 0

    @property
    def frames(self) -> list[bytes]:
        return split_frames(bytes(self.raw), self.framing)[0]

    async def start(self, port: int = 0) -> int:
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", port or self.port, ssl=self.ssl
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        """Stop listening and drop every open connection, as a stopped collector would."""
        if self._server is not None:
            self._server.close()
            for writer in list(self._writers):
                writer.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        self._writers.add(writer)
        try:
            while data := await reader.read(65536):
                self.raw += data
                self._changed.set()
        except (ssl.SSLError, ConnectionError):
            self.handshake_failures += 1
        finally:
            self._writers.discard(writer)
            writer.close()

    async def wait_for_frames(self, count: int, timeout: float = 10.0) -> list[bytes]:
        async with asyncio.timeout(timeout):
            while len(self.frames) < count:
                self._changed.clear()
                if len(self.frames) >= count:
                    break
                await self._changed.wait()
        return self.frames


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, sink: list[bytes], changed: asyncio.Event) -> None:
        self.sink = sink
        self.changed = changed

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        self.sink.append(data)
        self.changed.set()


class UdpCollector:
    def __init__(self) -> None:
        self.datagrams: list[bytes] = []
        self._changed = asyncio.Event()
        self._transport: asyncio.DatagramTransport | None = None
        self.port = 0

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self.datagrams, self._changed), local_addr=("127.0.0.1", 0)
        )
        self._transport = transport
        self.port = transport.get_extra_info("sockname")[1]
        return self.port

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()

    async def wait_for(self, count: int, timeout: float = 10.0) -> list[bytes]:
        async with asyncio.timeout(timeout):
            while len(self.datagrams) < count:
                self._changed.clear()
                await self._changed.wait()
        return self.datagrams


class BlackholeCollector:
    """Accepts connections and never reads, so a sender's buffers fill and stall."""

    def __init__(self) -> None:
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []
        self.port = 0

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.transport.pause_reading()
        self._writers.append(writer)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            for writer in self._writers:
                writer.close()
            await self._server.wait_closed()
