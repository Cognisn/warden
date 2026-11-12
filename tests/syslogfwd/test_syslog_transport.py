"""Transports: UDP, TCP and TLS, octet-counting or LF framing; TLS fails closed."""

from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from syslogfwd.certs import Authority, server_context
from syslogfwd.collector import BlackholeCollector, StreamCollector, UdpCollector
from warden.audit.syslog import (
    AuditRecord,
    SyslogSettings,
    TransportError,
    format_message,
    frame,
    open_transport,
    tls_context,
)


def _settings(port: int, **kw: Any) -> SyslogSettings:
    values: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port,
        "transport": "tcp",
        "sd_id": "warden@99999",
        "hostname": "app-1.example.com",
        "connect_timeout_seconds": 5,
        "send_timeout_seconds": 5,
    }
    values.update(kw)
    return SyslogSettings(**values)


INJECTION = "alice\n<13>1 2026-10-25T00:00:00Z forged - - - - pwned\r\n\x00\x1b\x85"


def _hostile_record(row_id: int = 7) -> AuditRecord:
    return AuditRecord(
        id=row_id,
        occurred_at=datetime(2026, 10, 25, tzinfo=UTC),
        action="product.export",
        outcome="failure",
        actor=INJECTION,
        resource_id=INJECTION,
        details={"username": INJECTION},
    )


# --- framing -----------------------------------------------------------------


def test_octet_counting_prefixes_the_byte_length() -> None:
    assert frame("héllo".encode(), "octet-counting") == b"6 h\xc3\xa9llo"


def test_lf_framing_appends_a_newline() -> None:
    assert frame(b"hello", "lf") == b"hello\n"


def test_lf_framing_refuses_a_message_that_holds_a_newline() -> None:
    with pytest.raises(ValueError):
        frame(b"two\nframes", "lf")


# --- TCP -------------------------------------------------------------------


@pytest.mark.parametrize("framing", ["octet-counting", "lf"])
async def test_tcp_delivers_framed_messages(framing: Any) -> None:
    collector = StreamCollector(framing)
    port = await collector.start()
    transport = await open_transport(_settings(port, framing=framing))
    try:
        await transport.send(b"<14>1 - - - - - - first")
        await transport.send(b"<14>1 - - - - - - second")
        frames = await collector.wait_for_frames(2)
    finally:
        await transport.close()
        await collector.stop()
    assert frames == [b"<14>1 - - - - - - first", b"<14>1 - - - - - - second"]


@pytest.mark.parametrize("framing", ["octet-counting", "lf"])
async def test_a_hostile_value_produces_exactly_one_frame(framing: Any) -> None:
    """The LF-injection test: control characters in values cannot forge a frame."""
    collector = StreamCollector(framing)
    port = await collector.start()
    settings = _settings(port, framing=framing)
    transport = await open_transport(settings)
    try:
        await transport.send(format_message(_hostile_record(), settings))
        await asyncio.sleep(0.2)
        frames = await collector.wait_for_frames(1)
    finally:
        await transport.close()
        await collector.stop()
    assert len(frames) == 1
    assert frames[0].startswith(b"<")
    raw = bytes(collector.raw)
    if framing == "lf":
        assert raw.count(b"\n") == 1 and raw.endswith(b"\n")
    else:
        assert raw == frame(frames[0], "octet-counting")
    assert not any(b < 0x20 or b == 0x7F for b in frames[0])


async def test_a_refused_connection_raises_a_transport_error() -> None:
    collector = StreamCollector()
    port = await collector.start()
    await collector.stop()
    with pytest.raises(TransportError) as raised:
        await open_transport(_settings(port))
    assert raised.value.category == "connection refused"


async def test_sending_after_the_collector_closed_raises() -> None:
    collector = StreamCollector()
    port = await collector.start()
    transport = await open_transport(_settings(port))
    try:
        await transport.send(b"<14>1 - - - - - - before")
        await collector.wait_for_frames(1)
        await collector.stop()
        await asyncio.sleep(0.2)
        with pytest.raises(TransportError):
            await transport.send(b"<14>1 - - - - - - after")
    finally:
        await transport.close()


async def test_a_collector_that_stops_reading_times_out_the_send() -> None:
    blackhole = BlackholeCollector()
    port = await blackhole.start()
    transport = await open_transport(_settings(port, send_timeout_seconds=0.3))
    message = b"<14>1 - - - - - - " + b"x" * 8000
    try:
        with pytest.raises(TransportError) as raised:
            async with asyncio.timeout(60):
                while True:
                    await transport.send(message)
        assert raised.value.category == "timeout"
    finally:
        await transport.close()
        await blackhole.stop()


async def test_close_is_idempotent() -> None:
    collector = StreamCollector()
    port = await collector.start()
    transport = await open_transport(_settings(port))
    await transport.close()
    await transport.close()
    await collector.stop()


# --- UDP ---------------------------------------------------------------------


async def test_udp_sends_one_message_per_datagram_without_framing() -> None:
    collector = UdpCollector()
    port = await collector.start()
    transport = await open_transport(_settings(port, transport="udp", framing="lf"))
    try:
        await transport.send(b"<14>1 - - - - - - one")
        await transport.send(b"<14>1 - - - - - - two")
        datagrams = await collector.wait_for(2)
    finally:
        await transport.close()
        await collector.stop()
    assert datagrams == [b"<14>1 - - - - - - one", b"<14>1 - - - - - - two"]


# --- TLS ---------------------------------------------------------------------


@pytest.fixture
def authority() -> Authority:
    return Authority()


async def _tls_collector(authority: Authority, tmp_path: Path, *names: str) -> StreamCollector:
    issued = authority.issue(*(names or ("localhost", "127.0.0.1")))
    collector = StreamCollector(ssl=server_context(issued, tmp_path))
    await collector.start()
    return collector


async def test_tls_delivers_with_the_right_ca(authority: Authority, tmp_path: Path) -> None:
    collector = await _tls_collector(authority, tmp_path)
    settings = _settings(collector.port, transport="tls", tls_ca_pem=authority.pem)
    transport = await open_transport(settings)
    try:
        await transport.send(b"<14>1 - - - - - - secure")
        frames = await collector.wait_for_frames(1)
    finally:
        await transport.close()
        await collector.stop()
    assert frames == [b"<14>1 - - - - - - secure"]


async def test_tls_accepts_a_ca_file(authority: Authority, tmp_path: Path) -> None:
    collector = await _tls_collector(authority, tmp_path)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text(authority.pem, encoding="utf-8")
    settings = _settings(collector.port, transport="tls", tls_ca_file=str(ca_file))
    transport = await open_transport(settings)
    try:
        await transport.send(b"<14>1 - - - - - - secure")
        assert await collector.wait_for_frames(1) == [b"<14>1 - - - - - - secure"]
    finally:
        await transport.close()
        await collector.stop()


async def test_tls_refuses_a_certificate_from_another_ca(
    authority: Authority, tmp_path: Path
) -> None:
    collector = await _tls_collector(authority, tmp_path)
    other = Authority("some other CA")
    settings = _settings(collector.port, transport="tls", tls_ca_pem=other.pem)
    try:
        with pytest.raises(TransportError) as raised:
            await open_transport(settings)
        await asyncio.sleep(0.2)
    finally:
        await collector.stop()
    assert raised.value.category == "certificate verification failed"
    assert collector.raw == b""


async def test_tls_refuses_a_certificate_for_another_name(
    authority: Authority, tmp_path: Path
) -> None:
    collector = await _tls_collector(authority, tmp_path, "collector.example.com")
    settings = _settings(
        collector.port,
        transport="tls",
        tls_ca_pem=authority.pem,
        tls_server_name="other.example.com",
    )
    try:
        with pytest.raises(TransportError) as raised:
            await open_transport(settings)
    finally:
        await collector.stop()
    assert raised.value.category == "certificate verification failed"
    assert collector.raw == b""


async def test_tls_checks_the_configured_server_name(authority: Authority, tmp_path: Path) -> None:
    collector = await _tls_collector(authority, tmp_path, "collector.example.com")
    settings = _settings(
        collector.port,
        transport="tls",
        tls_ca_pem=authority.pem,
        tls_server_name="collector.example.com",
    )
    transport = await open_transport(settings)
    try:
        await transport.send(b"<14>1 - - - - - - named")
        assert await collector.wait_for_frames(1) == [b"<14>1 - - - - - - named"]
    finally:
        await transport.close()
        await collector.stop()


async def test_tls_never_falls_back_to_plaintext(authority: Authority, tmp_path: Path) -> None:
    plain = StreamCollector()
    port = await plain.start()
    settings = _settings(port, transport="tls", tls_ca_pem=authority.pem)
    try:
        with pytest.raises(TransportError):
            async with asyncio.timeout(10):
                await open_transport(settings.model_copy(update={"connect_timeout_seconds": 2}))
        await asyncio.sleep(0.2)
    finally:
        await plain.stop()
    # At most a TLS ClientHello (record type 0x16) reached the plaintext
    # listener; the connection was never used for syslog.
    raw = bytes(plain.raw)
    assert raw[:1] in (b"", bytes([0x16]))


def test_tls_context_verifies_and_checks_hostnames(authority: Authority) -> None:
    context = tls_context(_settings(1, transport="tls", tls_ca_pem=authority.pem))
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
