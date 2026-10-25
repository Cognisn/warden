"""Live check: the forwarder against a real rsyslog collector over UDP, TCP and TLS.

Marked ``integration`` (skipped by default). Start the collector from
``tests/syslogfwd/live`` (see its compose file) on the slot's own ports and
point the test at it:

    WARDEN_IT_SANDBOX         directory holding certs/ and syslog-out/
    WARDEN_IT_SYSLOG_PORT     UDP and TCP port
    WARDEN_IT_SYSLOG_TLS_PORT TLS port

Each case records audit events with a unique marker and waits for the
collector's own log of what it received, so framing, MSGID and neutralisation
are judged by a real receiver, not by warden's own parser.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from syslogfwd.certs import Authority
from warden.audit import ActionRegistry, AuditEvent, AuditRecorder, Severity
from warden.audit.syslog import SyslogForwarder, SyslogSettings
from warden.db import Database

pytestmark = [pytest.mark.integration, pytest.mark.db]

SANDBOX = os.environ.get("WARDEN_IT_SANDBOX")
PORT = os.environ.get("WARDEN_IT_SYSLOG_PORT")
TLS_PORT = os.environ.get("WARDEN_IT_SYSLOG_TLS_PORT")

if not (SANDBOX and PORT and TLS_PORT):
    pytest.skip("live collector not configured", allow_module_level=True)

assert SANDBOX and PORT and TLS_PORT
OUT = Path(SANDBOX) / "syslog-out"
CA_FILE = Path(SANDBOX) / "certs" / "ca.pem"

CASES = [
    pytest.param("udp", "octet-counting", int(PORT), "udp.log", id="udp"),
    pytest.param("tcp", "octet-counting", int(PORT), "tcp.log", id="tcp-octet-counting"),
    pytest.param("tcp", "lf", int(PORT), "tcp.log", id="tcp-lf"),
    pytest.param("tls", "octet-counting", int(TLS_PORT), "tls.log", id="tls-octet-counting"),
    pytest.param("tls", "lf", int(TLS_PORT), "tls.log", id="tls-lf"),
]


def _lines_with(path: Path, marker: str) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text("utf-8", "replace").splitlines() if marker in line]


async def _wait_for_lines(path: Path, marker: str, count: int, timeout: float = 20) -> list[str]:
    deadline = time.monotonic() + timeout
    while True:
        lines = _lines_with(path, marker)
        if len(lines) >= count or time.monotonic() > deadline:
            return lines
        await asyncio.sleep(0.2)


@pytest.mark.parametrize(("transport", "framing", "port", "logfile"), CASES)
async def test_the_forwarder_delivers_to_a_real_collector(
    pool: Any, transport: Any, framing: Any, port: int, logfile: str
) -> None:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    db = Database(pool)
    recorder = AuditRecorder(db, registry)
    settings = SyslogSettings(
        host="127.0.0.1",
        port=port,
        transport=transport,
        framing=framing,
        sd_id="warden@99999",
        hostname="app-1.example.com",
        tls_ca_file=str(CA_FILE),
        tls_server_name="localhost",
        poll_seconds=0.5,
        grace_seconds=0.5,
        connect_timeout_seconds=5,
    )
    marker = "m" + uuid.uuid4().hex[:12]
    forwarder = SyslogForwarder(db, settings, registry)
    await forwarder.start()
    try:
        for _ in range(100):
            if forwarder.snapshot().role == "leader":
                break
            await asyncio.sleep(0.05)
        ids = [
            await recorder.record(
                AuditEvent(action="product.export", outcome="success", actor=f"{marker}-{n}")
            )
            for n in range(5)
        ]
        # A hostile value: under LF framing an unneutralised newline would
        # forge a second record with the marker in it.
        hostile = await recorder.record(
            AuditEvent(
                action="product.export",
                outcome="failure",
                actor=f"{marker}-x\n<13>1 - forged - - - {marker}-forged\r",
            )
        )
        lines = await _wait_for_lines(OUT / logfile, marker, 6)
    finally:
        await forwarder.stop()

    assert len(lines) == 6, lines
    assert [int(line.split(" ", 1)[0]) for line in lines] == [*ids, hostile]
    assert not any(line.startswith(f"{marker}-forged") for line in lines)
    assert "\\x0a" in lines[-1]
    status = await forwarder.status()
    assert status.lag == 0


async def test_tls_to_a_real_collector_fails_closed_with_the_wrong_ca(pool: Any) -> None:
    registry = ActionRegistry()
    registry.register("product.export", severity=Severity.NOTICE, summary="{actor} exported")
    db = Database(pool)
    settings = SyslogSettings(
        host="127.0.0.1",
        port=int(TLS_PORT),
        transport="tls",
        sd_id="warden@99999",
        tls_ca_pem=Authority("not the collector's CA").pem,
        tls_server_name="localhost",
        poll_seconds=0.5,
        connect_timeout_seconds=5,
    )
    marker = "m" + uuid.uuid4().hex[:12]
    forwarder = SyslogForwarder(db, settings, registry)
    await forwarder.start()
    try:
        for _ in range(100):
            if forwarder.snapshot().role == "leader":
                break
            await asyncio.sleep(0.05)
        await AuditRecorder(db, registry).record(
            AuditEvent(action="product.export", outcome="success", actor=marker)
        )
        for _ in range(100):
            if forwarder.snapshot().last_error is not None:
                break
            await asyncio.sleep(0.1)
        await asyncio.sleep(1)
    finally:
        await forwarder.stop()
    assert forwarder.snapshot().last_error == "certificate verification failed"
    assert _lines_with(OUT / "tls.log", marker) == []
    assert (await forwarder.status()).lag == 1
