"""The warden audit CLI without a database: connection failures and grants."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from warden.audit.actions import ANCHOR_ACTION
from warden.audit.anchor import Anchor
from warden.audit.retention import MIN_RETENTION_DAYS
from warden.cli import AUDIT_CONNECTION_FAILED, main

# Port 1 on loopback refuses at once; no database is needed for these tests.
UNREACHABLE = "postgresql://warden:pw-not-a-secret@127.0.0.1:1/warden_example?connect_timeout=2"

HTTP = {
    "public_base_url": "https://app.example.com",
    "accept_invitation_link": "/accept/{token}",
    "reset_password_link": "/reset/{token}",
}


class FakeSettings:
    def __init__(self, tree: dict[str, Any]) -> None:
        self._tree = tree

    def get_section(self, prefix: str) -> dict[str, Any]:
        return copy.deepcopy(self._tree.get(prefix, {}))


class FakeSecrets:
    def get(self, key: str) -> str | None:
        return None

    def set(self, key: str, value: str) -> None:
        raise AssertionError("audit commands must not write secrets")


def _settings(dsn: str | None) -> FakeSettings:
    warden: dict[str, Any] = {"http": dict(HTTP), "audit": {"retention_days": MIN_RETENTION_DAYS}}
    if dsn is not None:
        warden["db"] = {"dsn": dsn}
    return FakeSettings({"warden": warden})


def _anchors_file(directory: Path) -> str:
    """One synthetic anchor row, as an NDJSON export holds it."""
    anchor = Anchor(
        head_id=3,
        head_hash=bytes(32),
        anchored_at=datetime(2026, 10, 28, tzinfo=UTC),
        key_id="k-example",
        signature=bytes(64),
    )
    path = directory / "anchors.ndjson"
    row = {"id": 4, "action": ANCHOR_ACTION, "details": anchor.to_details()}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8", newline="\n")
    return str(path)


@pytest.mark.parametrize(
    "command",
    [
        ["audit", "verify"],
        ["audit", "purge"],
        ["audit", "anchor"],
        ["audit", "verify", "--anchors", "{anchors}"],
    ],
)
def test_connection_failure_prints_a_fixed_message_and_exits_1(
    command: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    command = [_anchors_file(tmp_path) if arg == "{anchors}" else arg for arg in command]
    assert main(command, settings=_settings(UNREACHABLE), secrets=FakeSecrets()) == 1
    captured = capsys.readouterr()
    assert captured.err.splitlines() == [AUDIT_CONNECTION_FAILED]
    assert captured.out == ""
    for fragment in ("pw-not-a-secret", "127.0.0.1", "warden_example", "Traceback"):
        assert fragment not in captured.err


def test_grants_prints_sql_without_needing_a_database(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["audit", "grants", "--app-role", "app", "--forwarder-role", "fwd", "--purger-role", "p"]
    assert main(argv, settings=_settings(None), secrets=FakeSecrets()) == 0
    out = capsys.readouterr().out
    assert 'REVOKE UPDATE, DELETE ON "warden"."audit_events" FROM "app"' in out
    assert 'GRANT SELECT ON "warden"."audit_events" TO "fwd"' in out
    assert 'GRANT SELECT, INSERT, DELETE ON "warden"."audit_events" TO "p"' in out


def test_grants_refuses_a_shared_role(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["audit", "grants", "--app-role", "app", "--purger-role", "app"]
    assert main(argv, settings=_settings(None), secrets=FakeSecrets()) == 2
    assert "distinct" in capsys.readouterr().err


def test_anchor_refuses_an_actor_too_long_to_forward_whole(
    capsys: pytest.CaptureFixture[str],
) -> None:
    argv = ["audit", "anchor", "--actor", "a" * 65]
    with pytest.raises(SystemExit) as exited:
        main(argv, settings=_settings(UNREACHABLE), secrets=FakeSecrets())
    assert exited.value.code == 2
    assert "at most 64" in capsys.readouterr().err
