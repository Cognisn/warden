"""The warden CLI fails cleanly when it cannot reach the database."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from warden.cli import KEYS_CONNECTION_FAILED, MIGRATE_CONNECTION_FAILED, main

# Port 1 on loopback refuses at once; no database is needed for this test.
UNREACHABLE = "postgresql://warden:pw-not-a-secret@127.0.0.1:1/warden_example?connect_timeout=5"


class FakeSettings:
    def __init__(self, tree: dict[str, Any]) -> None:
        self._tree = tree

    def get_section(self, prefix: str) -> dict[str, Any]:
        return copy.deepcopy(self._tree.get(prefix, {}))


class FakeSecrets:
    def get(self, key: str) -> str | None:
        return None

    def set(self, key: str, value: str) -> None:
        raise AssertionError("an unreachable database must not lead to a secret write")


def _settings(dsn: str) -> FakeSettings:
    return FakeSettings(
        {
            "warden": {
                "http": {
                    "public_base_url": "https://app.example.com",
                    "accept_invitation_link": "/accept/{token}",
                    "reset_password_link": "/reset/{token}",
                },
                "db": {"dsn": dsn},
            }
        }
    )


def test_migrate_connection_failure_prints_a_fixed_message_and_exits_1(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["migrate"], settings=_settings(UNREACHABLE), secrets=FakeSecrets()) == 1
    captured = capsys.readouterr()
    assert captured.err == MIGRATE_CONNECTION_FAILED + "\n"
    assert captured.out == ""
    for fragment in ("pw-not-a-secret", "127.0.0.1", "warden_example", "Traceback"):
        assert fragment not in captured.err


def test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1(
    capsys: pytest.CaptureFixture[str],
) -> None:
    argv = ["keys", "rotate"]
    assert main(argv, settings=_settings(UNREACHABLE), secrets=FakeSecrets()) == 1
    captured = capsys.readouterr()
    assert captured.err == KEYS_CONNECTION_FAILED + "\n"
    assert captured.out == ""
    for fragment in ("pw-not-a-secret", "127.0.0.1", "warden_example", "Traceback"):
        assert fragment not in captured.err
