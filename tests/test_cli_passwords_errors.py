"""warden passwords import and recheck fail cleanly without a database or a readable file."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from warden.cli import PASSWORDS_CONNECTION_FAILED, main

# Port 1 on loopback refuses at once; no database is needed for these tests.
UNREACHABLE = "postgresql://warden:pw-not-a-secret@127.0.0.1:1/warden_example?connect_timeout=5"
LEAKY = ("pw-not-a-secret", "127.0.0.1", "warden_example", "Traceback")


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


def _settings() -> FakeSettings:
    return FakeSettings(
        {
            "warden": {
                "http": {
                    "public_base_url": "https://app.example.com",
                    "accept_invitation_link": "/accept/{token}",
                    "reset_password_link": "/reset/{token}",
                },
                "db": {"dsn": UNREACHABLE},
            }
        }
    )


@pytest.fixture
def hibp_file(tmp_path: Path) -> Path:
    path = tmp_path / "pwned.txt"
    path.write_text(f"{'A' * 40}:3\n", encoding="ascii", newline="\n")
    return path


@pytest.mark.parametrize(
    "argv",
    [
        ["passwords", "import", "--list", "Breaches", "--file", "{file}"],
        ["passwords", "import", "--list", "Breaches", "--file", "{file}", "--create",
         "--reason", "Seen in a breach"],
        ["passwords", "recheck"],
        ["passwords", "recheck", "--policy", "Strict", "--end-sessions-override", "off"],
    ],
)  # fmt: skip
def test_a_connection_failure_prints_a_fixed_message_and_exits_1(
    argv: list[str], hibp_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = [a.replace("{file}", str(hibp_file)) for a in argv]
    assert main(args, settings=_settings(), secrets=FakeSecrets()) == 1
    captured = capsys.readouterr()
    assert captured.err == PASSWORDS_CONNECTION_FAILED + "\n"
    assert captured.out == ""
    for fragment in LEAKY:
        assert fragment not in captured.err


def test_an_unreadable_file_is_refused_before_connecting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "secret-name-of-a-file.txt"
    argv = ["passwords", "import", "--list", "Breaches", "--file", str(missing)]
    assert main(argv, settings=_settings(), secrets=FakeSecrets()) == 2
    captured = capsys.readouterr()
    assert captured.err == "warden passwords import: cannot read the import file\n"
    assert "secret-name-of-a-file" not in captured.err


def test_create_needs_a_reason(hibp_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["passwords", "import", "--list", "Breaches", "--file", str(hibp_file), "--create"]
    assert main(argv, settings=_settings(), secrets=FakeSecrets()) == 2
    assert "--create needs --reason" in capsys.readouterr().err


def test_the_override_takes_only_off(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        main(["passwords", "recheck", "--end-sessions-override", "on"], settings=_settings())
    assert exited.value.code == 2


def test_the_threshold_must_be_positive(hibp_file: Path) -> None:
    argv = ["passwords", "import", "--list", "B", "--file", str(hibp_file), "--threshold", "0"]
    with pytest.raises(SystemExit) as exited:
        main(argv, settings=_settings())
    assert exited.value.code == 2
