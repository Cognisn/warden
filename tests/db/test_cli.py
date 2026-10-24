"""The warden CLI: migrate and keys rotate."""

from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path
from typing import Any

import psycopg
import pytest

from warden.cli import main
from warden.db import current_revision, heads

pytestmark = pytest.mark.db

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
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = dict(values or {})

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


def _settings(dsn: str | None) -> FakeSettings:
    warden: dict[str, Any] = {"http": dict(HTTP)}
    if dsn is not None:
        warden["db"] = {"dsn": dsn}
    return FakeSettings({"warden": warden})


def test_migrate_upgrades_to_head(dsn: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["migrate"], settings=_settings(dsn), secrets=FakeSecrets()) == 0
    assert current_revision(dsn) == heads()[0]
    assert heads()[0] in capsys.readouterr().out


def test_migrate_reads_the_dsn_through_a_secret_reference(dsn: str) -> None:
    secrets = FakeSecrets({"warden-db": dsn})
    assert main(["migrate"], settings=_settings("secret://warden-db"), secrets=secrets) == 0
    assert current_revision(dsn) == heads()[0]


def test_migrate_without_a_dsn_fails_naming_the_field(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["migrate"], settings=_settings(None), secrets=FakeSecrets()) == 2
    assert "warden.db.dsn" in capsys.readouterr().err


def test_invalid_configuration_fails_before_doing_anything(
    dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = FakeSettings({"warden": {"db": {"dsn": dsn}}})
    assert main(["migrate"], settings=settings, secrets=FakeSecrets()) == 2
    assert "warden.http" in capsys.readouterr().err
    assert current_revision(dsn) is None


def test_keys_rotate_adds_a_key_and_prints_only_its_id(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets = FakeSecrets()
    assert main(["keys", "rotate"], settings=_settings(migrated_dsn), secrets=secrets) == 0
    with psycopg.connect(migrated_dsn) as conn:
        rows = conn.execute("SELECT key_id FROM warden.signing_keys").fetchall()
    assert len(rows) == 1
    (key_id,) = rows[0]
    out = capsys.readouterr().out
    assert key_id in out
    for value in secrets.values.values():
        assert value not in out


def test_keys_rotate_twice_keeps_both_keys(migrated_dsn: str) -> None:
    secrets = FakeSecrets()
    for _ in range(2):
        assert main(["keys", "rotate"], settings=_settings(migrated_dsn), secrets=secrets) == 0
    with psycopg.connect(migrated_dsn) as conn:
        (count,) = conn.execute(
            "SELECT count(*) FROM warden.signing_keys WHERE retired_at IS NULL"
        ).fetchone() or (0,)
    assert count == 2


def test_console_script_runs_migrate_from_a_config_file(dsn: str, tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        "warden:\n"
        "  http:\n"
        "    public_base_url: https://app.example.com\n"
        "    accept_invitation_link: /accept/{token}\n"
        "    reset_password_link: /reset/{token}\n"
        f"  db:\n    dsn: {dsn}\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "warden.cli", "--config", str(config), "migrate"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert current_revision(dsn) == heads()[0]
