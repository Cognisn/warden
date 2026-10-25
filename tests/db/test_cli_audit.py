"""The warden CLI: audit verify and audit purge against a real database."""

from __future__ import annotations

import copy
from typing import Any

import psycopg
import pytest

from chain_support import age, stored
from warden.audit.retention import MIN_RETENTION_DAYS
from warden.cli import main

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
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


def _settings(dsn: str | None, **audit: Any) -> FakeSettings:
    warden: dict[str, Any] = {"http": dict(HTTP)}
    if dsn is not None:
        warden["db"] = {"dsn": dsn}
    if audit:
        warden["audit"] = audit
    return FakeSettings({"warden": warden})


def _seed(dsn: str, rows: int = 3) -> None:
    from warden.audit.chain import GENESIS_HASH, ChainRow, row_hash

    with psycopg.connect(dsn) as conn:
        prev = GENESIS_HASH
        for _ in range(rows):
            cur = conn.execute(
                "SELECT nextval(pg_get_serial_sequence('warden.audit_events', 'id')),"
                " clock_timestamp()"
            )
            row_id, now = cur.fetchone()  # type: ignore[misc]
            fields = ChainRow(
                id=row_id, prev_hash=prev, recorded_at=now, occurred_at=now, actor=None,
                action="product.seed", resource_type=None, resource_id=None,
                outcome="success", source_ip=None, details={}, key_id=None,
            )  # fmt: skip
            new = row_hash(fields)
            conn.execute(
                "INSERT INTO warden.audit_events (id, recorded_at, occurred_at, action, outcome,"
                " prev_hash, row_hash) OVERRIDING SYSTEM VALUE"
                " VALUES (%s, %s, %s, 'product.seed', 'success', %s, %s)",
                (row_id, now, now, prev, new),
            )
            prev = new


def test_verify_reports_an_intact_chain(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn)
    assert main(["audit", "verify"], settings=_settings(migrated_dsn), secrets=FakeSecrets()) == 0
    out = capsys.readouterr().out
    assert "intact" in out and "3 rows" in out


def test_verify_names_the_first_broken_row_and_exits_1(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn)
    with psycopg.connect(migrated_dsn) as conn:
        row = conn.execute("SELECT max(id) FROM warden.audit_events").fetchone()
        assert row is not None
        conn.execute("UPDATE warden.audit_events SET actor = 'mallory' WHERE id = %s", row)
    assert main(["audit", "verify"], settings=_settings(migrated_dsn), secrets=FakeSecrets()) == 1
    out = capsys.readouterr().out
    assert f"broken at row {row[0]}" in out
    assert "mallory" not in out


def test_purge_uses_the_configured_retention_and_signs_a_checkpoint(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets = FakeSecrets()
    settings = _settings(migrated_dsn, retention_days=MIN_RETENTION_DAYS)
    assert main(["keys", "rotate"], settings=settings, secrets=secrets) == 0
    _seed(migrated_dsn)
    age(migrated_dsn, None, MIN_RETENTION_DAYS + 10)

    assert main(["audit", "purge", "--actor", "ops-1"], settings=settings, secrets=secrets) == 0
    assert "purged 3 audit rows" in capsys.readouterr().out
    rows = stored(migrated_dsn)
    assert [(r.action, r.actor) for r in rows] == [("warden.audit.purge", "ops-1")]
    assert main(["audit", "verify"], settings=settings, secrets=secrets) == 0


def test_purge_with_nothing_old_enough(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(migrated_dsn, retention_days=MIN_RETENTION_DAYS)
    _seed(migrated_dsn)
    assert main(["audit", "purge"], settings=settings, secrets=FakeSecrets()) == 0
    assert "nothing to purge" in capsys.readouterr().out


def test_purge_without_a_retention_period_is_a_configuration_error(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["audit", "purge"], settings=_settings(migrated_dsn), secrets=FakeSecrets()) == 2
    assert "warden.audit.retention_days" in capsys.readouterr().err


def test_purge_below_the_minimum_is_refused(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(migrated_dsn, retention_days=30)
    assert main(["audit", "purge"], settings=settings, secrets=FakeSecrets()) == 1
    assert "minimum" in capsys.readouterr().err
