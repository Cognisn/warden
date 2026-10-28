"""The warden CLI: audit anchor, and audit verify --anchors, against a real database."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import psycopg
import pytest

from chain_support import stored
from warden.audit.actions import ANCHOR_ACTION
from warden.audit.anchor import Anchor
from warden.audit.export import row_to_json
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


def _settings(dsn: str) -> FakeSettings:
    return FakeSettings({"warden": {"http": dict(HTTP), "db": {"dsn": dsn}}})


def _seed(dsn: str, rows: int = 3) -> None:
    from warden.audit.chain import GENESIS_HASH, ChainRow, row_hash

    with psycopg.connect(dsn) as conn:
        found = conn.execute(
            "SELECT row_hash FROM warden.audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev = GENESIS_HASH if found is None else bytes(found[0])
        for _ in range(rows):
            cur = conn.execute(
                "SELECT nextval(pg_get_serial_sequence('warden.audit_events', 'id')),"
                " clock_timestamp()"
            )
            row_id, now = cur.fetchone()  # type: ignore[misc]
            fields = ChainRow(
                id=row_id, prev_hash=prev, recorded_at=now, occurred_at=now, actor="mallory",
                action="product.seed", resource_type=None, resource_id=None,
                outcome="success", source_ip=None, details={}, key_id=None,
            )  # fmt: skip
            new = row_hash(fields)
            conn.execute(
                "INSERT INTO warden.audit_events (id, recorded_at, occurred_at, actor, action,"
                " outcome, prev_hash, row_hash) OVERRIDING SYSTEM VALUE"
                " VALUES (%s, %s, %s, 'mallory', 'product.seed', 'success', %s, %s)",
                (row_id, now, now, prev, new),
            )
            prev = new


def _export(dsn: str, path: Path) -> None:
    """The whole trail as NDJSON, the way a SIEM export of warden's export would hold it."""
    lines = [json.dumps(row_to_json(row), ensure_ascii=True) for row in stored(dsn)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


@pytest.fixture
def secrets(migrated_dsn: str) -> FakeSecrets:
    secrets = FakeSecrets()
    assert main(["keys", "rotate"], settings=_settings(migrated_dsn), secrets=secrets) == 0
    return secrets


def test_anchor_writes_a_signed_anchor_row(
    migrated_dsn: str, secrets: FakeSecrets, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn)
    capsys.readouterr()
    argv = ["audit", "anchor", "--actor", "scheduler"]
    assert main(argv, settings=_settings(migrated_dsn), secrets=secrets) == 0
    rows = stored(migrated_dsn)
    carrier = rows[-1]
    assert (carrier.action, carrier.actor) == (ANCHOR_ACTION, "scheduler")
    written = Anchor.from_details(carrier.details)
    assert capsys.readouterr().out.strip() == (
        f"anchored head row {written.head_id} in audit row {carrier.id}"
    )
    assert written.head_id == rows[-2].id


def test_anchor_on_an_empty_trail_writes_nothing(
    migrated_dsn: str, secrets: FakeSecrets, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    assert main(["audit", "anchor"], settings=_settings(migrated_dsn), secrets=secrets) == 0
    assert "nothing to anchor" in capsys.readouterr().out
    assert stored(migrated_dsn) == []


def test_anchor_with_min_rows_waits_for_enough_rows(
    migrated_dsn: str, secrets: FakeSecrets, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn, rows=2)
    argv = ["audit", "anchor", "--min-rows", "3"]
    assert main(argv, settings=_settings(migrated_dsn), secrets=secrets) == 0
    assert "nothing to anchor" in capsys.readouterr().out
    _seed(migrated_dsn, rows=1)
    assert main(argv, settings=_settings(migrated_dsn), secrets=secrets) == 0
    assert "anchored head row" in capsys.readouterr().out


def test_anchor_without_a_signing_key_exits_1(
    migrated_dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn)
    assert main(["audit", "anchor"], settings=_settings(migrated_dsn), secrets=FakeSecrets()) == 1
    assert "warden keys rotate" in capsys.readouterr().err


def test_verify_against_exported_anchors(
    migrated_dsn: str, secrets: FakeSecrets, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn)
    settings = _settings(migrated_dsn)
    assert main(["audit", "anchor"], settings=settings, secrets=secrets) == 0
    _seed(migrated_dsn, rows=2)
    exported = tmp_path / "siem.ndjson"
    _export(migrated_dsn, exported)
    capsys.readouterr()

    argv = ["audit", "verify", "--anchors", str(exported)]
    assert main(argv, settings=settings, secrets=secrets) == 0
    out = capsys.readouterr().out
    assert "audit chain intact" in out
    assert "anchors: 1 checked, 1 matched, 0 behind checkpoints, 0 failed" in out


def test_verify_names_a_deleted_tail_without_row_contents(
    migrated_dsn: str, secrets: FakeSecrets, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn)
    settings = _settings(migrated_dsn)
    assert main(["audit", "anchor"], settings=settings, secrets=secrets) == 0
    exported = tmp_path / "siem.ndjson"
    _export(migrated_dsn, exported)
    head = Anchor.from_details(stored(migrated_dsn)[-1].details).head_id
    with psycopg.connect(migrated_dsn) as conn:
        conn.execute("DELETE FROM warden.audit_events WHERE id >= %s", (head,))
    capsys.readouterr()

    argv = ["audit", "verify", "--anchors", str(exported)]
    assert main(argv, settings=settings, secrets=secrets) == 1
    out = capsys.readouterr().out
    assert "audit chain intact" in out
    assert "1 failed" in out
    assert f"anchor on line 4 (head row {head}): the row at head_id is missing" in out
    assert "mallory" not in out


def test_verify_with_a_file_holding_no_anchors_exits_1(
    migrated_dsn: str, secrets: FakeSecrets, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(migrated_dsn)
    exported = tmp_path / "siem.ndjson"
    _export(migrated_dsn, exported)
    argv = ["audit", "verify", "--anchors", str(exported)]
    assert main(argv, settings=_settings(migrated_dsn), secrets=secrets) == 1
    assert "no anchors found" in capsys.readouterr().err


def test_verify_with_an_unreadable_anchors_file_is_a_usage_error(
    migrated_dsn: str, secrets: FakeSecrets, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["audit", "verify", "--anchors", str(tmp_path / "missing.ndjson")]
    assert main(argv, settings=_settings(migrated_dsn), secrets=secrets) == 2
    err = capsys.readouterr().err
    assert "cannot read the anchors file" in err
    assert str(tmp_path) not in err
