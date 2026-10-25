"""Forwarder settings: built from ``SyslogConfig``, validated, never shipping 32473."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from warden.audit.syslog import SyslogSettings
from warden.config import SyslogConfig


def _base(**kw: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "host": "collector.example.com",
        "port": 6514,
        "sd_id": "warden@99999",
    }
    values.update(kw)
    return values


def test_defaults() -> None:
    settings = SyslogSettings(**_base())
    assert settings.transport == "tls"
    assert settings.framing == "octet-counting"
    assert settings.facility == 13
    assert settings.start_from == "latest"
    assert settings.hostname  # the local host name, never empty


def test_sd_id_has_no_default() -> None:
    values = _base()
    del values["sd_id"]
    with pytest.raises(ValidationError):
        SyslogSettings(**values)


@pytest.mark.parametrize("sd_id", ["warden@32473", "warden", "warden@", "a b@1", "x" * 24 + "@1"])
def test_bad_sd_ids_are_refused(sd_id: str) -> None:
    with pytest.raises(ValidationError):
        SyslogSettings(**_base(sd_id=sd_id))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "has space"),
        ("hostname", "a\nb"),
        ("hostname", "h" * 256),
        ("app_name", "a" * 49),
        ("app_name", "app\n"),
        ("host", "bad host"),
        ("max_message_bytes", 1023),
        ("max_message_bytes", 65_001),
        ("facility", 24),
        ("grace_seconds", 0),
        ("tls_server_name", "x\ny"),
    ],
)
def test_invalid_values_are_refused(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        SyslogSettings(**_base(**{field: value}))


def test_backoff_cap_must_not_be_below_the_initial_delay() -> None:
    with pytest.raises(ValidationError):
        SyslogSettings(**_base(backoff_initial_seconds=5, backoff_max_seconds=1))


def test_from_config_carries_the_transport_fields() -> None:
    config = SyslogConfig(
        enabled=True,
        host="collector.example.com",
        port=1514,
        transport="tcp",
        framing="lf",
        sd_id="warden@99999",
        app_name="vor",
        tls_server_name="syslog.example.com",
    )
    settings = SyslogSettings.from_config(config, grace_seconds=0.5)
    assert (settings.host, settings.port, settings.transport, settings.framing) == (
        "collector.example.com",
        1514,
        "tcp",
        "lf",
    )
    assert settings.sd_id == "warden@99999"
    assert settings.app_name == "vor"
    assert settings.tls_server_name == "syslog.example.com"
    assert settings.grace_seconds == 0.5


def test_from_config_refuses_an_incomplete_section() -> None:
    with pytest.raises(ValueError, match="host"):
        SyslogSettings.from_config(SyslogConfig(port=1514, sd_id="warden@99999"))
