"""The default structured-data id, ``warden@67382`` (design D12, ruling of 28 October 2026).

Cognisn's IANA Private Enterprise Number is 67382. The default SD-ID is
derived from one constant; a product may override it with any valid SD-ID,
and the documentation number 32473 is always refused.
"""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from warden.audit import ActionRegistry
from warden.audit.syslog import AuditRecord, SyslogSettings, format_message, format_test_message
from warden.config import COGNISN_PEN, DEFAULT_SD_ID, ConfigError, SyslogConfig, parse_config

BASE: dict[str, Any] = {
    "http": {
        "public_base_url": "https://app.example.com",
        "accept_invitation_link": "/accept?token={token}",
        "reset_password_link": "/reset/{token}",
    }
}


def _config(**syslog: Any) -> SyslogConfig:
    tree = copy.deepcopy(BASE)
    tree["syslog"] = syslog
    return parse_config(tree).syslog


def _record() -> AuditRecord:
    return AuditRecord(
        id=7,
        occurred_at=datetime(2026, 10, 28, 1, 2, 3, tzinfo=UTC),
        action="product.thing",
        outcome="success",
        actor="user-1",
        resource_type=None,
        resource_id=None,
        source_ip=None,
        details={},
    )


def _sd_ids(message: bytes) -> list[str]:
    return re.findall(r"\[([^\s\]]+)", message.decode("utf-8"))


def test_the_enterprise_number_is_defined_once() -> None:
    assert COGNISN_PEN == "67382"
    assert DEFAULT_SD_ID == f"warden@{COGNISN_PEN}" == "warden@67382"


def test_config_and_settings_default_to_warden_at_67382() -> None:
    assert SyslogConfig().sd_id == "warden@67382"
    assert SyslogSettings(host="collector.example.com", port=6514).sd_id == "warden@67382"


def test_start_up_no_longer_requires_an_sd_id_when_syslog_is_enabled() -> None:
    config = _config(enabled=True, host="collector.example.com", port=6514)
    assert config.enabled and config.sd_id == "warden@67382"


def test_start_up_still_requires_host_and_port_when_syslog_is_enabled() -> None:
    with pytest.raises(ConfigError) as caught:
        _config(enabled=True)
    message = str(caught.value)
    assert "warden.syslog.host" in message and "warden.syslog.port" in message
    assert "warden.syslog.sd_id" not in message


def test_the_default_appears_in_formatted_messages() -> None:
    settings = SyslogSettings.from_config(_config(host="collector.example.com", port=6514))
    registry = ActionRegistry()
    message = format_message(_record(), settings, registry)
    assert _sd_ids(message) == ["warden@67382"]


def test_the_default_appears_in_the_test_message() -> None:
    settings = SyslogSettings.from_config(_config(host="collector.example.com", port=6514))
    assert _sd_ids(format_test_message(settings)) == ["warden@67382"]


def test_a_product_override_is_honoured() -> None:
    settings = SyslogSettings.from_config(
        _config(host="collector.example.com", port=6514, sd_id="vor@99999")
    )
    assert settings.sd_id == "vor@99999"
    assert _sd_ids(format_test_message(settings)) == ["vor@99999"]


def test_the_documentation_number_is_still_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        _config(enabled=True, host="collector.example.com", port=6514, sd_id="warden@32473")
    assert "warden.syslog.sd_id" in str(caught.value)
    with pytest.raises(ValidationError):
        SyslogSettings(host="collector.example.com", port=6514, sd_id="warden@32473")
