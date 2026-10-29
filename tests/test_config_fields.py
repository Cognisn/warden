"""Start-up validation of the fields added for 0.1.0a4.

Every field below is checked at start-up: a bad value raises ``ConfigError``
naming the field, before anything else runs.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from warden.config import (
    MIN_RETENTION_DAYS,
    ConfigError,
    IdentityConfig,
    SyslogConfig,
    WardenConfig,
    parse_config,
)

BASE: dict[str, Any] = {
    "http": {
        "public_base_url": "https://app.example.com",
        "accept_invitation_link": "/accept?token={token}",
        "reset_password_link": "/reset/{token}",
    }
}


def _parse(**sections: dict[str, Any]) -> WardenConfig:
    tree = copy.deepcopy(BASE)
    for name, values in sections.items():
        tree.setdefault(name, {}).update(values)
    return parse_config(tree)


def _refused(field: str, **sections: dict[str, Any]) -> str:
    with pytest.raises(ConfigError) as caught:
        _parse(**sections)
    message = str(caught.value)
    assert f"warden.{field}" in message, message
    return message


# Audit retention (ruling of 27 October 2026).


def test_retention_defaults_to_keeping_the_trail_for_ever() -> None:
    assert _parse().audit.retention_days is None


def test_the_retention_minimum_is_365_days() -> None:
    assert MIN_RETENTION_DAYS == 365
    assert _parse(audit={"retention_days": 365}).audit.retention_days == 365


@pytest.mark.parametrize("days", [0, 1, 30, 364])
def test_retention_below_the_minimum_is_refused_with_a_clear_message(days: int) -> None:
    message = _refused("audit.retention_days", audit={"retention_days": days})
    assert "at least 365" in message
    assert str(days) not in message.replace("365", "")


def test_the_retention_purge_uses_the_same_minimum() -> None:
    from warden.audit import MIN_RETENTION_DAYS as purge_minimum

    assert purge_minimum == MIN_RETENTION_DAYS


# Syslog: the forwarder's fields, read from SyslogSettings.


def test_every_forwarder_setting_has_a_config_counterpart() -> None:
    from warden.audit.syslog import SyslogSettings

    counterpart = {"tls_ca_pem": "tls_ca_secret"}
    config_fields = set(SyslogConfig.model_fields)
    missing = [
        name
        for name in SyslogSettings.model_fields
        if counterpart.get(name, name) not in config_fields
    ]
    assert not missing, f"SyslogSettings fields without a SyslogConfig counterpart: {missing}"


def test_queue_size_is_gone() -> None:
    assert "queue_size" not in SyslogConfig.model_fields
    _refused("syslog.queue_size", syslog={"queue_size": 100})


def test_syslog_forwarder_defaults_match_the_forwarder() -> None:
    from warden.audit.syslog import SyslogSettings

    config = SyslogConfig()
    reference = SyslogSettings(host="collector.example.com", port=6514)
    for name in SyslogSettings.model_fields:
        if name in {"host", "port", "hostname", "tls_ca_pem"}:
            continue
        assert getattr(config, name) == getattr(reference, name), name
    assert config.hostname is None
    assert config.tls_ca_secret is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "has space"),
        ("hostname", "h" * 256),
        ("app_name", "a" * 49),
        ("facility", 24),
        ("facility", -1),
        ("max_message_bytes", 1023),
        ("max_message_bytes", 65_001),
        ("start_from", "middle"),
        ("grace_seconds", 0),
        ("grace_seconds", 301),
        ("poll_seconds", 0),
        ("standby_retry_seconds", 0),
        ("batch_size", 0),
        ("batch_size", 10_001),
        ("connect_timeout_seconds", 0),
        ("send_timeout_seconds", 301),
        ("backoff_initial_seconds", 0),
        ("backoff_max_seconds", 3601),
        ("tls_ca_secret", "has space"),
        ("tls_ca_secret", ""),
    ],
)
def test_invalid_syslog_forwarder_values_are_refused_at_start_up(field: str, value: Any) -> None:
    _refused(f"syslog.{field}", syslog={field: value})


def test_syslog_backoff_cap_must_not_be_below_the_initial_delay() -> None:
    _refused(
        "syslog.backoff_max_seconds",
        syslog={"backoff_initial_seconds": 5, "backoff_max_seconds": 1},
    )


def test_from_config_carries_every_field() -> None:
    from warden.audit.syslog import SyslogSettings

    values: dict[str, Any] = {
        "enabled": True,
        "host": "collector.example.com",
        "port": 1514,
        "transport": "tcp",
        "framing": "lf",
        "sd_id": "vor@99999",
        "app_name": "vor",
        "hostname": "app-1.example.com",
        "facility": 10,
        "max_message_bytes": 4096,
        "tls_ca_file": "ca.pem",
        "tls_ca_secret": "vor.syslog-ca",
        "tls_server_name": "syslog.example.com",
        "start_from": "beginning",
        "grace_seconds": 1.5,
        "poll_seconds": 7.0,
        "standby_retry_seconds": 3.0,
        "batch_size": 50,
        "connect_timeout_seconds": 4.0,
        "send_timeout_seconds": 6.0,
        "backoff_initial_seconds": 0.25,
        "backoff_max_seconds": 9.0,
    }
    config = _parse(syslog=values).syslog
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    settings = SyslogSettings.from_config(config, secrets={"vor.syslog-ca": pem}.get)
    for name in SyslogSettings.model_fields:
        if name == "tls_ca_pem":
            assert settings.tls_ca_pem == pem
            continue
        assert getattr(settings, name) == values[name], name


def test_from_config_refuses_a_ca_secret_it_cannot_read() -> None:
    from warden.audit.syslog import SyslogSettings

    config = _parse(
        syslog={"host": "collector.example.com", "port": 6514, "tls_ca_secret": "vor.syslog-ca"}
    ).syslog
    with pytest.raises(ValueError, match="tls_ca_secret") as caught:
        SyslogSettings.from_config(config, secrets={}.get)
    assert "vor.syslog-ca" not in str(caught.value)
    with pytest.raises(ValueError, match="tls_ca_secret"):
        SyslogSettings.from_config(config)


def test_from_config_uses_the_local_host_name_when_none_is_configured() -> None:
    from warden.audit.syslog import SyslogSettings

    config = _parse(syslog={"host": "collector.example.com", "port": 6514}).syslog
    assert SyslogSettings.from_config(config).hostname


# Identity: today's hard-coded values become configuration.


def test_identity_defaults_are_the_values_identity_used_before() -> None:
    identity = IdentityConfig()
    assert identity.totp_issuer is None
    assert identity.mfa_challenge_ttl_seconds == 300
    assert identity.mfa_max_failures == 5
    assert identity.recovery_code_count == 10
    assert identity.policy_cache_seconds == 30.0
    assert identity.sign_in_attempt_limit == 10
    assert identity.sign_in_window_seconds == 900
    assert identity.totp_key_secret == "warden.totp-key"
    assert identity.totp_previous_key_secret == "warden.totp-key.previous"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("totp_issuer", ""),
        ("totp_issuer", "Example\nCorp"),
        ("totp_issuer", "Example:Corp"),
        ("totp_issuer", "x" * 65),
        ("mfa_challenge_ttl_seconds", 29),
        ("mfa_challenge_ttl_seconds", 1801),
        ("mfa_max_failures", 0),
        ("mfa_max_failures", 21),
        ("recovery_code_count", 4),
        ("recovery_code_count", 51),
        ("policy_cache_seconds", 0),
        ("policy_cache_seconds", 3601),
        ("sign_in_attempt_limit", 0),
        ("sign_in_attempt_limit", 1001),
        ("sign_in_window_seconds", 59),
        ("sign_in_window_seconds", 86_401),
        ("totp_key_secret", "has space"),
        ("totp_previous_key_secret", ""),
    ],
)
def test_invalid_identity_values_are_refused_at_start_up(field: str, value: Any) -> None:
    _refused(f"identity.{field}", identity={field: value})


def test_the_totp_key_and_its_predecessor_must_have_different_names() -> None:
    _refused(
        "identity.totp_previous_key_secret",
        identity={"totp_key_secret": "k", "totp_previous_key_secret": "k"},
    )


def test_a_totp_issuer_with_spaces_is_allowed() -> None:
    assert _parse(identity={"totp_issuer": "Example Corp"}).identity.totp_issuer == "Example Corp"


# Fields wave 2 relies on, declared now (provisional until 0.1.0b1).


def test_api_key_fields() -> None:
    identity = IdentityConfig()
    assert identity.api_key_prefix == "wdn_"
    assert identity.api_key_max_lifetime_days == 365
    assert (
        _parse(identity={"api_key_max_lifetime_days": None}).identity.api_key_max_lifetime_days
        is None
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_key_prefix", ""),
        ("api_key_prefix", "has space_"),
        ("api_key_prefix", "x" * 17),
        ("api_key_prefix", "wdn\n"),
        ("api_key_max_lifetime_days", 0),
        ("api_key_max_lifetime_days", 3661),
    ],
)
def test_invalid_api_key_values_are_refused(field: str, value: Any) -> None:
    _refused(f"identity.{field}", identity={field: value})


def test_mail_template_override_fields() -> None:
    mail = _parse(mail={"template_package": "vor.mail_templates", "subject_prefix": "[VOR]"}).mail
    assert mail.template_package == "vor.mail_templates"
    assert mail.subject_prefix == "[VOR]"
    assert _parse().mail.template_package is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("template_package", "not a package"),
        ("template_package", "vor..templates"),
        ("template_package", "vor.templates\n"),
        ("template_package", "/srv/templates"),
        ("subject_prefix", "[VOR]\r\nBcc: x@example.com"),
        ("subject_prefix", "x" * 65),
    ],
)
def test_invalid_mail_template_values_are_refused(field: str, value: Any) -> None:
    _refused(f"mail.{field}", mail={field: value})


def test_sso_defaults() -> None:
    sso = _parse().sso
    assert sso.client_secret == "warden.sso.client-secret"
    assert sso.jwks_cache_seconds == 3600
    assert sso.jwks_refetch_min_seconds == 60
    assert sso.login_transaction_ttl_seconds == 600
    assert sso.handoff_code_ttl_seconds == 60
    assert sso.allowed_algorithms == ("RS256", "ES256", "PS256")
    assert sso.clock_skew_seconds == 60


def test_sso_client_secret_is_a_secret_name_not_a_value() -> None:
    sso = _parse(sso={"client_secret": "vor.sso-client-secret"}).sso
    assert sso.client_secret == "vor.sso-client-secret"
    _refused("sso.client_secret", sso={"client_secret": "s3cr3t value with spaces"})


@pytest.mark.parametrize(
    "algorithms",
    [["none"], ["HS256"], ["RS256", "HS512"], ["hs384"], ["None"], [], ["RS1"]],
)
def test_sso_never_allows_none_or_shared_secret_algorithms(algorithms: list[str]) -> None:
    _refused("sso.allowed_algorithms", sso={"allowed_algorithms": algorithms})


def test_sso_allowed_algorithms_from_the_environment() -> None:
    sso = _parse(sso={"allowed_algorithms": "ES256, EdDSA"}).sso
    assert sso.allowed_algorithms == ("ES256", "EdDSA")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("jwks_cache_seconds", 59),
        ("jwks_cache_seconds", 86_401),
        ("jwks_refetch_min_seconds", 0),
        ("jwks_refetch_min_seconds", 3601),
        ("login_transaction_ttl_seconds", 59),
        ("login_transaction_ttl_seconds", 3601),
        ("handoff_code_ttl_seconds", 4),
        ("handoff_code_ttl_seconds", 301),
        ("clock_skew_seconds", -1),
        ("clock_skew_seconds", 301),
    ],
)
def test_invalid_sso_values_are_refused(field: str, value: Any) -> None:
    _refused(f"sso.{field}", sso={field: value})


def test_sso_refetch_interval_must_not_exceed_the_cache_lifetime() -> None:
    _refused(
        "sso.jwks_refetch_min_seconds",
        sso={"jwks_cache_seconds": 120, "jwks_refetch_min_seconds": 300},
    )


def test_provisional_fields_are_marked_in_their_docstrings() -> None:
    from warden import config

    source = config.__file__
    assert source is not None
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    for name in (
        "api_key_prefix",
        "api_key_max_lifetime_days",
        "template_package",
        "subject_prefix",
        "jwks_cache_seconds",
        "jwks_refetch_min_seconds",
        "login_transaction_ttl_seconds",
        "handoff_code_ttl_seconds",
        "allowed_algorithms",
        "clock_skew_seconds",
    ):
        declaration = text.index(f"    {name}:")
        following = text[declaration : declaration + 600]
        assert "Provisional until 0.1.0b1" in following, name
