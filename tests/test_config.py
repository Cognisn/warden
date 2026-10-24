"""Configuration contract: one typed object, validated at start-up."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from warden.config import ConfigError, WardenConfig, load_config

BASE: dict[str, Any] = {
    "http": {
        "public_base_url": "https://app.example.com",
        "accept_invitation_link": "/accept?token={token}",
        "reset_password_link": "https://app.example.com/reset/{token}",
    }
}


class FakeSettings:
    """A settings source holding one nested tree, as konfig's get_section returns."""

    def __init__(self, tree: dict[str, Any]) -> None:
        self._tree = tree

    def get_section(self, prefix: str) -> dict[str, Any]:
        node: Any = self._tree
        for part in prefix.split("."):
            if not isinstance(node, dict) or part not in node:
                return {}
            node = node[part]
        return copy.deepcopy(node) if isinstance(node, dict) else {}


class FakeSecrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, key: str) -> str | None:
        return self._values.get(key)


def _tree(**overrides: Any) -> dict[str, Any]:
    tree = copy.deepcopy(BASE)
    for dotted, value in overrides.items():
        section, _, field = dotted.partition("__")
        tree.setdefault(section, {})[field] = value
    return tree


def _load(tree: dict[str, Any], secrets: dict[str, str] | None = None) -> WardenConfig:
    return load_config(
        FakeSettings({"warden": tree}),
        FakeSecrets(secrets or {}) if secrets is not None else None,
    )


def test_minimal_configuration_loads_with_every_section() -> None:
    config = _load(_tree())
    for section in ("db", "keys", "audit", "syslog", "identity", "sso", "mail", "http"):
        assert getattr(config, section) is not None
    assert config.http.public_base_url == "https://app.example.com"


def test_missing_public_base_url_fails_naming_the_field() -> None:
    tree = _tree()
    del tree["http"]["public_base_url"]
    with pytest.raises(ConfigError) as caught:
        _load(tree)
    assert "warden.http.public_base_url" in str(caught.value)


def test_missing_http_section_fails_naming_the_field() -> None:
    with pytest.raises(ConfigError) as caught:
        _load({})
    assert "warden.http" in str(caught.value)


def test_unknown_key_fails_so_typos_surface_at_boot() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(http__public_base_ur="https://app.example.com"))
    assert "warden.http.public_base_ur" in str(caught.value)


@pytest.mark.parametrize(
    "url",
    [
        "http://app.example.com",
        "https://app.example.com/?x=1",
        "https://app.example.com/#frag",
        "ftp://app.example.com",
        "https://user:pw@app.example.com",
    ],
)
def test_public_base_url_rejects_unsafe_forms(url: str) -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(http__public_base_url=url))
    assert "warden.http.public_base_url" in str(caught.value)


@pytest.mark.parametrize("url", ["http://localhost:8000", "http://127.0.0.1:8000"])
def test_plain_http_is_allowed_for_loopback_only(url: str) -> None:
    assert _load(_tree(http__public_base_url=url)).http.public_base_url == url


def test_public_base_url_path_is_kept_without_trailing_slash() -> None:
    config = _load(_tree(http__public_base_url="https://example.com/app/"))
    assert config.http.public_base_url == "https://example.com/app"


def test_sso_callback_is_derived_from_base_url_and_prefix() -> None:
    config = _load(_tree(http__public_base_url="https://example.com/app/", http__auth_prefix="/id"))
    assert config.http.sso_callback_url == "https://example.com/app/id/sso/callback"


def test_sso_callback_cannot_be_configured() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(http__sso_callback_url="https://evil.example.net/cb"))
    assert "warden.http.sso_callback_url" in str(caught.value)


@pytest.mark.parametrize("prefix", ["auth", "/auth/", "/au th", "/auth\n", "//auth", ""])
def test_mount_prefixes_are_validated(prefix: str) -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(http__auth_prefix=prefix))
    assert "warden.http.auth_prefix" in str(caught.value)


def test_mount_prefixes_must_be_distinct() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(http__auth_prefix="/x", http__admin_prefix="/x"))
    assert "prefix" in str(caught.value)


def test_link_template_without_token_placeholder_fails() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(http__accept_invitation_link="/accept"))
    assert "warden.http.accept_invitation_link" in str(caught.value)


def test_link_template_with_unknown_placeholder_fails() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(http__reset_password_link="/reset/{token}/{user}"))
    assert "warden.http.reset_password_link" in str(caught.value)


def test_link_templates_required_while_identity_is_enabled() -> None:
    tree = _tree()
    del tree["http"]["accept_invitation_link"]
    with pytest.raises(ConfigError) as caught:
        _load(tree)
    assert "warden.http.accept_invitation_link" in str(caught.value)


def test_audit_only_deployment_needs_no_link_templates() -> None:
    tree = {"http": {"public_base_url": "https://app.example.com"}, "identity": {"enabled": False}}
    assert _load(tree).identity.enabled is False


def test_render_link_resolves_relative_templates_and_quotes_values() -> None:
    config = _load(_tree(http__public_base_url="https://example.com/app"))
    link = config.http.render_link(config.http.accept_invitation_link, token="a/b c")
    assert link == "https://example.com/app/accept?token=a%2Fb%20c"
    absolute = config.http.render_link(config.http.reset_password_link, token="t")
    assert absolute == "https://app.example.com/reset/t"


def test_secret_references_are_resolved_through_the_secrets_store() -> None:
    config = _load(
        _tree(db__dsn="secret://warden-db"),
        secrets={"warden-db": "postgresql://u:p@db.example.com/w"},
    )
    assert config.db.dsn is not None
    assert config.db.dsn.get_secret_value() == "postgresql://u:p@db.example.com/w"
    assert "u:p" not in repr(config)


def test_unresolvable_secret_reference_fails_naming_the_field() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(db__dsn="secret://missing"), secrets={})
    assert "warden.db.dsn" in str(caught.value)


def test_secret_reference_without_a_secrets_store_fails() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(db__dsn="secret://warden-db"), secrets=None)
    assert "warden.db.dsn" in str(caught.value)


def test_errors_never_echo_the_offending_value() -> None:
    secret_value = "s3cr3t-value-that-must-not-leak"
    with pytest.raises(ConfigError) as caught:
        _load(_tree(sso__client_secret=secret_value, sso__enabled="not-a-bool"))
    assert secret_value not in str(caught.value)
    assert "not-a-bool" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_string_values_from_the_environment_are_coerced() -> None:
    config = _load(
        _tree(
            identity__access_token_ttl_seconds="600",
            sso__allowed_email_domains="example.com, Example.org",
        )
    )
    assert config.identity.access_token_ttl_seconds == 600
    assert config.sso.allowed_email_domains == ("example.com", "example.org")


def test_session_lifetimes_must_be_consistent() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(
            _tree(
                identity__refresh_token_ttl_seconds=100_000, identity__session_lifespan_seconds=3600
            )
        )
    assert "warden.identity" in str(caught.value)


def test_sso_enabled_requires_issuer_client_and_completion_link() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(sso__enabled=True))
    message = str(caught.value)
    for field in (
        "warden.sso.issuer_url",
        "warden.sso.client_id",
        "warden.sso.client_secret",
        "warden.http.sso_completion_link",
    ):
        assert field in message


def test_sso_issuer_must_be_https() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(
            _tree(
                sso__enabled=True,
                sso__issuer_url="http://idp.example.com",
                sso__client_id="c",
                sso__client_secret="s",
                http__sso_completion_link="/signed-in",
            )
        )
    assert "warden.sso.issuer_url" in str(caught.value)


def test_complete_sso_configuration_loads() -> None:
    config = _load(
        _tree(
            sso__enabled=True,
            sso__issuer_url="https://idp.example.com/tenant",
            sso__client_id="c",
            sso__client_secret="s",
            http__sso_completion_link="/signed-in",
        )
    )
    assert config.sso.enabled
    assert "openid" in config.sso.scopes


def test_syslog_enabled_requires_destination_and_sd_id() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(_tree(syslog__enabled=True))
    message = str(caught.value)
    for field in ("warden.syslog.host", "warden.syslog.port", "warden.syslog.sd_id"):
        assert field in message


def test_syslog_refuses_the_documentation_enterprise_number() -> None:
    with pytest.raises(ConfigError) as caught:
        _load(
            _tree(
                syslog__enabled=True,
                syslog__host="192.0.2.10",
                syslog__port=6514,
                syslog__sd_id="warden@32473",
            )
        )
    assert "warden.syslog.sd_id" in str(caught.value)


@pytest.mark.parametrize(
    "sd_id", ["warden", "warden@", "war den@1", 'warden@1"', "warden@1\n", "warden@01"]
)
def test_syslog_sd_id_shape_is_validated(sd_id: str) -> None:
    with pytest.raises(ConfigError) as caught:
        _load(
            _tree(
                syslog__enabled=True,
                syslog__host="192.0.2.10",
                syslog__port=6514,
                syslog__sd_id=sd_id,
            )
        )
    assert "warden.syslog.sd_id" in str(caught.value)


def test_syslog_has_no_default_sd_id() -> None:
    assert _load(_tree()).syslog.sd_id is None


def test_trusted_proxies_parse_as_networks() -> None:
    config = _load(_tree(audit__trusted_proxies=["192.0.2.0/24", "2001:db8::1"]))
    assert [str(n) for n in config.audit.trusted_proxies] == ["192.0.2.0/24", "2001:db8::1/128"]


def test_configuration_is_immutable() -> None:
    config = _load(_tree())
    with pytest.raises(Exception):  # noqa: B017 - pydantic raises its own frozen error type
        config.http.auth_prefix = "/other"  # type: ignore[misc]
