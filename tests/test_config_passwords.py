"""Start-up validation of the password settings (rulings PW2, PW7 and PW8 of 10 November 2026).

The fingerprint key's secret names and the Pwned Passwords range API's
base URL, timeout, padding and user agent are checked at start-up: a bad or
inconsistent value raises ``ConfigError`` naming the field, before anything
else runs, and never echoes the value.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from warden.config import ConfigError, PasswordsConfig, WardenConfig, parse_config

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
    assert f"warden.{field}:" in message, message
    return message


def test_the_defaults_make_no_request_and_hold_no_fingerprint_key() -> None:
    passwords = _parse().passwords
    assert passwords == PasswordsConfig()
    assert passwords.fingerprint_key_secret is None
    assert passwords.fingerprint_previous_key_secret is None
    assert not passwords.fingerprint_available
    assert passwords.hibp_range_url == "https://api.pwnedpasswords.com/range/"
    assert passwords.hibp_padding is True
    assert passwords.hibp_timeout_seconds == 5.0
    assert passwords.hibp_user_agent == "cognisn-warden"


def test_a_fingerprint_key_name_makes_the_fingerprint_available() -> None:
    passwords = _parse(passwords={"fingerprint_key_secret": "warden.password-fingerprint-key"})
    assert passwords.passwords.fingerprint_available


@pytest.mark.parametrize("name", ["has space", "semi;colon", "", "new\nline"])
def test_a_malformed_secret_name_is_refused(name: str) -> None:
    message = _refused(
        "passwords.fingerprint_key_secret", passwords={"fingerprint_key_secret": name}
    )
    assert name not in message or not name


def test_a_previous_key_needs_a_current_key() -> None:
    _refused(
        "passwords.fingerprint_previous_key_secret",
        passwords={"fingerprint_previous_key_secret": "warden.fp.previous"},
    )


def test_the_previous_key_must_differ_from_the_current_key() -> None:
    _refused(
        "passwords.fingerprint_previous_key_secret",
        passwords={
            "fingerprint_key_secret": "warden.fp",
            "fingerprint_previous_key_secret": "warden.fp",
        },
    )


def test_the_fingerprint_key_must_differ_from_the_totp_key() -> None:
    _refused(
        "passwords.fingerprint_key_secret",
        passwords={"fingerprint_key_secret": "warden.totp-key"},
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://pwned.example.com/range/",
        "https://pwned.example.com/range",
        "https://pwned.example.com:8443/mirror/range/",
    ],
)
def test_any_https_mirror_is_accepted(url: str) -> None:
    assert _parse(passwords={"hibp_range_url": url}).passwords.hibp_range_url == url


@pytest.mark.parametrize(
    "url",
    [
        "http://pwned.example.com/range/",
        "http://localhost/range/",
        "ftp://pwned.example.com/range/",
        "https://pwned.example.com/range/?x=1",
        "https://pwned.example.com/range/#frag",
        "https://user:pass@pwned.example.com/range/",
        "https://pwned.example.com/range/\n",
        "https:///range/",
        "pwned.example.com/range/",
    ],
)
def test_a_range_url_that_is_not_plain_https_is_refused(url: str) -> None:
    message = _refused("passwords.hibp_range_url", passwords={"hibp_range_url": url})
    assert url.strip() not in message


@pytest.mark.parametrize("seconds", [0, -1, 61])
def test_the_timeout_is_bounded(seconds: float) -> None:
    _refused("passwords.hibp_timeout_seconds", passwords={"hibp_timeout_seconds": seconds})


@pytest.mark.parametrize("agent", ["", "a" * 129, "bad\nagent", "tab\there"])
def test_the_user_agent_is_printable_and_bounded(agent: str) -> None:
    _refused("passwords.hibp_user_agent", passwords={"hibp_user_agent": agent})


def test_the_user_agent_may_contain_spaces() -> None:
    config = _parse(passwords={"hibp_user_agent": "Example Product (warden)"})
    assert config.passwords.hibp_user_agent == "Example Product (warden)"


def test_unknown_password_settings_are_refused() -> None:
    _refused("passwords.min_length", passwords={"min_length": 10})


def test_password_min_length_stays_in_identity() -> None:
    assert _parse(identity={"password_min_length": 16}).identity.password_min_length == 16
