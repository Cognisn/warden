"""Start-up validation of the WebAuthn settings (rulings P2, P3 and P7 of 6 November 2026).

The relying party (id, name, origins), the ceremony timings, the per-user
credential limit and the optional trusted attestation roots are checked at
start-up: a bad or inconsistent value raises ``ConfigError`` naming the field,
before anything else runs, and never echoes the value.
"""

from __future__ import annotations

import copy
import datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from warden.config import ConfigError, WardenConfig, WebAuthnConfig, parse_config

BASE: dict[str, Any] = {
    "http": {
        "public_base_url": "https://app.example.com",
        "accept_invitation_link": "/accept?token={token}",
        "reset_password_link": "/reset/{token}",
    }
}


def _parse(secrets: dict[str, str] | None = None, **sections: dict[str, Any]) -> WardenConfig:
    tree = copy.deepcopy(BASE)
    for name, values in sections.items():
        tree.setdefault(name, {}).update(values)
    return parse_config(tree, None if secrets is None else _Secrets(secrets))


def _refused(field: str, secrets: dict[str, str] | None = None, **sections: dict[str, Any]) -> str:
    with pytest.raises(ConfigError) as caught:
        _parse(secrets, **sections)
    message = str(caught.value)
    assert f"warden.{field}:" in message, message
    return message


class _Secrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, key: str) -> str | None:
        return self._values.get(key)


def _certificate(*, ca: bool, name: str = "Example Attestation Root") -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# Defaults: derived from http.public_base_url.


def test_webauthn_defaults() -> None:
    config = _parse()
    webauthn = config.webauthn
    assert webauthn == WebAuthnConfig()
    assert webauthn.rp_id is None
    assert webauthn.rp_name is None
    assert webauthn.allowed_origins == ()
    assert webauthn.challenge_ttl_seconds == 300
    assert webauthn.client_timeout_seconds == 240
    assert webauthn.max_credentials_per_user == 10
    assert webauthn.attestation_roots is None
    assert webauthn.relying_party_id(config.http) == "app.example.com"
    assert webauthn.relying_party_name(config.http) == "app.example.com"
    assert webauthn.origins(config.http) == ("https://app.example.com",)


def test_the_default_origin_drops_the_path_and_keeps_a_non_default_port() -> None:
    config = _parse(http={"public_base_url": "https://App.Example.com:8443/app/"})
    assert config.webauthn.relying_party_id(config.http) == "app.example.com"
    assert config.webauthn.origins(config.http) == ("https://app.example.com:8443",)


def test_the_default_origin_drops_the_default_port() -> None:
    config = _parse(http={"public_base_url": "https://app.example.com:443"})
    assert config.webauthn.origins(config.http) == ("https://app.example.com",)


def test_localhost_over_http_is_a_usable_relying_party() -> None:
    config = _parse(http={"public_base_url": "http://localhost:8040"})
    assert config.webauthn.relying_party_id(config.http) == "localhost"
    assert config.webauthn.origins(config.http) == ("http://localhost:8040",)


@pytest.mark.parametrize("base", ["http://127.0.0.1:8000", "http://[::1]:8000"])
def test_an_ip_address_base_url_still_loads_but_has_no_relying_party(base: str) -> None:
    # 0.1.0b8 accepts a loopback IP address as the base URL; browsers refuse an
    # IP address as a WebAuthn relying party id, so WebAuthn is unavailable
    # until rp_id and allowed_origins are set, and nothing else changes.
    config = _parse(http={"public_base_url": base})
    assert config.webauthn.relying_party_id(config.http) is None


# The relying party id: the origin host or a registrable suffix of it.


def test_a_registrable_suffix_of_the_origin_host_is_accepted() -> None:
    config = _parse(webauthn={"rp_id": "example.com"})
    assert config.webauthn.relying_party_id(config.http) == "example.com"
    assert config.webauthn.origins(config.http) == ("https://app.example.com",)


def test_the_relying_party_id_is_lower_cased() -> None:
    config = _parse(webauthn={"rp_id": "Example.COM"})
    assert config.webauthn.relying_party_id(config.http) == "example.com"


def test_the_relying_party_name_is_used_when_set() -> None:
    config = _parse(webauthn={"rp_name": "Example Cases"})
    assert config.webauthn.relying_party_name(config.http) == "Example Cases"


@pytest.mark.parametrize(
    ("rp_id", "origin"),
    [
        ("other.example.org", None),
        ("pp.example.com", None),
        ("app.example.com.example.net", None),
        ("co.uk", "https://app.example.co.uk"),
        ("localhost", None),
    ],
    ids=["another-site", "partial-label", "longer", "public-suffix", "localhost"],
)
def test_an_rp_id_that_does_not_cover_the_origin_is_refused(rp_id: str, origin: str | None) -> None:
    sections: dict[str, dict[str, Any]] = {"webauthn": {"rp_id": rp_id}}
    if origin is not None:
        sections["http"] = {"public_base_url": origin}
    message = _refused("webauthn.rp_id", **sections)
    assert rp_id not in message


@pytest.mark.parametrize(
    "rp_id",
    ["", "example.com\n", "example.com.", "127.0.0.1", "exa mple.com", "*.example.com", "com"],
    ids=["empty", "newline", "trailing-dot", "ip", "space", "wildcard", "single-label"],
)
def test_a_malformed_rp_id_is_refused(rp_id: str) -> None:
    _refused("webauthn.rp_id", webauthn={"rp_id": rp_id})


@pytest.mark.parametrize("rp_name", ["", "x" * 65, "Example\nCases", "Example\x7f"])
def test_a_malformed_rp_name_is_refused(rp_name: str) -> None:
    _refused("webauthn.rp_name", webauthn={"rp_name": rp_name})


# Allowed origins: exact, no wildcard, consistent with the relying party id.


def test_several_origins_under_the_relying_party_id() -> None:
    config = _parse(
        webauthn={
            "rp_id": "example.com",
            "allowed_origins": ["https://app.example.com", "https://login.example.com"],
        }
    )
    assert config.webauthn.origins(config.http) == (
        "https://app.example.com",
        "https://login.example.com",
    )


def test_allowed_origins_from_the_environment() -> None:
    config = _parse(
        webauthn={
            "rp_id": "example.com",
            "allowed_origins": "https://app.example.com, https://login.example.com",
        }
    )
    assert config.webauthn.allowed_origins == (
        "https://app.example.com",
        "https://login.example.com",
    )


@pytest.mark.parametrize(
    "origin",
    [
        "https://*.example.com",
        "*",
        "https://app.example.com/",
        "https://app.example.com/login",
        "https://app.example.com?x=1",
        "https://user@app.example.com",
        "https://App.example.com",
        "https://app.example.com:443",
        "http://app.example.com",
        "https://app.example.com\n",
        "app.example.com",
        "https://192.0.2.10",
    ],
    ids=[
        "wildcard-host",
        "wildcard",
        "trailing-slash",
        "path",
        "query",
        "credentials",
        "upper-case",
        "default-port",
        "plain-http",
        "newline",
        "no-scheme",
        "ip-address",
    ],
)
def test_an_origin_that_is_not_exact_is_refused(origin: str) -> None:
    message = _refused("webauthn.allowed_origins", webauthn={"allowed_origins": [origin]})
    assert origin.strip() not in message


def test_an_origin_outside_the_relying_party_is_refused() -> None:
    message = _refused(
        "webauthn.allowed_origins",
        webauthn={"allowed_origins": ["https://app.example.com", "https://app.example.org"]},
    )
    assert "example.org" not in message


def test_origins_set_alone_must_fall_under_the_base_url_host() -> None:
    _refused("webauthn.allowed_origins", webauthn={"allowed_origins": ["https://example.com"]})


def test_an_ip_address_base_url_with_a_relying_party_set_is_checked() -> None:
    config = _parse(
        http={"public_base_url": "http://127.0.0.1:8000"},
        webauthn={"rp_id": "localhost", "allowed_origins": ["http://localhost:8000"]},
    )
    assert config.webauthn.relying_party_id(config.http) == "localhost"
    _refused(
        "webauthn.rp_id",
        http={"public_base_url": "http://127.0.0.1:8000"},
        webauthn={"rp_id": "localhost"},
    )


# Ceremony timings and the credential limit.


def test_the_client_timeout_must_not_exceed_the_challenge_lifetime() -> None:
    _refused(
        "webauthn.client_timeout_seconds",
        webauthn={"challenge_ttl_seconds": 120, "client_timeout_seconds": 121},
    )
    config = _parse(webauthn={"challenge_ttl_seconds": 120, "client_timeout_seconds": 120})
    assert config.webauthn.client_timeout_seconds == 120


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("challenge_ttl_seconds", 29),
        ("challenge_ttl_seconds", 1801),
        ("client_timeout_seconds", 29),
        ("client_timeout_seconds", 1801),
        ("max_credentials_per_user", 0),
        ("max_credentials_per_user", 101),
        ("user_verification", "discouraged"),
    ],
)
def test_invalid_webauthn_values_are_refused_at_start_up(field: str, value: Any) -> None:
    # user_verification is not a setting (P7): the ceremony fixes it.
    _refused(f"webauthn.{field}", webauthn={field: value})


# Trusted attestation roots (P3).


def test_attestation_roots_from_a_setting() -> None:
    pem = _certificate(ca=True) + _certificate(ca=True, name="Second Root")
    roots = _parse(webauthn={"attestation_roots": pem}).webauthn.attestation_roots
    assert roots is not None
    assert len(x509.load_pem_x509_certificates(roots.encode("ascii"))) == 2


def test_attestation_roots_from_a_secret() -> None:
    pem = _certificate(ca=True)
    config = _parse(
        {"vor.webauthn-roots": pem}, webauthn={"attestation_roots": "secret://vor.webauthn-roots"}
    )
    assert config.webauthn.attestation_roots == pem


@pytest.mark.parametrize("value", ["", "   \n"])
def test_empty_attestation_roots_mean_any_authenticator(value: str) -> None:
    assert _parse(webauthn={"attestation_roots": value}).webauthn.attestation_roots is None


@pytest.mark.parametrize(
    "value",
    [
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    ],
    ids=["text", "truncated"],
)
def test_attestation_roots_that_are_not_certificates_are_refused(value: str) -> None:
    message = _refused("webauthn.attestation_roots", webauthn={"attestation_roots": value})
    assert "MIIB" not in message and "not a certificate" not in message


def test_an_attestation_root_that_is_not_a_ca_is_refused() -> None:
    pem = _certificate(ca=True) + _certificate(ca=False, name="Example Leaf")
    message = _refused("webauthn.attestation_roots", webauthn={"attestation_roots": pem})
    assert "Example Leaf" not in message


def test_an_unresolvable_roots_secret_is_refused() -> None:
    with pytest.raises(ConfigError, match=r"warden\.webauthn\.attestation_roots"):
        _parse({}, webauthn={"attestation_roots": "secret://vor.webauthn-roots"})


# The passkey registration link (wave 11), validated like the invitation link.


def test_the_passkey_registration_link_is_optional() -> None:
    assert _parse().http.passkey_registration_link is None


def test_the_passkey_registration_link_is_a_token_template() -> None:
    config = _parse(http={"passkey_registration_link": "/passkey/register?t={token}"})
    assert config.http.passkey_registration_link == "/passkey/register?t={token}"
    link = config.http.render_link(config.http.passkey_registration_link, token="a/b")
    assert link == "https://app.example.com/passkey/register?t=a%2Fb"


@pytest.mark.parametrize(
    "template",
    [
        "/passkey/register",
        "/passkey/register?t={token}&u={user}",
        "/passkey/register?t={token!r}",
        "//evil.example.net/{token}",
        "http://app.example.com/{token}",
        "/passkey/register?t={token}\n",
    ],
)
def test_a_malformed_passkey_registration_link_is_refused(template: str) -> None:
    _refused("http.passkey_registration_link", http={"passkey_registration_link": template})


def test_unknown_webauthn_fields_are_refused() -> None:
    _refused("webauthn.allowed_origin", webauthn={"allowed_origin": "https://app.example.com"})
