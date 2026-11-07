"""The sample's configuration: written for a sandbox, read back through konfig."""

from __future__ import annotations

from pathlib import Path

from warden.identity import TOTP_KEY_SECRET

PORTS = {"console": 8040, "postgres": 8032, "stub_idp": 8081, "syslog_tls": 8015}


def test_the_example_configuration_loads_through_konfig(tmp_path: Path) -> None:
    from examples.console.settings import load_settings, write_config

    path = write_config(tmp_path, PORTS)
    loaded = load_settings(path)
    config = loaded.config

    assert config.http.public_base_url == "http://localhost:8040"
    assert config.http.accept_invitation_link == "/accept?t={token}"
    assert config.http.sso_completion_link == "/signed-in"
    assert config.db.dsn is not None
    assert "127.0.0.1:8032" in config.db.dsn.get_secret_value()
    assert config.sso.issuer_url == "https://localhost:8081/warden"
    assert config.sso.enabled is False
    assert (config.syslog.host, config.syslog.port, config.syslog.transport) == (
        "127.0.0.1",
        8015,
        "tls",
    )
    assert config.syslog.tls_ca_file == (tmp_path / "certs" / "ca.pem").as_posix()
    assert loaded.port == 8040
    assert loaded.provider_ca_file == (tmp_path / "idp-certs" / "ca.pem").as_posix()


def test_every_secret_in_the_example_is_a_dev_only_value(tmp_path: Path) -> None:
    from examples.console.settings import write_config

    text = write_config(tmp_path, PORTS).read_text(encoding="utf-8")
    for key in ("master_key:", "dsn:"):
        line = next(line for line in text.splitlines() if line.strip().startswith(key))
        assert "-dev-only" in line, line


def test_init_seeds_the_secrets_warden_needs(tmp_path: Path) -> None:
    from examples.console.settings import load_settings, seed_secrets, write_config

    loaded = load_settings(write_config(tmp_path, PORTS))
    seed_secrets(loaded)
    assert loaded.secrets.get(TOTP_KEY_SECRET)
    assert loaded.secrets.get(loaded.config.sso.client_secret) == "console-sso-secret-dev-only"

    first = loaded.secrets.get(TOTP_KEY_SECRET)
    seed_secrets(loaded)
    assert loaded.secrets.get(TOTP_KEY_SECRET) == first


def test_the_example_configuration_has_the_passkey_registration_link(tmp_path: Path) -> None:
    from examples.console.app import PAGES
    from examples.console.settings import load_settings, write_config

    config = load_settings(write_config(tmp_path, PORTS)).config
    link = config.http.passkey_registration_link
    assert link == "/passkey?t={token}"
    assert link.split("?")[0] in PAGES
    # On localhost the relying party is localhost and the only origin is the console's.
    assert config.webauthn.relying_party_id(config.http) == "localhost"
    assert config.webauthn.origins(config.http) == ("http://localhost:8040",)


def test_attestation_roots_added_to_the_configuration_load(tmp_path: Path) -> None:
    """README, "Only YubiKeys": a root certificate pasted under warden.webauthn."""
    from console_support import soft_authenticator

    from examples.console.settings import load_settings, write_config

    root = soft_authenticator().TestCa.create("Example").root_pem
    path = write_config(tmp_path, PORTS)
    block = "".join(f"      {line}\n" for line in root.strip().splitlines())
    text = path.read_text(encoding="utf-8").replace(
        "\nwarden:\n", f"\nwarden:\n  webauthn:\n    attestation_roots: |\n{block}", 1
    )
    path.write_text(text, encoding="utf-8", newline="\n")

    config = load_settings(path).config
    assert config.webauthn.attestation_roots is not None
    assert config.webauthn.attestation_roots.strip() == root.strip()
