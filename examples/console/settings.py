"""The sample's configuration: written for a sandbox, read through konfig.

A product reads warden's settings exactly this way: konfig ``Settings`` from
its configuration file (and environment), konfig ``Secrets`` for secret
values, and ``warden.config.load_config`` to validate the ``warden`` section
into one ``WardenConfig`` at start-up.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any

from warden.config import WardenConfig, load_config
from warden.identity import new_totp_key

__all__ = [
    "CONFIG_NAME",
    "REQUIRED_PORTS",
    "SSO_CLIENT_SECRET",
    "KonfigSecrets",
    "LoadedSettings",
    "load_settings",
    "read_ports",
    "seed_secrets",
    "write_config",
]

TEMPLATE = Path(__file__).resolve().parent / "console.template.yaml"
CONFIG_NAME = "console.yaml"
REQUIRED_PORTS = ("console", "postgres", "stub_idp", "syslog_tls")
# konfig's secrets namespace; the same default the warden CLI uses.
SERVICE_NAME = "warden"
# The stub provider accepts any client secret; this one is fixed and dev-only.
SSO_CLIENT_SECRET = "console-sso-secret-dev-only"  # noqa: S105


class KonfigSecrets:
    """konfig's ``Secrets``, typed as the store warden expects (``get`` and ``set``)."""

    def __init__(self, settings: Any) -> None:
        from konfig import Secrets

        self._secrets: Any = Secrets(service_name=SERVICE_NAME, settings=settings)

    def get(self, key: str) -> str | None:
        value = self._secrets.get(key)
        return None if value is None else str(value)

    def set(self, key: str, value: str) -> None:
        self._secrets.set(key, value)


@dataclass(frozen=True)
class LoadedSettings:
    path: Path
    config: WardenConfig
    secrets: KonfigSecrets
    port: int
    provider_ca_file: str | None


def read_ports(path: Path) -> dict[str, int]:
    """The ``name=port`` lines of a sandbox's ``ports.txt``; other lines are skipped."""
    ports: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        name, sep, value = line.partition("=")
        if sep and value.strip().isdigit():
            ports[name.strip()] = int(value.strip())
    return ports


def write_config(sandbox: Path, ports: Mapping[str, int]) -> Path:
    """Write ``<sandbox>/console.yaml`` from the template and return its path."""
    missing = [name for name in REQUIRED_PORTS if name not in ports]
    if missing:
        raise ValueError("ports missing: " + ", ".join(missing))
    text = Template(TEMPLATE.read_text(encoding="utf-8")).substitute(
        sandbox=sandbox.resolve().as_posix(),
        **{name: str(ports[name]) for name in REQUIRED_PORTS},
    )
    target = sandbox / CONFIG_NAME
    target.write_text(text, encoding="utf-8", newline="\n")
    return target


def load_settings(path: Path) -> LoadedSettings:
    """Read the configuration file through konfig and validate warden's section.

    A missing or inconsistent warden setting raises ``warden.config.ConfigError``
    naming the field, before anything else runs.
    """
    from konfig import Settings

    settings: Any = Settings(config_file=str(path))
    secrets = KonfigSecrets(settings)
    config = load_config(settings, secrets)
    port = int(settings.get("console.port") or 0)
    if not 0 < port < 65536:
        raise ValueError("console.port must be a port number")
    ca_file = settings.get("console.provider_ca_file")
    return LoadedSettings(
        path=path,
        config=config,
        secrets=secrets,
        port=port,
        provider_ca_file=None if ca_file is None else str(ca_file),
    )


def seed_secrets(loaded: LoadedSettings) -> None:
    """Put the secrets warden needs in konfig's store, keeping any already there.

    The TOTP encryption key and the password fingerprint key are generated
    once; the single sign-on client secret is the stub provider's fixed
    dev-only value. Signing keys are created with ``warden keys rotate``, as a
    product would.
    """
    secrets = loaded.secrets
    totp_key = loaded.config.identity.totp_key_secret
    if secrets.get(totp_key) is None:
        secrets.set(totp_key, new_totp_key())
    # The key that seals password fingerprints (ruling PW8); with it a policy
    # may enable the fingerprint and the recheck can find passwords that have
    # since appeared on a watch list.
    fingerprint_key = loaded.config.passwords.fingerprint_key_secret
    if fingerprint_key is not None and secrets.get(fingerprint_key) is None:
        secrets.set(fingerprint_key, new_totp_key())
    client_secret = loaded.config.sso.client_secret
    if secrets.get(client_secret) is None:
        secrets.set(client_secret, SSO_CLIENT_SECRET)
