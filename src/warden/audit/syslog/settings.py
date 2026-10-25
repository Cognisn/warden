"""Settings for the syslog forwarder.

``SyslogConfig`` in ``warden.config`` carries the fields an operator sets
through konfig. The forwarder needs a few more (header host name, facility,
byte cap, gap grace and timings); until they join the shared configuration,
``SyslogSettings.from_config`` builds the full set from ``SyslogConfig`` plus
keyword overrides, with defaults for everything else.
"""

from __future__ import annotations

import re
import socket
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from warden.config import SyslogConfig

__all__ = ["SyslogSettings"]

# RFC 5424 PRINTUSASCII (33..126), the only bytes allowed in header fields.
_PRINTUSASCII = re.compile(r"[!-~]+")
_SD_ID = re.compile(r"[A-Za-z0-9._-]{1,23}@([1-9][0-9]{0,8})")

# RFC 5612: the enterprise number reserved for documentation. Never shipped (design D12).
DOCUMENTATION_PEN = "32473"


def _local_hostname() -> str:
    """This host's name, reduced to what an RFC 5424 HOSTNAME may carry."""
    name = "".join(ch if "!" <= ch <= "~" else "-" for ch in socket.gethostname())[:255]
    return name or "-"


class SyslogSettings(BaseModel):
    """Everything the forwarder, formatter and transports need."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str
    port: int = Field(ge=1, le=65535)
    transport: Literal["udp", "tcp", "tls"] = "tls"
    framing: Literal["octet-counting", "lf"] = "octet-counting"
    """Stream framing (RFC 6587); UDP always sends one message per datagram."""
    sd_id: str
    """Structured-data id, ``name@<PEN>``. No default (design D12); never 32473."""
    app_name: str = Field(default="warden", max_length=48)
    hostname: str = Field(default_factory=_local_hostname, max_length=255)
    """RFC 5424 HOSTNAME: this application host, as the collector should see it."""
    facility: int = Field(default=13, ge=0, le=23)
    """RFC 5424 facility; 13 is "log audit"."""
    max_message_bytes: int = Field(default=8192, ge=1024, le=65_000)
    """Whole-message cap in bytes, framing excluded."""

    tls_ca_file: str | None = None
    """CA bundle path; with neither this nor ``tls_ca_pem`` the system trust store is used."""
    tls_ca_pem: str | None = None
    """CA certificates as PEM text, normally read from konfig's secrets store."""
    tls_server_name: str | None = None
    """Name the collector's certificate must match; defaults to ``host``."""

    start_from: Literal["latest", "beginning"] = "latest"
    """With no stored cursor: start at the newest row, or replay the whole table."""
    grace_seconds: float = Field(default=2.0, gt=0, le=300)
    """How long a gap in row ids is held open for a late commit before it is passed."""
    poll_seconds: float = Field(default=5.0, gt=0, le=3600)
    """Safety poll interval, in case a notification is missed."""
    standby_retry_seconds: float = Field(default=2.0, gt=0, le=3600)
    """How often a standby replica tries to become the forwarder."""
    batch_size: int = Field(default=500, ge=1, le=10_000)
    connect_timeout_seconds: float = Field(default=10.0, gt=0, le=300)
    send_timeout_seconds: float = Field(default=10.0, gt=0, le=300)
    backoff_initial_seconds: float = Field(default=0.5, gt=0, le=300)
    backoff_max_seconds: float = Field(default=30.0, gt=0, le=3600)

    @field_validator("host", "app_name", "hostname", "tls_ca_file", "tls_server_name")
    @classmethod
    def _printable(cls, value: str | None) -> str | None:
        if value is not None and _PRINTUSASCII.fullmatch(value) is None:
            raise ValueError("must be printable ASCII without spaces")
        return value

    @field_validator("sd_id")
    @classmethod
    def _sd_id_shape(cls, value: str) -> str:
        match = _SD_ID.fullmatch(value)
        if match is None:
            raise ValueError("must be name@<enterprise number>")
        if match.group(1) == DOCUMENTATION_PEN:
            raise ValueError("must not use the documentation enterprise number 32473")
        return value

    @model_validator(mode="after")
    def _backoff_consistent(self) -> Self:
        if self.backoff_max_seconds < self.backoff_initial_seconds:
            raise ValueError("backoff_max_seconds must not be below backoff_initial_seconds")
        return self

    @property
    def server_name(self) -> str:
        return self.tls_server_name or self.host

    @classmethod
    def from_config(cls, config: SyslogConfig, **overrides: Any) -> Self:
        """Build settings from the shared ``SyslogConfig``; ``overrides`` set the rest."""
        missing = [name for name in ("host", "port", "sd_id") if getattr(config, name) is None]
        missing = [name for name in missing if name not in overrides]
        if missing:
            raise ValueError("syslog configuration is missing " + ", ".join(missing))
        values: dict[str, Any] = {
            "host": config.host,
            "port": config.port,
            "transport": config.transport,
            "framing": config.framing,
            "sd_id": config.sd_id,
            "app_name": config.app_name,
            "tls_ca_file": config.tls_ca_file,
            "tls_server_name": config.tls_server_name,
        }
        values.update(overrides)
        return cls(**values)
