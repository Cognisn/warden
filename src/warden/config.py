"""Typed configuration, bound through konfig and validated at start-up.

A product builds one ``WardenConfig`` at boot, normally with
``load_config(ctx.settings, ctx.secrets)`` from a konfig ``AppContext``.
Every value lives under one settings prefix (``warden`` by default), so the
environment variable ``<APP>__WARDEN__HTTP__PUBLIC_BASE_URL`` maps to
``warden.http.public_base_url``. A missing, unknown or inconsistent value
raises ``ConfigError`` naming the field, before anything else runs.

Values of the form ``secret://<name>`` are resolved through the secrets
store before validation. Error messages carry field names and fixed reasons
only, never the offending value, because the value may be a secret.

This module is shared: after the Foundation arc only the integration session
edits it. Sections whose fields are marked provisional are declared now so
later arcs can rely on them existing.
"""

from __future__ import annotations

import re
import string
from collections.abc import Iterable, Mapping
from typing import Annotated, Any, Literal, Protocol, Self
from urllib.parse import quote, urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

__all__ = [
    "AuditConfig",
    "ConfigError",
    "DbConfig",
    "HttpConfig",
    "IdentityConfig",
    "KeysConfig",
    "MailConfig",
    "SecretSource",
    "SettingsSource",
    "SsoConfig",
    "SyslogConfig",
    "WardenConfig",
    "load_config",
    "parse_config",
]

SECRET_SCHEME = "secret://"  # noqa: S105 - a URI scheme, not a secret
DEFAULT_PREFIX = "warden"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

_PRINTABLE = re.compile(r"[!-~]+")
_MOUNT_PREFIX = re.compile(r"(?:/[A-Za-z0-9._~-]+)+")
_SECRET_NAME = re.compile(r"[A-Za-z0-9._/-]+")
_SD_ID = re.compile(r"[A-Za-z0-9._-]{1,23}@([1-9][0-9]{0,8})")
_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_SCOPE = re.compile(r"[!#-\[\]-~]+")

# RFC 5612: the enterprise number reserved for documentation. Never shipped.
DOCUMENTATION_PEN = "32473"


class ConfigError(Exception):
    """The configuration is missing, unknown or inconsistent.

    The message lists every problem as ``<prefix>.<section>.<field>: reason``.
    """


class SettingsSource(Protocol):
    """What warden needs from konfig's ``Settings``."""

    def get_section(self, prefix: str) -> dict[str, Any]: ...


class SecretSource(Protocol):
    """What warden needs from konfig's ``Secrets``."""

    def get(self, key: str) -> str | None: ...


class _FieldProblems(ValueError):
    """Cross-field problems, each with a path relative to the failing model."""

    def __init__(self, problems: list[tuple[tuple[str, ...], str]]) -> None:
        super().__init__("; ".join(".".join(path) + ": " + reason for path, reason in problems))
        self.problems = problems


def _split_list(value: Any) -> Any:
    """Accept a comma-separated string (as the environment supplies) for a list field."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


def _check_url(value: str, *, allow_path: bool = True) -> str:
    """Validate an absolute http(s) URL; plain http only for loopback hosts."""
    if _PRINTABLE.fullmatch(value) is None:
        raise ValueError("must be a URL without spaces or control characters")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an absolute http or https URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("must not carry credentials")
    if parts.query or parts.fragment or "?" in value or "#" in value:
        raise ValueError("must not carry a query or fragment")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        raise ValueError("must use https unless the host is loopback")
    if not allow_path and parts.path not in ("", "/"):
        raise ValueError("must not carry a path")
    return value.rstrip("/")


def _check_template(value: str, *, placeholders: frozenset[str]) -> str:
    """Validate a UI link template: a path or URL using exactly ``placeholders``."""
    if _PRINTABLE.fullmatch(value) is None:
        raise ValueError("must not contain spaces or control characters")
    try:
        parsed = list(string.Formatter().parse(value))
    except ValueError:
        raise ValueError("has unbalanced braces") from None
    used: set[str] = set()
    for _literal, field, spec, conversion in parsed:
        if field is None:
            continue
        if field not in placeholders or spec or conversion:
            allowed = ", ".join("{" + p + "}" for p in sorted(placeholders)) or "none"
            raise ValueError(f"may use only these placeholders: {allowed}")
        used.add(field)
    missing = placeholders - used
    if missing:
        raise ValueError("must contain " + ", ".join("{" + p + "}" for p in sorted(missing)))
    if value.startswith("/") and not value.startswith("//"):
        return value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be a path starting with / or an absolute http or https URL")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        raise ValueError("must use https unless the host is loopback")
    return value


class _Section(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class DbConfig(_Section):
    """Database settings. At runtime warden uses the product's pool, never this DSN."""

    dsn: SecretStr | None = None
    """Connection string for ``warden migrate`` and ``warden keys rotate`` only."""


class KeysConfig(_Section):
    """Ed25519 signing keys. Private halves live in konfig's secrets store."""

    secret_prefix: str = "warden.signing-key."  # noqa: S105 - a name prefix, not a secret
    """Secrets-store name prefix; a key is stored as ``<secret_prefix><key_id>``."""

    @field_validator("secret_prefix")
    @classmethod
    def _secret_prefix_shape(cls, value: str) -> str:
        if _SECRET_NAME.fullmatch(value) is None:
            raise ValueError("may contain only letters, digits, '.', '_', '/' and '-'")
        return value


class AuditConfig(_Section):
    """Audit trail settings. Provisional: the audit core arc settles the defaults."""

    details_max_bytes: int = Field(default=8192, ge=256, le=1_048_576)
    retention_days: int | None = Field(default=None, ge=1)
    trusted_proxies: Annotated[tuple[IPvAnyNetwork, ...], BeforeValidator(_split_list)] = ()


class SyslogConfig(_Section):
    """Syslog forwarding. Provisional: the syslog arc settles the transport fields."""

    enabled: bool = False
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    transport: Literal["udp", "tcp", "tls"] = "tls"
    framing: Literal["octet-counting", "lf"] = "octet-counting"
    sd_id: str | None = None
    """Structured-data id, ``name@<PEN>``. No default is shipped (design D12)."""
    app_name: str = "warden"
    queue_size: int = Field(default=10_000, ge=1, le=1_000_000)
    tls_ca_file: str | None = None
    tls_server_name: str | None = None

    @field_validator("host", "app_name", "tls_ca_file", "tls_server_name")
    @classmethod
    def _printable(cls, value: str | None) -> str | None:
        if value is not None and _PRINTABLE.fullmatch(value) is None:
            raise ValueError("must not contain spaces or control characters")
        return value

    @field_validator("sd_id")
    @classmethod
    def _sd_id_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        match = _SD_ID.fullmatch(value)
        if match is None:
            raise ValueError("must be name@<enterprise number>")
        if match.group(1) == DOCUMENTATION_PEN:
            raise ValueError("must not use the documentation enterprise number 32473")
        return value


class IdentityConfig(_Section):
    """Identity settings. Provisional: the identity arcs settle the defaults."""

    enabled: bool = True
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=28_800, ge=300)
    session_lifespan_seconds: int = Field(default=43_200, ge=300)
    refresh_reuse_grace_seconds: int = Field(default=10, ge=0, le=120)
    invitation_ttl_seconds: int = Field(default=604_800, ge=300)
    reset_ttl_seconds: int = Field(default=3600, ge=300, le=86_400)
    require_mfa: bool = True
    password_min_length: int = Field(default=12, ge=8, le=1024)

    @model_validator(mode="after")
    def _lifetimes_consistent(self) -> Self:
        problems: list[tuple[tuple[str, ...], str]] = []
        if self.access_token_ttl_seconds >= self.refresh_token_ttl_seconds:
            problems.append(
                (("access_token_ttl_seconds",), "must be shorter than refresh_token_ttl_seconds")
            )
        if self.refresh_token_ttl_seconds > self.session_lifespan_seconds:
            problems.append(
                (("refresh_token_ttl_seconds",), "must not exceed session_lifespan_seconds")
            )
        if problems:
            raise _FieldProblems(problems)
        return self


class SsoConfig(_Section):
    """OIDC single sign-on. Provisional: the SSO arc settles the fields."""

    enabled: bool = False
    issuer_url: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    scopes: Annotated[tuple[str, ...], BeforeValidator(_split_list)] = (
        "openid",
        "email",
        "profile",
    )
    allowed_email_domains: Annotated[tuple[str, ...], BeforeValidator(_split_list)] = ()
    provider_preset: Literal["entra", "google", "okta", "generic"] = "generic"
    """A label for setup guidance only; it never changes behaviour."""
    discovery_cache_seconds: int = Field(default=3600, ge=60, le=86_400)

    @field_validator("issuer_url")
    @classmethod
    def _issuer_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        checked = _check_url(value)
        if not checked.startswith("https://"):
            raise ValueError("must use https")
        return checked

    @field_validator("client_id")
    @classmethod
    def _client_id_shape(cls, value: str | None) -> str | None:
        if value is not None and _PRINTABLE.fullmatch(value) is None:
            raise ValueError("must not contain spaces or control characters")
        return value

    @field_validator("scopes")
    @classmethod
    def _scopes_shape(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SCOPE.fullmatch(scope) is None for scope in value):
            raise ValueError("each scope must be a printable token")
        if "openid" not in value:
            raise ValueError("must include openid")
        return value

    @field_validator("allowed_email_domains")
    @classmethod
    def _domains_shape(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        lowered = tuple(domain.lower() for domain in value)
        if any(len(d) > 253 or _DOMAIN.fullmatch(d) is None for d in lowered):
            raise ValueError("each entry must be a domain name")
        return lowered


class MailConfig(_Section):
    """Mail settings. The product implements the sender. Provisional."""

    from_address: str | None = None
    from_name: str | None = None
    reply_to: str | None = None

    @field_validator("from_address", "reply_to")
    @classmethod
    def _address_shape(cls, value: str | None) -> str | None:
        if value is not None and _EMAIL.fullmatch(value) is None:
            raise ValueError("must be an email address")
        return value

    @field_validator("from_name")
    @classmethod
    def _name_shape(cls, value: str | None) -> str | None:
        if value is not None and any(ch < " " or ch == "\x7f" for ch in value):
            raise ValueError("must not contain control characters")
        return value


class HttpConfig(_Section):
    """Where the product exposes warden (design D9).

    Mount prefixes are where the product mounts warden's routers. Link
    templates point at the product's own screens; a template starting with
    ``/`` is resolved against ``public_base_url``. The SSO callback is
    derived from the base URL and the auth prefix, never configured.
    """

    public_base_url: str
    auth_prefix: str = "/auth"
    admin_prefix: str = "/admin"
    audit_prefix: str = "/audit"
    keys_prefix: str = "/keys"
    accept_invitation_link: str | None = None
    """Template for the product's accept-invitation screen; must contain ``{token}``."""
    reset_password_link: str | None = None
    """Template for the product's reset-password screen; must contain ``{token}``."""
    sso_completion_link: str | None = None
    """Where the browser lands after single sign-on; no placeholders."""

    @field_validator("public_base_url")
    @classmethod
    def _base_url_shape(cls, value: str) -> str:
        return _check_url(value)

    @field_validator("auth_prefix", "admin_prefix", "audit_prefix", "keys_prefix")
    @classmethod
    def _prefix_shape(cls, value: str) -> str:
        if _MOUNT_PREFIX.fullmatch(value) is None:
            raise ValueError("must be a path such as /auth, without a trailing slash")
        return value

    @field_validator("accept_invitation_link", "reset_password_link")
    @classmethod
    def _token_template_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_template(value, placeholders=frozenset({"token"}))

    @field_validator("sso_completion_link")
    @classmethod
    def _completion_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_template(value, placeholders=frozenset())

    @model_validator(mode="after")
    def _prefixes_distinct(self) -> Self:
        names = ("auth_prefix", "admin_prefix", "audit_prefix", "keys_prefix")
        seen: dict[str, str] = {}
        problems: list[tuple[tuple[str, ...], str]] = []
        for name in names:
            value = getattr(self, name)
            if value in seen:
                problems.append(((name,), f"must differ from {seen[value]}"))
            seen.setdefault(value, name)
        if problems:
            raise _FieldProblems(problems)
        return self

    @property
    def sso_callback_url(self) -> str:
        """The OIDC redirect URI, derived so it cannot disagree with the mount."""
        return f"{self.public_base_url}{self.auth_prefix}/sso/callback"

    def url_for(self, path: str) -> str:
        """An absolute URL for a path under the public base URL."""
        if not path.startswith("/"):
            raise ValueError("path must start with /")
        return f"{self.public_base_url}{path}"

    def render_link(self, template: str | None, **values: str) -> str:
        """Fill a link template, percent-encoding every value."""
        if template is None:
            raise ValueError("link template is not configured")
        filled = template.format_map({k: quote(v, safe="") for k, v in values.items()})
        return self.url_for(filled) if filled.startswith("/") else filled


class WardenConfig(_Section):
    """warden's whole configuration: one object, validated once at start-up."""

    http: HttpConfig
    db: DbConfig = DbConfig()
    keys: KeysConfig = KeysConfig()
    audit: AuditConfig = AuditConfig()
    syslog: SyslogConfig = SyslogConfig()
    identity: IdentityConfig = IdentityConfig()
    sso: SsoConfig = SsoConfig()
    mail: MailConfig = MailConfig()

    @model_validator(mode="after")
    def _cross_section(self) -> Self:
        problems: list[tuple[tuple[str, ...], str]] = []
        if self.identity.enabled:
            for name in ("accept_invitation_link", "reset_password_link"):
                if getattr(self.http, name) is None:
                    problems.append((("http", name), "is required while identity is enabled"))
        if self.sso.enabled:
            if not self.identity.enabled:
                problems.append((("sso", "enabled"), "requires identity to be enabled"))
            for name in ("issuer_url", "client_id", "client_secret"):
                if getattr(self.sso, name) is None:
                    problems.append((("sso", name), "is required while sso is enabled"))
            if self.http.sso_completion_link is None:
                problems.append(
                    (("http", "sso_completion_link"), "is required while sso is enabled")
                )
        if self.syslog.enabled:
            for name in ("host", "port", "sd_id"):
                if getattr(self.syslog, name) is None:
                    problems.append((("syslog", name), "is required while syslog is enabled"))
        if problems:
            raise _FieldProblems(problems)
        return self


def _resolve_secrets(
    node: Any, secrets: SecretSource | None, path: tuple[str, ...], missing: list[str]
) -> Any:
    if isinstance(node, Mapping):
        return {k: _resolve_secrets(v, secrets, (*path, str(k)), missing) for k, v in node.items()}
    if isinstance(node, list | tuple):
        return [_resolve_secrets(v, secrets, (*path, str(i)), missing) for i, v in enumerate(node)]
    if isinstance(node, str) and node.startswith(SECRET_SCHEME):
        name = node[len(SECRET_SCHEME) :]
        value = secrets.get(name) if secrets is not None and name else None
        if value is None:
            missing.append(".".join(path))
        return value
    return node


def _format_errors(prefix: str, errors: Iterable[Mapping[str, Any]]) -> list[str]:
    lines: list[str] = []
    for error in errors:
        loc = tuple(str(part) for part in error.get("loc", ()))
        cause = error.get("ctx", {}).get("error")
        if isinstance(cause, _FieldProblems):
            for path, reason in cause.problems:
                lines.append(".".join((prefix, *loc, *path)) + ": " + reason)
            continue
        message = str(error.get("msg", "is invalid"))
        message = message.removeprefix("Value error, ")
        lines.append(".".join((prefix, *loc)) + ": " + message)
    return lines


def parse_config(
    data: Mapping[str, Any],
    secrets: SecretSource | None = None,
    *,
    prefix: str = DEFAULT_PREFIX,
) -> WardenConfig:
    """Validate a settings tree into ``WardenConfig`` or raise ``ConfigError``."""
    missing: list[str] = []
    resolved = _resolve_secrets(data, secrets, (prefix,), missing)
    if missing:
        raise ConfigError(
            "invalid warden configuration:\n"
            + "\n".join(f"  {path}: secret reference could not be resolved" for path in missing)
        )
    try:
        return WardenConfig.model_validate(resolved)
    except ValidationError as exc:
        lines = _format_errors(prefix, exc.errors(include_input=False, include_url=False))
        raise ConfigError(
            "invalid warden configuration:\n" + "\n".join(f"  {line}" for line in lines)
        ) from None


def load_config(
    settings: SettingsSource,
    secrets: SecretSource | None = None,
    *,
    prefix: str = DEFAULT_PREFIX,
) -> WardenConfig:
    """Read the ``prefix`` section from konfig settings and validate it.

    Call this once at start-up and pass the result to warden's components.
    """
    return parse_config(settings.get_section(prefix), secrets, prefix=prefix)
