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

Fields that name a konfig secret (``*_secret``) hold the secret's name, not
its value; the component that needs the value reads it from the secrets
store when it starts.

This module is shared: only the session assigned it edits it. Fields marked
"Provisional until 0.1.0b1" are declared now so the 0.1.0 workstreams can
rely on them existing; their names and defaults may still change before b1.
"""

from __future__ import annotations

import re
import string
from collections.abc import Iterable, Mapping
from typing import Annotated, Any, Literal, Protocol, Self
from urllib.parse import quote, urlsplit

from cryptography import x509
from fido2.rpid import verify_rp_id
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
    "COGNISN_PEN",
    "DEFAULT_SD_ID",
    "MIN_RETENTION_DAYS",
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
    "WebAuthnConfig",
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
_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_API_KEY_PREFIX = re.compile(r"[a-z0-9_]{1,16}")

_DEFAULT_PORTS = {"http": 80, "https": 443}
_ORIGIN_SHAPE = (
    "each entry must be an exact origin such as https://login.example.com,"
    " with a domain name and no path, trailing slash or wildcard"
)

# RFC 5612: the enterprise number reserved for documentation. Never shipped.
DOCUMENTATION_PEN = "32473"

# Cognisn's IANA Private Enterprise Number (design D12), and the structured-data
# id warden's syslog messages carry unless the product sets its own.
COGNISN_PEN = "67382"
DEFAULT_SD_ID = f"warden@{COGNISN_PEN}"

# The shortest audit retention period warden accepts, in days.
MIN_RETENTION_DAYS = 365

# id_token signature algorithms single sign-on may accept: asymmetric only, so
# never ``none`` and never a shared-secret (HS*) algorithm.
_ASYMMETRIC_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)


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


def _check_secret_name(value: str | None) -> str | None:
    """A konfig secret name: letters, digits, '.', '_', '/' and '-'."""
    if value is not None and _SECRET_NAME.fullmatch(value) is None:
        raise ValueError("must be a secret name: letters, digits, '.', '_', '/' and '-'")
    return value


def _check_url(value: str, *, allow_path: bool = True) -> str:
    """Validate an absolute http(s) URL; plain http only for loopback hosts.

    The value is returned exactly as given: a caller that joins paths onto it
    strips a trailing slash itself, and an OIDC issuer must keep one.
    """
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
    return value


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
    """Audit trail settings."""

    details_max_bytes: int = Field(default=8192, ge=256, le=1_048_576)
    retention_days: int | None = None
    """Days of audit trail ``warden audit purge`` keeps. None (the default) keeps
    it for ever; any value set must be at least ``MIN_RETENTION_DAYS`` (365)."""
    trusted_proxies: Annotated[tuple[IPvAnyNetwork, ...], BeforeValidator(_split_list)] = ()
    """Reverse proxies whose ``X-Forwarded-For`` is believed, for audit records
    and identity's sign-in throttle alike."""

    @field_validator("retention_days")
    @classmethod
    def _retention_minimum(cls, value: int | None) -> int | None:
        if value is not None and value < MIN_RETENTION_DAYS:
            raise ValueError(
                f"must be at least {MIN_RETENTION_DAYS} days, or unset to keep the trail for ever"
            )
        return value


class SyslogConfig(_Section):
    """Syslog forwarding: every field ``SyslogSettings`` needs.

    ``SyslogSettings.from_config`` builds the forwarder's settings from this
    section; the defaults here are the forwarder's own.
    """

    enabled: bool = False
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    transport: Literal["udp", "tcp", "tls"] = "tls"
    framing: Literal["octet-counting", "lf"] = "octet-counting"
    """Stream framing (RFC 6587); UDP always sends one message per datagram."""
    sd_id: str = DEFAULT_SD_ID
    """Structured-data id, ``name@<PEN>``; ``warden@67382`` unless the product
    sets its own. The documentation number 32473 is refused."""
    app_name: str = Field(default="warden", max_length=48)
    hostname: str | None = Field(default=None, max_length=255)
    """RFC 5424 HOSTNAME as the collector should see it; None uses this host's name."""
    facility: int = Field(default=13, ge=0, le=23)
    """RFC 5424 facility; 13 is "log audit"."""
    max_message_bytes: int = Field(default=8192, ge=1024, le=65_000)
    """Whole-message cap in bytes, framing excluded."""
    tls_ca_file: str | None = None
    """CA bundle path; with neither this nor ``tls_ca_secret`` the system trust store is used."""
    tls_ca_secret: str | None = None
    """Name of the konfig secret holding the collector's CA certificates as PEM."""
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
        if value is not None and _PRINTABLE.fullmatch(value) is None:
            raise ValueError("must not contain spaces or control characters")
        return value

    @field_validator("tls_ca_secret")
    @classmethod
    def _secret_name(cls, value: str | None) -> str | None:
        return _check_secret_name(value)

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
            raise _FieldProblems(
                [(("backoff_max_seconds",), "must not be below backoff_initial_seconds")]
            )
        return self


class IdentityConfig(_Section):
    """Identity settings."""

    enabled: bool = True
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=28_800, ge=300)
    session_lifespan_seconds: int = Field(default=43_200, ge=300)
    refresh_reuse_grace_seconds: int = Field(default=10, ge=0, le=120)
    invitation_ttl_seconds: int = Field(default=604_800, ge=300)
    reset_ttl_seconds: int = Field(default=3600, ge=300, le=86_400)
    require_mfa: bool = True
    password_min_length: int = Field(default=12, ge=8, le=1024)

    totp_issuer: str | None = Field(default=None, min_length=1, max_length=64)
    """Issuer shown in authenticator apps; None uses the host of ``http.public_base_url``."""
    mfa_challenge_ttl_seconds: int = Field(default=300, ge=30, le=1800)
    """How long a second-factor or enrolment challenge stays usable."""
    mfa_max_failures: int = Field(default=5, ge=1, le=20)
    """Wrong codes a challenge tolerates before it is used up."""
    recovery_code_count: int = Field(default=10, ge=5, le=50)
    """Recovery codes issued at each enrolment."""
    policy_cache_seconds: float = Field(default=30.0, gt=0, le=3600)
    """Longest a replica serves its cached session policy without re-reading it,
    should a change notification be missed."""
    sign_in_attempt_limit: int = Field(default=10, ge=1, le=1000)
    """Password attempts per identifier and client address in each window."""
    sign_in_window_seconds: int = Field(default=900, ge=60, le=86_400)
    """Length of the sign-in throttle window."""
    totp_key_secret: str = "warden.totp-key"  # noqa: S105 - a secret name, not a secret
    """Name of the konfig secret holding the TOTP encryption key."""
    totp_previous_key_secret: str = "warden.totp-key.previous"  # noqa: S105
    """Name of the konfig secret holding the previous TOTP key while rotating."""

    api_key_prefix: str = "wdn_"
    """Prefix on every API key, so a leaked key is recognisable. Provisional until 0.1.0b1."""
    api_key_max_lifetime_days: int | None = Field(default=365, ge=1, le=3660)
    """Longest lifetime an API key may be given; None allows keys that never
    expire. Provisional until 0.1.0b1."""

    @field_validator("totp_issuer")
    @classmethod
    def _issuer_shape(cls, value: str | None) -> str | None:
        # Shown in an otpauth:// label, where ':' separates issuer and account.
        if value is not None and (any(ch < " " or ch == "\x7f" for ch in value) or ":" in value):
            raise ValueError("must not contain control characters or ':'")
        return value

    @field_validator("totp_key_secret", "totp_previous_key_secret")
    @classmethod
    def _secret_names(cls, value: str) -> str:
        _check_secret_name(value)
        return value

    @field_validator("api_key_prefix")
    @classmethod
    def _api_key_prefix_shape(cls, value: str) -> str:
        if _API_KEY_PREFIX.fullmatch(value) is None:
            raise ValueError("must be 1 to 16 lower-case letters, digits or '_'")
        return value

    @model_validator(mode="after")
    def _lifetimes_consistent(self) -> Self:
        problems: list[tuple[tuple[str, ...], str]] = []
        if self.totp_key_secret == self.totp_previous_key_secret:
            problems.append((("totp_previous_key_secret",), "must differ from totp_key_secret"))
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
    """OIDC single sign-on. Provisional until 0.1.0b1: the single sign-on
    workstream settles the fields."""

    enabled: bool = False
    issuer_url: str | None = None
    client_id: str | None = None
    client_secret: str = "warden.sso.client-secret"  # noqa: S105 - a secret's name
    """Name of the konfig secret holding the OIDC client secret, never the
    secret itself. The secret is stored through ``PUT <admin>/sso/client-secret``."""
    scopes: Annotated[tuple[str, ...], BeforeValidator(_split_list)] = (
        "openid",
        "email",
        "profile",
    )
    allowed_email_domains: Annotated[tuple[str, ...], BeforeValidator(_split_list)] = ()
    provider_preset: Literal["entra", "google", "okta", "generic"] = "generic"
    """A label for setup guidance only; it never changes behaviour."""
    discovery_cache_seconds: int = Field(default=3600, ge=60, le=86_400)
    jwks_cache_seconds: int = Field(default=3600, ge=60, le=86_400)
    """How long the provider's signing keys are cached. Provisional until 0.1.0b1."""
    jwks_refetch_min_seconds: int = Field(default=60, ge=1, le=3600)
    """Shortest interval between fetches forced by an unknown key id, so a
    stream of forged tokens cannot hammer the provider. Provisional until 0.1.0b1."""
    login_transaction_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    """How long a started sign-in (state, nonce, PKCE verifier) stays
    usable. Provisional until 0.1.0b1."""
    handoff_code_ttl_seconds: int = Field(default=60, ge=5, le=300)
    """How long the single-use code handed to the product's completion
    screen stays usable. Provisional until 0.1.0b1."""
    allowed_algorithms: Annotated[tuple[str, ...], BeforeValidator(_split_list)] = (
        "RS256",
        "ES256",
        "PS256",
    )
    """id_token signature algorithms accepted: asymmetric only, never ``none``
    or HS*. Provisional until 0.1.0b1."""
    clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    """Leeway when checking id_token times. Provisional until 0.1.0b1."""

    @field_validator("client_secret")
    @classmethod
    def _client_secret_name(cls, value: str) -> str:
        _check_secret_name(value)
        return value

    @field_validator("allowed_algorithms")
    @classmethod
    def _algorithms_asymmetric(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("must name at least one algorithm")
        if any(name not in _ASYMMETRIC_ALGORITHMS for name in value):
            allowed = ", ".join(sorted(_ASYMMETRIC_ALGORITHMS))
            raise ValueError(f"may contain only asymmetric algorithms: {allowed}")
        return value

    @model_validator(mode="after")
    def _jwks_timings_consistent(self) -> Self:
        if self.jwks_refetch_min_seconds > self.jwks_cache_seconds:
            raise _FieldProblems(
                [(("jwks_refetch_min_seconds",), "must not exceed jwks_cache_seconds")]
            )
        return self

    @field_validator("issuer_url")
    @classmethod
    def _issuer_shape(cls, value: str | None) -> str | None:
        # Kept verbatim, trailing slash included: discovery and id_token
        # checks compare it with the provider's issuer by exact equality.
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
    """Mail settings. The product implements the sender. Provisional until 0.1.0b1."""

    from_address: str | None = None
    from_name: str | None = None
    reply_to: str | None = None
    template_package: str | None = None
    """Importable package holding the product's message templates, which
    replace warden's own template by template. Provisional until 0.1.0b1."""
    subject_prefix: str | None = Field(default=None, max_length=64)
    """Text put before every message subject, such as the product's name.
    Provisional until 0.1.0b1."""

    @field_validator("template_package")
    @classmethod
    def _package_shape(cls, value: str | None) -> str | None:
        if value is not None and _PACKAGE.fullmatch(value) is None:
            raise ValueError("must be a dotted Python package name")
        return value

    @field_validator("from_address", "reply_to")
    @classmethod
    def _address_shape(cls, value: str | None) -> str | None:
        if value is not None and _EMAIL.fullmatch(value) is None:
            raise ValueError("must be an email address")
        return value

    @field_validator("from_name", "subject_prefix")
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
    passkey_registration_link: str | None = None
    """Template for the product's screen that registers a passkey from an
    administrator's emailed link; must contain ``{token}``."""

    @field_validator("public_base_url")
    @classmethod
    def _base_url_shape(cls, value: str) -> str:
        return _check_url(value).rstrip("/")

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

    @field_validator("passkey_registration_link")
    @classmethod
    def _passkey_link_shape(cls, value: str | None) -> str | None:
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


def _is_domain(host: str) -> bool:
    """A lower-case DNS name, or ``localhost``; never an IP address."""
    return host == "localhost" or (len(host) <= 253 and _DOMAIN.fullmatch(host) is not None)


def _serialise_origin(scheme: str, host: str, port: int | None) -> str:
    """An origin as a browser serialises it: no path, no default port."""
    shown = f"[{host}]" if ":" in host else host
    suffix = "" if port is None or port == _DEFAULT_PORTS.get(scheme) else f":{port}"
    return f"{scheme}://{shown}{suffix}"


def _base_origin(url: str) -> str:
    parts = urlsplit(url)
    return _serialise_origin(parts.scheme.lower(), (parts.hostname or "").lower(), parts.port)


def _check_origin(value: str) -> str:
    """An exact origin, ``https://host[:port]``; plain http only for localhost."""
    if _PRINTABLE.fullmatch(value) is None:
        raise ValueError(_ORIGIN_SHAPE)
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        raise ValueError(_ORIGIN_SHAPE) from None
    host = parts.hostname or ""
    if parts.scheme not in ("http", "https") or not _is_domain(host):
        raise ValueError(_ORIGIN_SHAPE)
    if value != _serialise_origin(parts.scheme, host, port):
        raise ValueError(_ORIGIN_SHAPE)
    if parts.scheme == "http" and host != "localhost" and not host.endswith(".localhost"):
        raise ValueError("each entry must use https unless the host is localhost")
    return value


class WebAuthnConfig(_Section):
    """Passkeys and security keys (WebAuthn): the relying party and ceremony limits.

    With nothing set, the relying party is the host of ``http.public_base_url``
    and the only allowed origin is that URL's origin. User verification is not
    a setting: a ceremony prefers it for a second factor and requires it for
    passkey sign-in (ruling P7).
    """

    rp_id: str | None = None
    """Relying party id; None uses the host of ``http.public_base_url``. It must
    be the host of every allowed origin or a registrable suffix of it."""
    rp_name: str | None = Field(default=None, min_length=1, max_length=64)
    """Name an authenticator shows; None uses the relying party id."""
    allowed_origins: Annotated[tuple[str, ...], BeforeValidator(_split_list)] = ()
    """Origins a ceremony response may come from, compared exactly; empty uses
    the origin of ``http.public_base_url``. No wildcards."""
    challenge_ttl_seconds: int = Field(default=300, ge=30, le=1800)
    """How long a registration or sign-in challenge stays usable."""
    client_timeout_seconds: int = Field(default=240, ge=30, le=1800)
    """The timeout hint sent to the browser; at most ``challenge_ttl_seconds``."""
    max_credentials_per_user: int = Field(default=10, ge=1, le=100)
    """Most passkeys and security keys one user may register."""
    attestation_roots: str | None = None
    """Trusted attestation roots as PEM certificates, usually
    ``secret://<name>``. Unset or empty accepts any authenticator; set, only
    authenticators whose attestation chains to one of them may register
    (ruling P3). warden never fetches attestation metadata."""

    @field_validator("rp_id")
    @classmethod
    def _rp_id_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.lower()
        if not _is_domain(lowered):
            raise ValueError("must be a domain name such as example.com, not an IP address")
        return lowered

    @field_validator("rp_name")
    @classmethod
    def _rp_name_shape(cls, value: str | None) -> str | None:
        if value is not None and any(ch < " " or ch == "\x7f" for ch in value):
            raise ValueError("must not contain control characters")
        return value

    @field_validator("allowed_origins")
    @classmethod
    def _origins_shape(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for origin in value:
            _check_origin(origin)
        return value

    @field_validator("attestation_roots")
    @classmethod
    def _roots_shape(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        try:
            certificates = x509.load_pem_x509_certificates(value.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise ValueError("must hold one or more PEM certificates") from None
        for certificate in certificates:
            try:
                constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
            except x509.ExtensionNotFound:
                raise ValueError("each certificate must be a CA certificate") from None
            if not constraints.value.ca:
                raise ValueError("each certificate must be a CA certificate")
        return value

    @model_validator(mode="after")
    def _timeout_within_lifetime(self) -> Self:
        if self.client_timeout_seconds > self.challenge_ttl_seconds:
            raise _FieldProblems(
                [(("client_timeout_seconds",), "must not exceed challenge_ttl_seconds")]
            )
        return self

    def relying_party_id(self, http: HttpConfig) -> str | None:
        """The relying party id, or None when WebAuthn is unavailable.

        It is unavailable only when nothing is set and the base URL's host is
        an IP address, which browsers refuse as a relying party id.
        """
        if self.rp_id is not None:
            return self.rp_id
        host = (urlsplit(http.public_base_url).hostname or "").lower()
        return host if _is_domain(host) else None

    def relying_party_name(self, http: HttpConfig) -> str:
        if self.rp_name is not None:
            return self.rp_name
        return self.relying_party_id(http) or (urlsplit(http.public_base_url).hostname or "")

    def origins(self, http: HttpConfig) -> tuple[str, ...]:
        """The origins a ceremony response may come from, compared exactly."""
        return self.allowed_origins or (_base_origin(http.public_base_url),)

    def _relying_party_problems(self, http: HttpConfig) -> list[tuple[tuple[str, ...], str]]:
        """Whether the relying party id covers every origin (fido2's public suffix rules)."""
        explicit = self.rp_id is not None or bool(self.allowed_origins)
        rp_id = self.relying_party_id(http)
        if rp_id is None:
            if not explicit:
                return []
            return [(("rp_id",), "is required when http.public_base_url's host is not a domain")]
        if all(verify_rp_id(rp_id, origin) for origin in self.origins(http)):
            return []
        if self.rp_id is not None:
            return [(("rp_id",), "must be every allowed origin's host or a registrable suffix of it")]
        return [(("allowed_origins",), "each origin's host must be rp_id or a subdomain of it")]


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
    webauthn: WebAuthnConfig = WebAuthnConfig()

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
            for name in ("issuer_url", "client_id"):
                if getattr(self.sso, name) is None:
                    problems.append((("sso", name), "is required while sso is enabled"))
            if self.http.sso_completion_link is None:
                problems.append(
                    (("http", "sso_completion_link"), "is required while sso is enabled")
                )
        if self.syslog.enabled:
            for name in ("host", "port"):
                if getattr(self.syslog, name) is None:
                    problems.append((("syslog", name), "is required while syslog is enabled"))
        for path, reason in self.webauthn._relying_party_problems(self.http):
            problems.append((("webauthn", *path), reason))
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
