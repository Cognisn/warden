"""Single sign-on settings: configuration defaults and run-time overrides.

``sso.*`` configuration supplies the defaults. An administrator may override
``enabled``, ``issuer_url``, ``client_id``, ``scopes``,
``allowed_email_domains`` and ``provider_preset`` at run time; the overrides
live in ``warden.settings`` under ``SSO_SETTING`` and are validated by the
same rules as configuration at start-up. Every change is audited.

Every other ``sso.*`` value (the client secret's name, timings, algorithms)
stays configuration-only. The client secret itself is written through
konfig's secrets store and never read back (``SingleSignOn.set_client_secret``).

A change takes ``SSO_SETTINGS_LOCK_KEY`` exclusively. Issuing a session
through single sign-on takes it shared and re-reads the settings inside
that transaction, so turning single sign-on off and ending its sessions
(``revoke_sso_sessions``) cannot miss a session being issued at the same
moment. Each replica caches the settings for ``identity.policy_cache_seconds``
for the earlier sign-in steps, which only lead to that check.

No lock-out by single sign-on (ruling CS17): a change that leaves single
sign-on unusable (off, or without an issuer or client id) is refused with
``SsoStillRequired`` while it was usable and the instance default, or any
active user's own, pending or in-force method, is ``sso_only``. Changing
any of those to ``sso_only`` takes the same lock shared, so the check
cannot miss one. The refusal is audited.
"""

from __future__ import annotations

import dataclasses
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from psycopg import AsyncConnection, sql
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from warden.audit import AuditEvent, record_audit
from warden.config import SsoConfig, WardenConfig
from warden.db import SETTINGS, Database, schema, table
from warden.identity.http import SourceIp
from warden.identity.sso.schema import SSO_SETTING, SSO_SETTINGS_LOCK_KEY
from warden.identity.users import effective_method_sql, pending_method_sql

__all__ = [
    "SSO_AMR",
    "SsoSettings",
    "SsoSettingsError",
    "SsoSettingsStore",
    "SsoStillRequired",
    "revoke_sso_sessions",
    "usable",
]

logger = logging.getLogger(__name__)

# The authentication method recorded on sessions issued through single sign-on.
SSO_AMR = "sso"

_SETTINGS = table(SETTINGS)
_SESSIONS = table(schema.SESSIONS)
_USERS = table(schema.USERS)
_SIGN_IN_SETTINGS = table(schema.SIGN_IN_SETTINGS)
_SSO_ONLY = "sso_only"


class SsoSettingsError(ValueError):
    """A settings change was refused. The message names fields, never values."""


class SsoStillRequired(SsoSettingsError):
    """Single sign-on cannot be turned off or cleared: someone signs in with it alone.

    ``default_sso_only`` says whether the instance default is ``sso_only``;
    ``users`` lists each active user whose own, pending or in-force method
    is ``sso_only``, as (id, email), for the administrator to move first
    (ruling CS17). The message carries counts only.
    """

    def __init__(self, *, default_sso_only: bool, users: tuple[tuple[uuid.UUID, str], ...]) -> None:
        parts = []
        if default_sso_only:
            parts.append("the default sign-in method is sso_only")
        if users:
            parts.append(f"{len(users)} active users sign in with sso_only")
        super().__init__(
            "single sign-on cannot be turned off or cleared while " + " and ".join(parts)
        )
        self.default_sso_only = default_sso_only
        self.users = users


@dataclass(frozen=True, slots=True)
class SsoSettings:
    enabled: bool
    issuer_url: str | None
    client_id: str | None
    scopes: tuple[str, ...]
    allowed_email_domains: tuple[str, ...]
    provider_preset: str
    """A label for setup guidance only; sign-in never reads it."""


_FIELDS = frozenset(f.name for f in dataclasses.fields(SsoSettings))


def _from_config(sso: SsoConfig) -> SsoSettings:
    return SsoSettings(**{name: getattr(sso, name) for name in _FIELDS})


def usable(settings: SsoSettings) -> bool:
    """Whether single sign-on works: enabled, with an issuer and a client id."""
    return settings.enabled and settings.issuer_url is not None and settings.client_id is not None


async def _sso_dependants(conn: AsyncConnection[Any]) -> SsoStillRequired | None:
    """Who would be locked out without single sign-on, as the refusal; None if nobody."""
    cur = await conn.execute(
        sql.SQL("SELECT default_sign_in_method = %s FROM {}").format(_SIGN_IN_SETTINGS),
        (_SSO_ONLY,),
    )
    row = await cur.fetchone()
    default_sso_only = bool(row and row[0])
    cur = await conn.execute(
        sql.SQL(
            "SELECT u.id, u.email FROM {} u WHERE u.status = 'active'"
            " AND %(sso)s IN (u.sign_in_method, {}, {}) ORDER BY lower(u.email), u.id"
        ).format(_USERS, effective_method_sql("u"), pending_method_sql("u")),
        {"sso": _SSO_ONLY},
    )
    users = tuple((r[0], str(r[1])) for r in await cur.fetchall())
    if not default_sso_only and not users:
        return None
    return SsoStillRequired(default_sso_only=default_sso_only, users=users)


async def revoke_sso_sessions(conn: AsyncConnection[Any], reason: str) -> int:
    """End every live session issued through single sign-on. Returns how many ended."""
    cur = await conn.execute(
        sql.SQL(
            "UPDATE {} SET revoked_at = now(), revoked_reason = %s"
            " WHERE revoked_at IS NULL AND %s = ANY(amr)"
        ).format(_SESSIONS),
        (reason, SSO_AMR),
    )
    return cur.rowcount


class SsoSettingsStore:
    def __init__(
        self,
        db: Database,
        config: WardenConfig,
        *,
        max_age: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._db = db
        self._config = config
        self._defaults = _from_config(config.sso)
        self._max_age = max_age
        self._clock = clock
        self._cached: SsoSettings | None = None
        self._loaded_at = 0.0

    @property
    def defaults(self) -> SsoSettings:
        return self._defaults

    def invalidate(self) -> None:
        self._cached = None

    async def current(self) -> SsoSettings:
        """The effective settings, cached for ``max_age`` seconds."""
        cached = self._cached
        if cached is not None and self._clock() - self._loaded_at < self._max_age:
            return cached
        async with self._db.connection() as conn:
            settings = await self.read(conn)
        self._cached, self._loaded_at = settings, self._clock()
        return settings

    async def read(self, conn: AsyncConnection[Any]) -> SsoSettings:
        """The effective settings, read now on ``conn`` (no cache)."""
        overrides = await self._overrides(conn)
        try:
            return self._effective(overrides)
        except SsoSettingsError:
            # Stored overrides that no longer fit configuration must not break
            # sign-in; configuration wins until an administrator fixes them.
            logger.warning("stored single sign-on overrides are invalid; using configuration")
            return self._defaults

    async def update(
        self, *, actor: str | None, source_ip: SourceIp = None, **changes: Any
    ) -> SsoSettings:
        """Override some fields: validated as a whole, audited, and, when this
        turns single sign-on off, every SSO session ended in the same transaction.

        ``source_ip`` is the client address the change was asked from, if any."""
        unknown = set(changes) - _FIELDS
        if unknown:
            raise SsoSettingsError(f"unknown settings: {', '.join(sorted(unknown))}")
        wrong = sorted(name for name, value in changes.items() if not _typed(name, value))
        if wrong:
            raise SsoSettingsError(f"invalid settings: {', '.join(wrong)}")
        try:
            async with self._db.transaction() as tx:
                await tx.execute("SELECT pg_advisory_xact_lock(%s)", (SSO_SETTINGS_LOCK_KEY,))
                before = await self.read(tx)
                overrides = {**await self._overrides(tx), **_plain(changes)}
                settings = self._effective(overrides)
                await self._guard(tx, before, settings)
                await tx.execute(
                    sql.SQL(
                        "INSERT INTO {} (key, value, updated_at) VALUES (%s, %s, now())"
                        " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value,"
                        " updated_at = now()"
                    ).format(_SETTINGS),
                    (SSO_SETTING, Jsonb(cast(Any, overrides))),
                )
                await self._record_change(tx, actor, source_ip, before, settings, sorted(changes))
        except SsoStillRequired as exc:
            await self._record_refusal(actor, source_ip, exc, sorted(changes))
            raise
        self.invalidate()
        return settings

    async def reset(self, *, actor: str | None, source_ip: SourceIp = None) -> SsoSettings:
        """Drop every override, returning to configuration.

        ``source_ip`` is the client address the reset was asked from, if any.
        """
        try:
            async with self._db.transaction() as tx:
                await tx.execute("SELECT pg_advisory_xact_lock(%s)", (SSO_SETTINGS_LOCK_KEY,))
                before = await self.read(tx)
                await self._guard(tx, before, self._defaults)
                await tx.execute(
                    sql.SQL("DELETE FROM {} WHERE key = %s").format(_SETTINGS), (SSO_SETTING,)
                )
                await self._record_change(tx, actor, source_ip, before, self._defaults, ["reset"])
        except SsoStillRequired as exc:
            await self._record_refusal(actor, source_ip, exc, ["reset"])
            raise
        self.invalidate()
        return self._defaults

    async def _guard(
        self, tx: AsyncConnection[Any], before: SsoSettings, after: SsoSettings
    ) -> None:
        """Refuse leaving single sign-on unusable while anyone signs in with it alone."""
        if usable(before) and not usable(after):
            refusal = await _sso_dependants(tx)
            if refusal is not None:
                raise refusal

    async def _record_refusal(
        self,
        actor: str | None,
        source_ip: SourceIp,
        refusal: SsoStillRequired,
        changed: list[str],
    ) -> None:
        await record_audit(
            AuditEvent(
                action="warden.identity.sso.settings_changed",
                outcome="failure",
                actor=actor,
                resource_type="sso_settings",
                source_ip=source_ip,
                details={
                    "changed": list[Any](changed),
                    "reason": "sso_still_required",
                    "default_sso_only": refusal.default_sso_only,
                    "user_ids": [str(user_id) for user_id, _ in refusal.users],
                },
            )
        )

    async def _record_change(
        self,
        tx: AsyncConnection[Any],
        actor: str | None,
        source_ip: SourceIp,
        before: SsoSettings,
        after: SsoSettings,
        changed: list[str],
    ) -> None:
        await record_audit(
            AuditEvent(
                action="warden.identity.sso.settings_changed",
                outcome="success",
                actor=actor,
                resource_type="sso_settings",
                source_ip=source_ip,
                details={"changed": list[Any](changed), "enabled": after.enabled},
            ),
            conn=tx,
        )
        if before.enabled and not after.enabled:
            ended = await revoke_sso_sessions(tx, "sso_disabled")
            await record_audit(
                AuditEvent(
                    action="warden.identity.sso.disabled",
                    outcome="success",
                    actor=actor,
                    resource_type="sso_settings",
                    source_ip=source_ip,
                    details={"sessions_revoked": ended},
                ),
                conn=tx,
            )

    async def _overrides(self, conn: AsyncConnection[Any]) -> dict[str, Any]:
        cur = await conn.execute(
            sql.SQL("SELECT value FROM {} WHERE key = %s").format(_SETTINGS), (SSO_SETTING,)
        )
        row = await cur.fetchone()
        if row is None or not isinstance(row[0], dict):
            return {}
        return {k: v for k, v in row[0].items() if k in _FIELDS}

    def _effective(self, overrides: dict[str, Any]) -> SsoSettings:
        merged = {**self._config.sso.model_dump(), **overrides}
        try:
            sso = SsoConfig.model_validate(merged)
        except ValidationError as exc:
            fields = sorted({str(e["loc"][0]) for e in exc.errors() if e.get("loc")})
            raise SsoSettingsError(f"invalid settings: {', '.join(fields)}") from None
        settings = _from_config(sso)
        if settings.enabled:
            missing = [n for n in ("issuer_url", "client_id") if getattr(settings, n) is None]
            if self._config.http.sso_completion_link is None:
                missing.append("http.sso_completion_link")
            if missing:
                raise SsoSettingsError(f"required while enabled: {', '.join(missing)}")
        return settings


def _typed(name: str, value: object) -> bool:
    """Run-time changes arrive as JSON: no coercion of strings to booleans or lists."""
    if name == "enabled":
        return isinstance(value, bool)
    if name in ("scopes", "allowed_email_domains"):
        return isinstance(value, list | tuple) and all(isinstance(v, str) for v in value)
    if name in ("issuer_url", "client_id"):
        return value is None or isinstance(value, str)
    return isinstance(value, str)


def _plain(changes: dict[str, Any]) -> dict[str, Any]:
    """Values as JSON stores them (tuples as lists)."""
    return {k: list(v) if isinstance(v, tuple) else v for k, v in changes.items()}
