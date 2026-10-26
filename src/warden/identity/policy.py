"""Session policy: token lifetimes, the session lifespan, reuse grace and MFA.

Configuration supplies the defaults. An administrator may override them at
run time; the overrides live in ``warden.settings`` and every replica caches
the effective policy. A change issues ``pg_notify`` in the same transaction,
so every listening replica drops its cache as soon as the change commits.
A replica that is not listening still re-reads within ``max_age`` seconds.

Shortening the session lifespan takes effect on existing sessions too: a
session is valid only while younger than both the lifespan it started with
and the current one.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg import AsyncConnection, sql
from psycopg.types.json import Jsonb

from warden.audit import AuditEvent, record_audit
from warden.config import IdentityConfig
from warden.db import SETTINGS, Database, table

__all__ = ["POLICY_CHANNEL", "POLICY_SETTING", "PolicyError", "PolicyStore", "SessionPolicy"]

logger = logging.getLogger(__name__)

# ``warden.settings`` key holding the administrator's overrides, and the
# channel a change is announced on. (Both belong in ``warden.db.schema``;
# recorded for the integration session.)
POLICY_SETTING = "identity.session_policy"
POLICY_CHANNEL = "warden_identity_policy"

_SETTINGS = table(SETTINGS)


class PolicyError(ValueError):
    """A policy change was refused."""


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    access_token_ttl_seconds: int
    refresh_token_ttl_seconds: int
    session_lifespan_seconds: int
    refresh_reuse_grace_seconds: int
    require_mfa: bool

    @classmethod
    def from_config(cls, config: IdentityConfig) -> SessionPolicy:
        return cls(
            access_token_ttl_seconds=config.access_token_ttl_seconds,
            refresh_token_ttl_seconds=config.refresh_token_ttl_seconds,
            session_lifespan_seconds=config.session_lifespan_seconds,
            refresh_reuse_grace_seconds=config.refresh_reuse_grace_seconds,
            require_mfa=config.require_mfa,
        )

    def validate(self) -> None:
        """The same rules configuration applies at start-up."""
        problems: list[str] = []
        for name in (
            "access_token_ttl_seconds",
            "refresh_token_ttl_seconds",
            "session_lifespan_seconds",
            "refresh_reuse_grace_seconds",
        ):
            value = getattr(self, name)
            if type(value) is not int:
                problems.append(f"{name} must be an integer")
        if type(self.require_mfa) is not bool:
            problems.append("require_mfa must be true or false")
        if problems:
            raise PolicyError("; ".join(problems))
        if not 60 <= self.access_token_ttl_seconds <= 3600:
            problems.append("access_token_ttl_seconds must be between 60 and 3600")
        if self.refresh_token_ttl_seconds < 300:
            problems.append("refresh_token_ttl_seconds must be at least 300")
        if self.session_lifespan_seconds < 300:
            problems.append("session_lifespan_seconds must be at least 300")
        if not 0 <= self.refresh_reuse_grace_seconds <= 120:
            problems.append("refresh_reuse_grace_seconds must be between 0 and 120")
        if self.access_token_ttl_seconds >= self.refresh_token_ttl_seconds:
            problems.append(
                "access_token_ttl_seconds must be shorter than refresh_token_ttl_seconds"
            )
        if self.refresh_token_ttl_seconds > self.session_lifespan_seconds:
            problems.append("refresh_token_ttl_seconds must not exceed session_lifespan_seconds")
        if problems:
            raise PolicyError("; ".join(problems))


_FIELDS = frozenset(f.name for f in dataclasses.fields(SessionPolicy))


class PolicyStore:
    """The effective session policy, cached per replica and invalidated over NOTIFY."""

    def __init__(
        self,
        db: Database,
        defaults: SessionPolicy,
        *,
        max_age: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        defaults.validate()
        self._db = db
        self._defaults = defaults
        self._max_age = max_age
        self._clock = clock
        self._cached: SessionPolicy | None = None
        self._listening = False
        self._loaded_at = 0.0
        self._generation = 0

    @property
    def listening(self) -> bool:
        """Whether ``listen()`` currently holds a LISTEN on the policy channel."""
        return self._listening

    @property
    def defaults(self) -> SessionPolicy:
        return self._defaults

    def invalidate(self) -> None:
        """Forget the cached policy; the next ``current()`` re-reads it."""
        self._generation += 1
        self._cached = None

    async def current(self) -> SessionPolicy:
        cached = self._cached
        if cached is not None and self._clock() - self._loaded_at < self._max_age:
            return cached
        generation = self._generation
        async with self._db.connection() as conn:
            overrides = await self._read(conn)
        try:
            policy = self._effective(overrides)
        except (PolicyError, TypeError):
            # Stored overrides that no longer fit the configured defaults must not
            # break every request; configuration wins until an administrator fixes it.
            logger.warning("stored session policy overrides are invalid; using configuration")
            policy = self._defaults
        # An invalidation that arrived during the read wins; do not cache stale data.
        if generation == self._generation:
            self._cached, self._loaded_at = policy, self._clock()
        return policy

    async def update(
        self, *, actor: str | None, conn: AsyncConnection[Any] | None = None, **changes: Any
    ) -> SessionPolicy:
        """Override some fields. Validated as a whole; audited; announced on commit."""
        unknown = set(changes) - _FIELDS
        if unknown:
            raise PolicyError(f"unknown policy fields: {', '.join(sorted(unknown))}")
        async with self._db.transaction(conn) as tx:
            await tx.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (POLICY_SETTING,))
            overrides = {**await self._read(tx), **changes}
            policy = self._effective(overrides)
            await self._write(tx, overrides)
            await record_audit(
                AuditEvent(
                    action="identity.policy.changed",
                    outcome="success",
                    actor=actor,
                    resource_type="session_policy",
                    details=dict(sorted(changes.items())),
                ),
                conn=tx,
            )
        if conn is None:
            self.invalidate()
        return policy

    async def reset(self, *, actor: str | None) -> SessionPolicy:
        """Drop every override, returning to configuration."""
        async with self._db.transaction() as tx:
            await tx.execute(
                sql.SQL("DELETE FROM {} WHERE key = %s").format(_SETTINGS), (POLICY_SETTING,)
            )
            await tx.execute("SELECT pg_notify(%s, '')", (POLICY_CHANNEL,))
            await record_audit(
                AuditEvent(
                    action="identity.policy.changed",
                    outcome="success",
                    actor=actor,
                    resource_type="session_policy",
                    details={"reset": True},
                ),
                conn=tx,
            )
        self.invalidate()
        return self._defaults

    async def listen(self, *, ready: asyncio.Event | None = None) -> None:
        """Drop the cache whenever any replica changes the policy. Runs until cancelled.

        Holds one pooled connection while running. Reconnects after a lost
        connection, dropping the cache each time, since a change may have
        been missed meanwhile.
        """
        while True:
            try:
                async with self._db.connection() as conn:
                    await conn.set_autocommit(True)
                    await conn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(POLICY_CHANNEL)))
                    self.invalidate()
                    self._listening = True
                    if ready is not None:
                        ready.set()
                    async for _notify in conn.notifies():
                        self.invalidate()
            except psycopg.OperationalError:
                logger.warning("session policy listener lost its connection; reconnecting")
                self.invalidate()
                await asyncio.sleep(1.0)
            finally:
                self._listening = False

    async def _read(self, conn: AsyncConnection[Any]) -> dict[str, Any]:
        cur = await conn.execute(
            sql.SQL("SELECT value FROM {} WHERE key = %s").format(_SETTINGS), (POLICY_SETTING,)
        )
        row = await cur.fetchone()
        if row is None or not isinstance(row[0], dict):
            return {}
        return {k: v for k, v in row[0].items() if k in _FIELDS}

    async def _write(self, tx: AsyncConnection[Any], overrides: dict[str, Any]) -> None:
        await tx.execute(
            sql.SQL(
                "INSERT INTO {} (key, value, updated_at) VALUES (%s, %s, now())"
                " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()"
            ).format(_SETTINGS),
            (POLICY_SETTING, Jsonb(overrides)),
        )
        await tx.execute("SELECT pg_notify(%s, '')", (POLICY_CHANNEL,))

    def _effective(self, overrides: dict[str, Any]) -> SessionPolicy:
        try:
            policy = dataclasses.replace(self._defaults, **overrides)
        except TypeError:
            raise PolicyError("unknown policy fields") from None
        policy.validate()
        return policy
