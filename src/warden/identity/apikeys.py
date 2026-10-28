"""API keys: long-lived bearer credentials for a user's scripts and integrations.

A key is ``<identity.api_key_prefix>`` followed by 32 random bytes in
base64url, shown once when created and stored only as its SHA-256 hash
(the key is high-entropy, so a fast hash is enough). A short ``hint`` (the
prefix and the first few characters) is kept so a person can recognise a
key in a list.

Every key expires within ``identity.api_key_max_lifetime_days`` (unless
that is None), can be revoked, and is scoped to a set of the product's
permissions no wider than its user's when it is created. On every use the
key's permissions are its scopes intersected with the user's **current**
permissions, so a key never exceeds its user, and a key whose user is not
active is refused (#132). Every refusal gets the same response; the reason
goes to the audit trail.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn

from psycopg import sql

from warden.audit import ActionRegistry, AuditEvent, Severity, record_audit
from warden.audit.registry import register_warden_action
from warden.config import IdentityConfig
from warden.db import Database, schema, table
from warden.identity.dependencies import Principal
from warden.identity.errors import AuthenticationRefused
from warden.identity.http import SourceIp
from warden.identity.roles import Roles
from warden.identity.users import UserStatus

__all__ = [
    "API_KEYS",
    "API_KEY_ACTIONS",
    "ApiKey",
    "ApiKeyError",
    "ApiKeys",
    "NewApiKey",
    "register_actions",
]

API_KEYS = "api_keys"

API_KEY_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    (
        "warden.identity.api_key.created",
        Severity.NOTICE,
        "{actor} created an API key for {resource_id}",
    ),
    (
        "warden.identity.api_key.revoked",
        Severity.NOTICE,
        "{actor} revoked an API key of {resource_id}",
    ),
    (
        "warden.identity.api_key.authenticate",
        Severity.WARNING,
        "API key refused: {outcome}",
    ),
)

_KEYS = table(API_KEYS)
_USERS = table(schema.USERS)
_KEY_BODY = r"[A-Za-z0-9_-]{43}"  # secrets.token_urlsafe(32)
_HINT_CHARS = 6
_MAX_NAME = 100
# Recording every use would write on every request; once a minute is enough.
_LAST_USED_RESOLUTION_SECONDS = 60
_COLUMNS = sql.SQL(
    "id, user_id, name, hint, scopes, created_at, created_by, expires_at, revoked_at, last_used_at"
)


def register_actions(registry: ActionRegistry) -> None:
    for action, severity, summary in API_KEY_ACTIONS:
        register_warden_action(registry, action, severity=severity, summary=summary)


class ApiKeyError(Exception):
    """An API key change was refused. Messages carry no values."""


@dataclass(frozen=True, slots=True)
class ApiKey:
    """A stored key, without its secret."""

    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    hint: str
    scopes: frozenset[str]
    created_at: datetime
    created_by: str | None
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None


@dataclass(frozen=True, slots=True)
class NewApiKey:
    """A key just created. ``key`` is shown once and never stored."""

    key: str
    api_key: ApiKey


def _row_to_key(row: tuple[Any, ...]) -> ApiKey:
    return ApiKey(
        id=row[0],
        user_id=row[1],
        name=row[2],
        hint=row[3],
        scopes=frozenset(row[4]),
        created_at=row[5],
        created_by=row[6],
        expires_at=row[7],
        revoked_at=row[8],
        last_used_at=row[9],
    )


def _hash(key: str) -> bytes:
    return hashlib.sha256(key.encode("ascii")).digest()


class ApiKeys:
    """Keys in ``warden.api_keys``."""

    def __init__(self, config: IdentityConfig, db: Database, roles: Roles) -> None:
        self._db = db
        self._roles = roles
        self._prefix = config.api_key_prefix
        self._max_lifetime = (
            None
            if config.api_key_max_lifetime_days is None
            else timedelta(days=config.api_key_max_lifetime_days)
        )
        self._shape = re.compile(re.escape(self._prefix) + _KEY_BODY)

    def looks_like_key(self, token: str) -> bool:
        """Whether a bearer token should be checked as an API key rather than an access token.

        Access tokens always contain dots and keys never do, so a bearer is
        routed to exactly one kind of check.
        """
        return token.startswith(self._prefix) and "." not in token

    async def create(
        self,
        user_id: uuid.UUID,
        name: str,
        scopes: Iterable[str],
        *,
        actor: str | None,
        expires_at: datetime | None = None,
        source_ip: SourceIp = None,
    ) -> NewApiKey:
        """Create a key for an active user, scoped within the user's current permissions.

        ``expires_at`` defaults to the longest lifetime allowed and may not
        exceed it.
        """
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= _MAX_NAME
            or any(ch < " " or ch == "\x7f" for ch in name)
        ):
            raise ApiKeyError(f"a key name must be 1 to {_MAX_NAME} printable characters")
        wanted = frozenset(scopes)
        registered = self._roles.registry.permissions().keys()
        if not wanted or not wanted <= registered:
            raise ApiKeyError("a key needs at least one scope, each a registered permission")
        expiry = self._expiry(expires_at)
        key = self._prefix + secrets.token_urlsafe(32)
        hint = key[: len(self._prefix) + _HINT_CHARS]
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("SELECT status FROM {} WHERE id = %s FOR SHARE").format(_USERS),
                (user_id,),
            )
            row = await cur.fetchone()
            if row is None or row[0] != UserStatus.ACTIVE:
                raise ApiKeyError("API keys are issued only to active users")
            held = self._roles.registry.permissions_for(
                await self._roles.roles_of(user_id, conn=tx)
            )
            if not wanted <= held:
                raise ApiKeyError("a key's scopes may not exceed its user's permissions")
            cur = await tx.execute(
                sql.SQL(
                    "INSERT INTO {} (user_id, name, key_hash, hint, scopes, created_by, expires_at)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING {}"
                ).format(_KEYS, _COLUMNS),
                (user_id, name, _hash(key), hint, sorted(wanted), actor, expiry),
            )
            created = await cur.fetchone()
            if created is None:
                raise ApiKeyError("the key was not recorded")
            api_key = _row_to_key(created)
            details: dict[str, Any] = {
                "key_id": str(api_key.id),
                "name": name,
                "scopes": sorted(wanted),
                "expires_at": None if expiry is None else expiry.isoformat(),
            }
            await record_audit(
                AuditEvent(
                    action="warden.identity.api_key.created",
                    outcome="success",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    source_ip=source_ip,
                    details=details,
                ),
                conn=tx,
            )
        return NewApiKey(key, api_key)

    def _expiry(self, expires_at: datetime | None) -> datetime | None:
        now = datetime.now(UTC)
        if expires_at is None:
            return None if self._max_lifetime is None else now + self._max_lifetime
        if expires_at.tzinfo is None or expires_at <= now:
            raise ApiKeyError("a key's expiry must be a future, zoned time")
        if self._max_lifetime is not None and expires_at > now + self._max_lifetime:
            raise ApiKeyError("a key's expiry may not exceed identity.api_key_max_lifetime_days")
        return expires_at

    async def get(self, key_id: uuid.UUID) -> ApiKey | None:
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL("SELECT {} FROM {} WHERE id = %s").format(_COLUMNS, _KEYS), (key_id,)
            )
            row = await cur.fetchone()
        return None if row is None else _row_to_key(row)

    async def list(self, *, user_id: uuid.UUID | None = None) -> list[ApiKey]:
        """Keys, newest first; one user's, or everyone's."""
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT {} FROM {} WHERE %(user)s::uuid IS NULL OR user_id = %(user)s"
                    " ORDER BY created_at DESC, id"
                ).format(_COLUMNS, _KEYS),
                {"user": user_id},
            )
            return [_row_to_key(row) for row in await cur.fetchall()]

    async def revoke(
        self, key_id: uuid.UUID, *, actor: str | None, source_ip: SourceIp = None
    ) -> bool:
        """Revoke a key; False if it was already revoked or does not exist."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET revoked_at = now(), revoked_by = %s"
                    " WHERE id = %s AND revoked_at IS NULL RETURNING user_id"
                ).format(_KEYS),
                (actor, key_id),
            )
            row = await cur.fetchone()
            if row is None:
                return False
            await record_audit(
                AuditEvent(
                    action="warden.identity.api_key.revoked",
                    outcome="success",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(row[0]),
                    source_ip=source_ip,
                    details={"key_id": str(key_id)},
                ),
                conn=tx,
            )
        return True

    async def authenticate(self, key: str, *, source_ip: SourceIp = None) -> Principal:
        """The principal behind a live key, or ``AuthenticationRefused`` after auditing why.

        A malformed key is refused without an audit record, as a malformed
        access token is.
        """
        if self._shape.fullmatch(key) is None:
            raise AuthenticationRefused("malformed")
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT k.id, k.user_id, k.scopes, k.revoked_at IS NOT NULL,"
                    " k.expires_at IS NOT NULL AND k.expires_at <= now(), u.status, u.email"
                    " FROM {} k JOIN {} u ON u.id = k.user_id WHERE k.key_hash = %s"
                ).format(_KEYS, _USERS),
                (_hash(key),),
            )
            row = await cur.fetchone()
            if row is None:
                reason: str | None = "unknown_key"
            elif row[3]:
                reason = "key_revoked"
            elif row[4]:
                reason = "key_expired"
            elif row[5] != UserStatus.ACTIVE:
                reason = "user_inactive"
            else:
                reason = None
            roles: list[str] = []
            if reason is None and row is not None:
                roles = await self._roles.roles_of(row[1], conn=tx)
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET last_used_at = now() WHERE id = %s AND (last_used_at IS NULL"
                        " OR last_used_at < now() - %s * interval '1 second')"
                    ).format(_KEYS),
                    (row[0], _LAST_USED_RESOLUTION_SECONDS),
                )
        if reason is not None or row is None:
            key_ref, user_ref = (None, None) if row is None else (row[0], row[1])
            await self._refuse(reason or "unknown_key", key_ref, user_ref, source_ip)
        key_id, user_id, scopes, email = row[0], row[1], frozenset(row[2]), row[6]
        held = self._roles.registry.permissions_for(roles)
        return Principal(
            user_id=user_id,
            session_id=key_id,
            email=email,
            roles=frozenset(roles),
            permissions=held & scopes,
            amr=("api_key",),
            api_key_id=key_id,
        )

    async def _refuse(
        self,
        reason: str,
        key_id: uuid.UUID | None,
        user_id: uuid.UUID | None,
        source_ip: SourceIp,
    ) -> NoReturn:
        details: dict[str, Any] = {"reason": reason}
        if key_id is not None:
            details["key_id"] = str(key_id)
        await record_audit(
            AuditEvent(
                action="warden.identity.api_key.authenticate",
                outcome="failure",
                actor=None if user_id is None else str(user_id),
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details=details,
            )
        )
        raise AuthenticationRefused(reason)
