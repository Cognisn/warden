"""Roles and permissions (design D5).

The product registers its permissions and defines roles as named sets of
them; warden hardcodes neither. Roles are defined in code, at start-up.
Users hold any number of roles, each assignment optionally expiring.
warden stores the assignments, audits every change, and refuses any change
that would leave no active administrator.
"""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, record_audit
from warden.db import ADMINISTRATOR_LOCK_KEY, Database, schema, table

__all__ = [
    "ADMINISTRATOR_LOCK_KEY",
    "LastAdministratorError",
    "PermissionRegistry",
    "Role",
    "RoleAssignment",
    "RoleError",
    "Roles",
]

_PERMISSION = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_ROLE = re.compile(r"[a-z][a-z0-9_-]{0,63}")

_USERS = table(schema.USERS)
_ASSIGNMENTS = table(schema.ROLE_ASSIGNMENTS)


class RoleError(Exception):
    """A role change was refused. Messages carry identifiers only."""


class LastAdministratorError(RoleError):
    """The change would leave no active administrator."""


@dataclass(frozen=True, slots=True)
class Role:
    name: str
    permissions: frozenset[str]
    administrator: bool


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    user_id: uuid.UUID
    role: str
    granted_at: datetime
    granted_by: str | None
    expires_at: datetime | None


class PermissionRegistry:
    """The product's permissions and the roles built from them."""

    def __init__(self) -> None:
        self._permissions: dict[str, str] = {}
        self._roles: dict[str, Role] = {}
        self._lock = threading.Lock()

    def register_permission(self, name: str, description: str) -> None:
        """Register a permission. Re-registering it identically is a no-op."""
        if _PERMISSION.fullmatch(name) is None:
            raise ValueError("permission must be dotted lower-case words, such as cases.read")
        with self._lock:
            existing = self._permissions.get(name)
            if existing is not None and existing != description:
                raise ValueError(f"permission {name} is already registered differently")
            self._permissions[name] = description

    def define_role(
        self, name: str, permissions: Iterable[str], *, administrator: bool = False
    ) -> Role:
        """Define a role. An administrator role counts towards last-administrator protection."""
        if _ROLE.fullmatch(name) is None:
            raise ValueError("role name must be lower-case letters, digits, '-' or '_'")
        role = Role(name=name, permissions=frozenset(permissions), administrator=administrator)
        with self._lock:
            unknown = role.permissions - self._permissions.keys()
            if unknown:
                raise ValueError(f"role {name} uses unregistered permissions")
            existing = self._roles.get(name)
            if existing is not None and existing != role:
                raise ValueError(f"role {name} is already defined differently")
            self._roles[name] = role
        return role

    def role(self, name: str) -> Role:
        try:
            return self._roles[name]
        except KeyError:
            raise KeyError(f"role {name!r} is not defined") from None

    def __contains__(self, name: object) -> bool:
        return name in self._roles

    def roles(self) -> list[Role]:
        return sorted(self._roles.values(), key=lambda r: r.name)

    def permissions(self) -> dict[str, str]:
        return dict(self._permissions)

    def administrator_roles(self) -> frozenset[str]:
        return frozenset(r.name for r in self._roles.values() if r.administrator)

    def permissions_for(self, roles: Iterable[str]) -> frozenset[str]:
        """The union of the named roles' permissions; a role no longer defined grants nothing."""
        granted: set[str] = set()
        for name in roles:
            role = self._roles.get(name)
            if role is not None:
                granted |= role.permissions
        return frozenset(granted)


_LIVE = sql.SQL("(a.expires_at IS NULL OR a.expires_at > now())")


class Roles:
    """Role assignments in ``warden.role_assignments``."""

    def __init__(self, db: Database, registry: PermissionRegistry) -> None:
        self._db = db
        self._registry = registry

    @property
    def registry(self) -> PermissionRegistry:
        return self._registry

    async def roles_of(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> list[str]:
        """The user's unexpired role names."""
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT a.role FROM {} a WHERE a.user_id = %s AND {} ORDER BY a.role"
                ).format(_ASSIGNMENTS, _LIVE),
                (user_id,),
            )
            return [row[0] for row in await cur.fetchall()]

    async def assignments_of(self, user_id: uuid.UUID) -> list[RoleAssignment]:
        """Every assignment the user holds, expired ones included."""
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT user_id, role, granted_at, granted_by, expires_at FROM {}"
                    " WHERE user_id = %s ORDER BY role"
                ).format(_ASSIGNMENTS),
                (user_id,),
            )
            return [RoleAssignment(*row) for row in await cur.fetchall()]

    async def assign(
        self,
        user_id: uuid.UUID,
        role: str,
        *,
        actor: str | None,
        expires_at: datetime | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> None:
        """Grant ``role`` to the user, or update the expiry of an existing grant.

        An administrator role cannot expire: expiry is a clock, not a change
        warden can refuse, so it could silently leave no administrator.
        """
        definition = self._registry.role(role)
        if definition.administrator and expires_at is not None:
            raise RoleError(f"administrator role {role} cannot carry an expiry")
        async with self._db.transaction(conn) as tx:
            if definition.administrator:
                await lock_administrators(tx)
            cur = await tx.execute(
                sql.SQL("SELECT 1 FROM {} WHERE id = %s").format(_USERS), (user_id,)
            )
            if await cur.fetchone() is None:
                raise RoleError(f"user {user_id} does not exist")
            await tx.execute(
                sql.SQL(
                    "INSERT INTO {} (user_id, role, granted_at, granted_by, expires_at)"
                    " VALUES (%s, %s, now(), %s, %s)"
                    " ON CONFLICT (user_id, role) DO UPDATE SET expires_at = EXCLUDED.expires_at,"
                    " granted_at = now(), granted_by = EXCLUDED.granted_by"
                ).format(_ASSIGNMENTS),
                (user_id, role, actor, expires_at),
            )
            await record_audit(
                AuditEvent(
                    action="identity.role.assigned",
                    outcome="success",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    details={
                        "role": role,
                        "expires_at": expires_at.isoformat() if expires_at else None,
                    },
                ),
                conn=tx,
            )

    async def revoke(
        self,
        user_id: uuid.UUID,
        role: str,
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> bool:
        """Remove ``role`` from the user. False if they did not hold it.

        Raises ``LastAdministratorError`` (and audits the refusal) if this
        would leave no active administrator.
        """
        administrator = role in self._registry.administrator_roles()
        try:
            async with self._db.transaction(conn) as tx:
                if administrator:
                    await lock_administrators(tx)
                cur = await tx.execute(
                    sql.SQL("DELETE FROM {} WHERE user_id = %s AND role = %s RETURNING 1").format(
                        _ASSIGNMENTS
                    ),
                    (user_id, role),
                )
                if await cur.fetchone() is None:
                    return False
                if administrator:
                    await self.ensure_administrator_remains(tx)
                await record_audit(
                    AuditEvent(
                        action="identity.role.revoked",
                        outcome="success",
                        actor=actor,
                        resource_type="user",
                        resource_id=str(user_id),
                        details={"role": role},
                    ),
                    conn=tx,
                )
        except LastAdministratorError:
            await record_audit(
                AuditEvent(
                    action="identity.role.revoked",
                    outcome="failure",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    details={"role": role, "reason": "last_administrator"},
                )
            )
            raise
        return True

    async def is_administrator(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> bool:
        """Whether the user holds an unexpired administrator role (whatever their status)."""
        admin_roles = self._registry.administrator_roles()
        return any(role in admin_roles for role in await self.roles_of(user_id, conn=conn))

    async def ensure_administrator_remains(self, conn: AsyncConnection[Any]) -> None:
        """Raise ``LastAdministratorError`` unless an active user holds an administrator role.

        Call inside the transaction making the change, after the change and
        after ``lock_administrators``, so the check sees the result and no
        concurrent change can interleave. The transaction then rolls back.
        Identity lifecycle uses this when suspending or deactivating a user.
        """
        cur = await conn.execute(
            sql.SQL(
                "SELECT count(DISTINCT a.user_id) FROM {} a JOIN {} u ON u.id = a.user_id"
                " WHERE u.status = 'active' AND a.role = ANY(%s) AND {}"
            ).format(_ASSIGNMENTS, _USERS, _LIVE),
            (sorted(self._registry.administrator_roles()),),
        )
        row = await cur.fetchone()
        if row is None or int(row[0]) == 0:
            raise LastAdministratorError("refusing to leave no active administrator")


async def lock_administrators(conn: AsyncConnection[Any]) -> None:
    """Serialise changes that could remove an administrator, until this transaction ends."""
    await conn.execute("SELECT pg_advisory_xact_lock(%s)", (ADMINISTRATOR_LOCK_KEY,))
