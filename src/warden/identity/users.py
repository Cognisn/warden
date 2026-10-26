"""Users: statuses, sign-in methods and passwords.

A user signs in with their email address, matched without regard to case.
The password hash never leaves this module's queries: ``User`` says only
whether one is set.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

import psycopg
from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, record_audit
from warden.db import Database, table
from warden.identity import schema
from warden.identity.passwords import MAX_PASSWORD_LENGTH, PasswordHasher
from warden.identity.roles import LastAdministratorError, Roles, lock_administrators

__all__ = ["SignInMethod", "User", "UserError", "UserStatus", "Users"]

# Deliberately loose: one "@", no whitespace, a dot in the domain. Deliverability
# is the product's concern; this only keeps obvious garbage out.
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_MAX_EMAIL = 320

_USERS = table(schema.USERS)
_COLUMNS = sql.SQL(
    "id, email, display_name, status, sign_in_method, password_hash IS NOT NULL,"
    " created_at, updated_at"
)


class UserStatus(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"


class SignInMethod(StrEnum):
    PASSWORD_AND_SSO = "password_and_sso"  # noqa: S105 - a method name, not a password
    SSO_ONLY = "sso_only"


class UserError(Exception):
    """A user change was refused. Messages carry identifiers only, never values."""


@dataclass(frozen=True, slots=True)
class User:
    id: uuid.UUID
    email: str
    display_name: str | None
    status: UserStatus
    sign_in_method: SignInMethod
    has_password: bool
    created_at: datetime
    updated_at: datetime


def _row_to_user(row: tuple[Any, ...]) -> User:
    return User(
        id=row[0],
        email=row[1],
        display_name=row[2],
        status=UserStatus(row[3]),
        sign_in_method=SignInMethod(row[4]),
        has_password=bool(row[5]),
        created_at=row[6],
        updated_at=row[7],
    )


def is_email(text: str) -> bool:
    """Whether ``text`` is shaped like an email address (and short enough to be one)."""
    return len(text) <= _MAX_EMAIL and _EMAIL.fullmatch(text) is not None


def check_email(email: str) -> str:
    if len(email) > _MAX_EMAIL or _EMAIL.fullmatch(email) is None:
        raise UserError("email address is not valid")
    return email


class Users:
    """User records in ``warden.users``."""

    def __init__(
        self, db: Database, hasher: PasswordHasher, roles: Roles, *, password_min_length: int
    ) -> None:
        self._db = db
        self._hasher = hasher
        self._roles = roles
        self._min_length = password_min_length

    async def _hash_password(self, password: str) -> str:
        if not self._min_length <= len(password) <= MAX_PASSWORD_LENGTH:
            raise UserError(
                f"password must be between {self._min_length} and {MAX_PASSWORD_LENGTH} characters"
            )
        return await self._hasher.hash(password)

    async def create(
        self,
        email: str,
        *,
        actor: str | None,
        display_name: str | None = None,
        status: UserStatus = UserStatus.ACTIVE,
        sign_in_method: SignInMethod = SignInMethod.PASSWORD_AND_SSO,
        password: str | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> User:
        """Create a user. The email address must be unique, ignoring case."""
        check_email(email)
        password_hash = None if password is None else await self._hash_password(password)
        try:
            async with self._db.transaction(conn) as tx:
                cur = await tx.execute(
                    sql.SQL(
                        "INSERT INTO {}"
                        " (email, display_name, status, sign_in_method, password_hash)"
                        " VALUES (%s, %s, %s, %s, %s) RETURNING {}"
                    ).format(_USERS, _COLUMNS),
                    (email, display_name, status.value, sign_in_method.value, password_hash),
                )
                row = await cur.fetchone()
                if row is None:
                    raise UserError("the user was not recorded")
                user = _row_to_user(row)
                await record_audit(
                    AuditEvent(
                        action="identity.user.created",
                        outcome="success",
                        actor=actor,
                        resource_type="user",
                        resource_id=str(user.id),
                        details={"status": status.value, "sign_in_method": sign_in_method.value},
                    ),
                    conn=tx,
                )
        except psycopg.errors.UniqueViolation:
            raise UserError("a user with that email address already exists") from None
        return user

    async def get(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> User | None:
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT {} FROM {} WHERE id = %s").format(_COLUMNS, _USERS), (user_id,)
            )
            row = await cur.fetchone()
        return None if row is None else _row_to_user(row)

    async def get_by_email(self, email: str) -> User | None:
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL("SELECT {} FROM {} WHERE lower(email) = lower(%s)").format(
                    _COLUMNS, _USERS
                ),
                (email,),
            )
            row = await cur.fetchone()
        return None if row is None else _row_to_user(row)

    async def set_status(
        self,
        user_id: uuid.UUID,
        status: UserStatus,
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> User:
        """Change a user's status. Refuses leaving no active administrator."""
        previous: str | None = None
        try:
            async with self._db.transaction(conn) as tx:
                if status is not UserStatus.ACTIVE:
                    await lock_administrators(tx)
                cur = await tx.execute(
                    sql.SQL("SELECT status FROM {} WHERE id = %s FOR UPDATE").format(_USERS),
                    (user_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    raise UserError(f"user {user_id} does not exist")
                previous = row[0]
                user = await self._update(tx, user_id, sql.SQL("status = %s"), status.value)
                if (
                    previous == UserStatus.ACTIVE
                    and status is not UserStatus.ACTIVE
                    and await self._roles.is_administrator(user_id, conn=tx)
                ):
                    await self._roles.ensure_administrator_remains(tx)
                await record_audit(
                    AuditEvent(
                        action="identity.user.status_changed",
                        outcome="success",
                        actor=actor,
                        resource_type="user",
                        resource_id=str(user_id),
                        details={"from": previous, "to": status.value},
                    ),
                    conn=tx,
                )
        except LastAdministratorError:
            await record_audit(
                AuditEvent(
                    action="identity.user.status_changed",
                    outcome="failure",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    details={"from": previous, "to": status.value, "reason": "last_administrator"},
                )
            )
            raise
        return user

    async def set_sign_in_method(
        self,
        user_id: uuid.UUID,
        method: SignInMethod,
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> User:
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT sign_in_method FROM {} WHERE id = %s FOR UPDATE").format(_USERS),
                (user_id,),
            )
            row = await cur.fetchone()
            if row is None:
                raise UserError(f"user {user_id} does not exist")
            user = await self._update(tx, user_id, sql.SQL("sign_in_method = %s"), method.value)
            await record_audit(
                AuditEvent(
                    action="identity.user.sign_in_method_changed",
                    outcome="success",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    details={"from": row[0], "to": method.value},
                ),
                conn=tx,
            )
        return user

    async def set_password(
        self,
        user_id: uuid.UUID,
        password: str,
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> User:
        """Set a new password (an administrative action; users change theirs by signing in)."""
        password_hash = await self._hash_password(password)
        async with self._db.transaction(conn) as tx:
            user = await self._update(tx, user_id, sql.SQL("password_hash = %s"), password_hash)
            await record_audit(
                AuditEvent(
                    action="identity.user.password_set",
                    outcome="success",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                ),
                conn=tx,
            )
        return user

    async def _update(
        self, tx: AsyncConnection[Any], user_id: uuid.UUID, assignment: sql.Composable, value: Any
    ) -> User:
        cur = await tx.execute(
            sql.SQL("UPDATE {} SET {}, updated_at = now() WHERE id = %s RETURNING {}").format(
                _USERS, assignment, _COLUMNS
            ),
            (value, user_id),
        )
        row = await cur.fetchone()
        if row is None:
            raise UserError(f"user {user_id} does not exist")
        return _row_to_user(row)
