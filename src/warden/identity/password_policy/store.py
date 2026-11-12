"""The password policy store (rulings PW1, PW2 and PW11).

Policies live in ``warden.password_policies``. Exactly one is the default,
which has no priority; every other policy has a unique priority, where 1 is
the highest. A role maps to at most one policy, and an administrator may pin
a policy on one user.

A user's effective policy (PW1) is their pin, else the highest-priority
policy mapped from a role they hold and the product still declares, else
the default. When no default exists, the first read seeds one from
configuration (PW2): ``identity.password_min_length``, no class rule, no
tiers, no history, and the built-in common-password list.

Every replica caches the policies and role mappings. Every change takes the
password-policy advisory lock, issues ``pg_notify`` on the identity policy
channel in the same transaction, and is audited there too, so a listening
replica drops its cache as soon as the change commits; one that is not
listening re-reads within ``max_age`` seconds. Updates are checked against
the version the caller read (optimistic concurrency).
"""

from __future__ import annotations

import asyncio
import builtins
import logging
import time
import unicodedata
import uuid
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import datetime
from typing import Any, Literal, Protocol

import psycopg
from psycopg import AsyncConnection, sql
from psycopg.types.json import Jsonb

from warden.audit import AuditEvent, record_audit
from warden.db import (
    PASSWORD_POLICIES,
    PASSWORD_POLICY_LOCK_KEY,
    PASSWORD_POLICY_NOTIFY,
    PASSWORD_POLICY_PINS,
    PASSWORD_POLICY_ROLES,
    PASSWORD_POLICY_WATCH_LISTS,
    POLICY_CHANNEL,
    Database,
    schema,
    table,
)
from warden.identity.password_policy.errors import (
    PasswordPolicyConflict,
    PasswordPolicyError,
    PasswordPolicyNotFound,
    WatchListNotFound,
)
from warden.identity.password_policy.rules import PassphraseRule, PasswordRules, Tier
from warden.identity.roles import PermissionRegistry

__all__ = [
    "DEFAULT_POLICY_DESCRIPTION",
    "DEFAULT_POLICY_NAME",
    "MAX_HISTORY",
    "EffectivePolicy",
    "PasswordPolicies",
    "PasswordPolicy",
    "PolicySettings",
    "PolicySource",
    "resolve",
]

logger = logging.getLogger(__name__)

MAX_HISTORY = 24
MAX_MIN_AGE_HOURS = 8760
DEFAULT_POLICY_NAME = "Default"
DEFAULT_POLICY_DESCRIPTION = "Applies to every user whose roles map to no other policy."

PolicySource = Literal["pin", "role", "default"]
OnUnavailable = Literal["allow", "refuse"]

_POLICIES = table(PASSWORD_POLICIES)
_ROLES = table(PASSWORD_POLICY_ROLES)
_PINS = table(PASSWORD_POLICY_PINS)
_ATTACHED = table(PASSWORD_POLICY_WATCH_LISTS)
_USERS = table(schema.USERS)
_ASSIGNMENTS = table(schema.ROLE_ASSIGNMENTS)
_LIVE_ROLE = sql.SQL("(a.expires_at IS NULL OR a.expires_at > now())")


@dataclass(frozen=True, slots=True)
class PolicySettings:
    """What an administrator sets on a policy: everything but its id, priority and version."""

    name: str
    rules: PasswordRules
    description: str = ""
    history_count: int = 0
    """Previous passwords (Argon2id hashes) a new one may not repeat, 0 to 24 (PW6)."""
    min_age_hours: int = 0
    """Hours a password must be held before the user may change it again (PW6)."""
    include_builtin: bool = True
    """Check the built-in common-password list (PW12)."""
    watch_list_ids: tuple[uuid.UUID, ...] = ()
    """Local watch lists this policy checks (PW7)."""
    hibp_enabled: bool = False
    """Ask the Pwned Passwords range API (PW7)."""
    hibp_on_unavailable: OnUnavailable = "allow"
    """When the range API cannot be reached: allow (and audit) or refuse."""
    fingerprint_enabled: bool = False
    """Keep a sealed fingerprint for recheck (PW8); needs a configured key."""
    end_sessions_on_match: bool = False
    """End a user's live sessions when recheck finds their password listed (PW8)."""
    enforce_on_sign_in: bool = False
    """Force a change at sign-in when the password fails the current rules (PW11)."""

    def problems(self, *, fingerprint_available: bool) -> list[str]:
        problems: list[str] = []
        if not isinstance(self.name, str) or not 1 <= len(self.name.strip()) <= 64:
            problems.append("name must be 1 to 64 characters")
        elif len(self.name) > 64 or any(unicodedata.category(c)[0] == "C" for c in self.name):
            problems.append("name must be at most 64 characters without control characters")
        if not isinstance(self.description, str) or len(self.description) > 500:
            problems.append("description must be at most 500 characters")
        elif any(unicodedata.category(c) == "Cc" and c not in "\n\t" for c in self.description):
            problems.append("description must not contain control characters")
        if not isinstance(self.rules, PasswordRules):
            problems.append("rules must be PasswordRules")
        else:
            try:
                self.rules.validate()
            except PasswordPolicyError as exc:
                problems.append(str(exc))
        if type(self.history_count) is not int or not 0 <= self.history_count <= MAX_HISTORY:
            problems.append(f"history_count must be between 0 and {MAX_HISTORY}")
        if type(self.min_age_hours) is not int or not 0 <= self.min_age_hours <= MAX_MIN_AGE_HOURS:
            problems.append(f"min_age_hours must be between 0 and {MAX_MIN_AGE_HOURS}")
        if self.hibp_on_unavailable not in ("allow", "refuse"):
            problems.append("hibp_on_unavailable must be allow or refuse")
        for name in (
            "include_builtin",
            "hibp_enabled",
            "fingerprint_enabled",
            "end_sessions_on_match",
            "enforce_on_sign_in",
        ):
            if type(getattr(self, name)) is not bool:
                problems.append(f"{name} must be true or false")
        if not all(isinstance(i, uuid.UUID) for i in self.watch_list_ids):
            problems.append("watch_list_ids must be watch list ids")
        elif len(set(self.watch_list_ids)) != len(self.watch_list_ids):
            problems.append("watch_list_ids must not repeat a list")
        if self.fingerprint_enabled is True and not fingerprint_available:
            problems.append(
                "fingerprint_enabled needs passwords.fingerprint_key_secret to be configured"
            )
        return problems


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """A stored policy."""

    id: uuid.UUID
    priority: int | None
    """1 is the highest; None for the default."""
    is_default: bool
    settings: PolicySettings
    roles: tuple[str, ...]
    """The roles mapped to this policy, sorted."""
    version: int
    created_at: datetime
    updated_at: datetime

    @property
    def name(self) -> str:
        return self.settings.name


@dataclass(frozen=True, slots=True)
class EffectivePolicy:
    """The policy that applies to a user, and why (PW1)."""

    policy: PasswordPolicy
    source: PolicySource
    role: str | None = None
    """The mapped role that chose the policy, when ``source`` is ``role``."""


class _Prioritised(Protocol):
    @property
    def priority(self) -> int | None: ...


def resolve[P: _Prioritised](
    policies: Mapping[uuid.UUID, P],
    role_map: Mapping[str, uuid.UUID],
    default_id: uuid.UUID,
    pin: uuid.UUID | None,
    roles: Iterable[str],
    declared: Collection[str],
) -> tuple[P, PolicySource, str | None]:
    """PW1: the pin, else the highest-priority mapped and declared role, else the default."""
    if pin is not None and pin in policies:
        return policies[pin], "pin", None
    best: tuple[int, str, P] | None = None
    for role in roles:
        policy_id = role_map.get(role)
        if role not in declared or policy_id is None or policy_id not in policies:
            continue
        policy = policies[policy_id]
        if policy.priority is None:
            continue
        candidate = (policy.priority, role, policy)
        if best is None or candidate[:2] < best[:2]:
            best = candidate
    if best is not None:
        return best[2], "role", best[1]
    return policies[default_id], "default", None


@dataclass(frozen=True, slots=True)
class _Snapshot:
    policies: dict[uuid.UUID, PasswordPolicy]
    role_map: dict[str, uuid.UUID]
    default_id: uuid.UUID | None


_COLUMNS = sql.SQL(
    "p.id, p.name, p.description, p.priority, p.is_default, p.min_length, p.max_length,"
    " p.min_classes, p.max_repeat, p.forbid_user_details, p.passphrase_min_length,"
    " p.passphrase_min_words, p.passphrase_relaxes_classes, p.tiers, p.warning_days,"
    " p.history_count, p.min_age_hours, p.include_builtin, p.hibp_enabled,"
    " p.hibp_on_unavailable, p.fingerprint_enabled, p.end_sessions_on_match,"
    " p.enforce_on_sign_in, p.version, p.created_at, p.updated_at"
)

_SETTING_FIELDS = tuple(f.name for f in fields(PolicySettings))


def _row_to_policy(
    row: Sequence[Any], roles: tuple[str, ...], lists: tuple[uuid.UUID, ...]
) -> PasswordPolicy:
    (
        policy_id,
        name,
        description,
        priority,
        is_default,
        min_length,
        max_length,
        min_classes,
        max_repeat,
        forbid_user_details,
        phrase_length,
        phrase_words,
        phrase_relaxes,
        tiers,
        warning_days,
        history_count,
        min_age_hours,
        include_builtin,
        hibp_enabled,
        hibp_on_unavailable,
        fingerprint_enabled,
        end_sessions_on_match,
        enforce_on_sign_in,
        version,
        created_at,
        updated_at,
    ) = row
    rules = PasswordRules(
        min_length=min_length,
        max_length=max_length,
        min_classes=min_classes,
        max_repeat=max_repeat,
        forbid_user_details=forbid_user_details,
        passphrase=None
        if phrase_length is None
        else PassphraseRule(phrase_length, phrase_words, phrase_relaxes),
        tiers=tuple(
            Tier(
                name=t["name"],
                passphrase=t["passphrase"],
                min_length=t["min_length"],
                min_classes=t["min_classes"],
                max_age_days=t["max_age_days"],
            )
            for t in tiers
        ),
        warning_days=warning_days,
    )
    settings = PolicySettings(
        name=name,
        rules=rules,
        description=description,
        history_count=history_count,
        min_age_hours=min_age_hours,
        include_builtin=include_builtin,
        watch_list_ids=lists,
        hibp_enabled=hibp_enabled,
        hibp_on_unavailable=hibp_on_unavailable,
        fingerprint_enabled=fingerprint_enabled,
        end_sessions_on_match=end_sessions_on_match,
        enforce_on_sign_in=enforce_on_sign_in,
    )
    return PasswordPolicy(
        id=policy_id,
        priority=priority,
        is_default=is_default,
        settings=settings,
        roles=roles,
        version=version,
        created_at=created_at,
        updated_at=updated_at,
    )


def _values(settings: PolicySettings) -> dict[str, Any]:
    rules = settings.rules
    phrase = rules.passphrase
    return {
        "name": settings.name,
        "description": settings.description,
        "min_length": rules.min_length,
        "max_length": rules.max_length,
        "min_classes": rules.min_classes,
        "max_repeat": rules.max_repeat,
        "forbid_user_details": rules.forbid_user_details,
        "passphrase_min_length": None if phrase is None else phrase.min_length,
        "passphrase_min_words": None if phrase is None else phrase.min_words,
        "passphrase_relaxes_classes": False if phrase is None else phrase.relaxes_classes,
        "tiers": Jsonb(rules.describe()["tiers"]),
        "warning_days": rules.warning_days,
        "history_count": settings.history_count,
        "min_age_hours": settings.min_age_hours,
        "include_builtin": settings.include_builtin,
        "hibp_enabled": settings.hibp_enabled,
        "hibp_on_unavailable": settings.hibp_on_unavailable,
        "fingerprint_enabled": settings.fingerprint_enabled,
        "end_sessions_on_match": settings.end_sessions_on_match,
        "enforce_on_sign_in": settings.enforce_on_sign_in,
    }


async def lock_policies(conn: AsyncConnection[Any]) -> None:
    """Take the password-policy advisory lock for the rest of the transaction."""
    await conn.execute("SELECT pg_advisory_xact_lock(%s)", (PASSWORD_POLICY_LOCK_KEY,))


async def notify_policies(conn: AsyncConnection[Any]) -> None:
    """Announce a change on the identity policy channel; delivered when it commits."""
    await conn.execute("SELECT pg_notify(%s, %s)", (POLICY_CHANNEL, PASSWORD_POLICY_NOTIFY))


# The effective policy id of every user who holds a password, in SQL: the pin,
# else the highest-priority policy mapped from a live, declared role, else the
# default. Parameters: ``declared`` (text[]).
EFFECTIVE_SQL = sql.SQL(
    """
    WITH mapped AS (
        SELECT a.user_id, p.id AS policy_id,
               row_number() OVER (PARTITION BY a.user_id ORDER BY p.priority, a.role) AS rank
        FROM {assignments} a
        JOIN {roles} r ON r.role = a.role
        JOIN {policies} p ON p.id = r.policy_id
        WHERE {live} AND a.role = ANY(%(declared)s::text[]) AND p.priority IS NOT NULL
    )
    SELECT u.id AS user_id,
           COALESCE(pin.policy_id, m.policy_id,
                    (SELECT id FROM {policies} WHERE is_default)) AS policy_id
    FROM {users} u
    LEFT JOIN {pins} pin ON pin.user_id = u.id
    LEFT JOIN mapped m ON m.user_id = u.id AND m.rank = 1
    WHERE u.sign_in_method = 'password_and_sso'
    """
).format(
    assignments=_ASSIGNMENTS,
    roles=_ROLES,
    policies=_POLICIES,
    live=_LIVE_ROLE,
    users=_USERS,
    pins=_PINS,
)


class PasswordPolicies:
    """Password policies, role mappings and pins, with each replica's cache."""

    def __init__(
        self,
        db: Database,
        registry: PermissionRegistry,
        *,
        seed_min_length: int,
        fingerprint_available: bool,
        max_age: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._db = db
        self._registry = registry
        self._seed = PasswordRules(min_length=seed_min_length)
        self._seed.validate()
        self._fingerprint_available = fingerprint_available
        self._max_age = max_age
        self._clock = clock
        self._cached: _Snapshot | None = None
        self._loaded_at = 0.0
        self._generation = 0
        self._listening = False

    @property
    def fingerprint_available(self) -> bool:
        return self._fingerprint_available

    def declared_roles(self) -> builtins.list[str]:
        """The roles the product declares now; mappings of any other role have no effect."""
        return [role.name for role in self._registry.roles()]

    @property
    def listening(self) -> bool:
        return self._listening

    def invalidate(self) -> None:
        """Forget the cached policies; the next read re-reads them."""
        self._generation += 1
        self._cached = None

    # Reading

    async def _snapshot(self) -> _Snapshot:
        cached = self._cached
        if cached is not None and self._clock() - self._loaded_at < self._max_age:
            return cached
        generation = self._generation
        async with self._db.connection() as conn:
            snapshot = await self._read(conn)
        # An invalidation that arrived during the read wins; do not cache stale data.
        if generation == self._generation and snapshot.default_id is not None:
            self._cached, self._loaded_at = snapshot, self._clock()
        return snapshot

    async def _read(self, conn: AsyncConnection[Any]) -> _Snapshot:
        cur = await conn.execute(sql.SQL("SELECT role, policy_id FROM {}").format(_ROLES))
        role_rows = await cur.fetchall()
        cur = await conn.execute(sql.SQL("SELECT policy_id, list_id FROM {}").format(_ATTACHED))
        list_rows = await cur.fetchall()
        cur = await conn.execute(sql.SQL("SELECT {} FROM {} p").format(_COLUMNS, _POLICIES))
        rows = await cur.fetchall()
        roles: dict[uuid.UUID, list[str]] = {}
        for role, policy_id in role_rows:
            roles.setdefault(policy_id, []).append(role)
        lists: dict[uuid.UUID, list[uuid.UUID]] = {}
        for policy_id, list_id in list_rows:
            lists.setdefault(policy_id, []).append(list_id)
        policies = {
            row[0]: _row_to_policy(
                row,
                tuple(sorted(roles.get(row[0], ()))),
                tuple(sorted(lists.get(row[0], ()), key=str)),
            )
            for row in rows
        }
        default_id = next((p.id for p in policies.values() if p.is_default), None)
        return _Snapshot(policies, {r: p for r, p in role_rows}, default_id)

    async def list(self) -> list[PasswordPolicy]:
        """Every policy: by priority, highest first, then the default."""
        snapshot = await self._seeded()
        return sorted(
            snapshot.policies.values(),
            key=lambda p: (p.priority is None, p.priority or 0),
        )

    async def get(self, policy_id: uuid.UUID) -> PasswordPolicy:
        snapshot = await self._seeded()
        policy = snapshot.policies.get(policy_id)
        if policy is None:
            self.invalidate()
            snapshot = await self._seeded()
            policy = snapshot.policies.get(policy_id)
        if policy is None:
            raise PasswordPolicyNotFound(f"no password policy {policy_id}")
        return policy

    async def default(self) -> PasswordPolicy:
        snapshot = await self._seeded()
        return snapshot.policies[_default_id(snapshot)]

    async def _seeded(self) -> _Snapshot:
        snapshot = await self._snapshot()
        if snapshot.default_id is None:
            await self.ensure_default()
            snapshot = await self._snapshot()
        return snapshot

    async def ensure_default(self) -> PasswordPolicy:
        """Seed the default policy from configuration if none exists (PW2); concurrency-safe."""
        async with self._db.transaction() as tx:
            await lock_policies(tx)
            cur = await tx.execute(
                sql.SQL("SELECT {} FROM {} p WHERE p.is_default").format(_COLUMNS, _POLICIES)
            )
            row = await cur.fetchone()
            if row is not None:
                return _row_to_policy(row, (), ())
            settings = PolicySettings(
                name=DEFAULT_POLICY_NAME,
                rules=self._seed,
                description=DEFAULT_POLICY_DESCRIPTION,
            )
            policy = await self._insert(tx, settings, priority=None, is_default=True)
            await record_audit(
                AuditEvent(
                    action="warden.identity.password_policy.created",
                    outcome="success",
                    actor=None,
                    resource_type="password_policy",
                    resource_id=str(policy.id),
                    details={"seeded": True, "version": 1},
                ),
                conn=tx,
            )
            await notify_policies(tx)
        self.invalidate()
        return policy

    async def effective(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> EffectivePolicy:
        """The policy that applies to ``user_id``, and why (PW1)."""
        snapshot = await self._seeded()
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT (SELECT policy_id FROM {} WHERE user_id = %s),"
                    " ARRAY(SELECT a.role FROM {} a WHERE a.user_id = %s AND {})"
                ).format(_PINS, _ASSIGNMENTS, _LIVE_ROLE),
                (user_id, user_id),
            )
            row = await cur.fetchone()
        pin, roles = (None, []) if row is None else (row[0], list(row[1]))
        if pin is not None and pin not in snapshot.policies:
            # Pinned on another replica since this one cached: read again once.
            self.invalidate()
            snapshot = await self._seeded()
        declared = set(self.declared_roles())
        policy, source, role = resolve(
            snapshot.policies, snapshot.role_map, _default_id(snapshot), pin, roles, declared
        )
        return EffectivePolicy(policy, source, role)

    async def affected_users(self, policy_id: uuid.UUID) -> int:
        """How many users who hold a password this policy currently applies to (PW11)."""
        await self._seeded()
        declared = self.declared_roles()
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL("SELECT count(*) FROM ({}) e WHERE e.policy_id = %(policy)s").format(
                    EFFECTIVE_SQL
                ),
                {"declared": declared, "policy": policy_id},
            )
            row = await cur.fetchone()
        return 0 if row is None else int(row[0])

    # Changing

    def _check(self, settings: PolicySettings) -> None:
        problems = settings.problems(fingerprint_available=self._fingerprint_available)
        if problems:
            raise PasswordPolicyError("; ".join(problems))

    async def _insert(
        self,
        tx: AsyncConnection[Any],
        settings: PolicySettings,
        *,
        priority: int | None,
        is_default: bool,
    ) -> PasswordPolicy:
        values = {**_values(settings), "priority": priority, "is_default": is_default}
        cur = await tx.execute(
            sql.SQL("INSERT INTO {} ({}) VALUES ({}) RETURNING id").format(
                _POLICIES,
                sql.SQL(", ").join(sql.Identifier(k) for k in values),
                sql.SQL(", ").join(sql.Placeholder(k) for k in values),
            ),
            values,
        )
        row = await cur.fetchone()
        if row is None:
            raise PasswordPolicyError("the policy was not recorded")
        await self._attach(tx, row[0], settings.watch_list_ids)
        return await self._fetch(tx, row[0])

    async def _attach(
        self, tx: AsyncConnection[Any], policy_id: uuid.UUID, lists: Sequence[uuid.UUID]
    ) -> None:
        await tx.execute(
            sql.SQL("DELETE FROM {} WHERE policy_id = %s").format(_ATTACHED), (policy_id,)
        )
        for list_id in lists:
            await tx.execute(
                sql.SQL("INSERT INTO {} (policy_id, list_id) VALUES (%s, %s)").format(_ATTACHED),
                (policy_id, list_id),
            )

    async def _fetch(self, conn: AsyncConnection[Any], policy_id: uuid.UUID) -> PasswordPolicy:
        cur = await conn.execute(
            sql.SQL("SELECT {} FROM {} p WHERE p.id = %s").format(_COLUMNS, _POLICIES),
            (policy_id,),
        )
        row = await cur.fetchone()
        if row is None:
            raise PasswordPolicyNotFound(f"no password policy {policy_id}")
        cur = await conn.execute(
            sql.SQL("SELECT role FROM {} WHERE policy_id = %s ORDER BY role").format(_ROLES),
            (policy_id,),
        )
        roles = tuple(r[0] for r in await cur.fetchall())
        cur = await conn.execute(
            sql.SQL("SELECT list_id FROM {} WHERE policy_id = %s").format(_ATTACHED),
            (policy_id,),
        )
        lists = tuple(sorted((r[0] for r in await cur.fetchall()), key=str))
        return _row_to_policy(row, roles, lists)

    async def _audit(
        self,
        tx: AsyncConnection[Any],
        action: str,
        *,
        actor: str | None,
        resource_type: str,
        resource_id: uuid.UUID,
        details: dict[str, Any],
    ) -> None:
        await record_audit(
            AuditEvent(
                action=f"warden.identity.password_policy.{action}",
                outcome="success",
                actor=actor,
                resource_type=resource_type,
                resource_id=str(resource_id),
                details=details,
            ),
            conn=tx,
        )

    async def create(
        self,
        settings: PolicySettings,
        *,
        priority: int,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> PasswordPolicy:
        """Add a policy at ``priority`` (1 is the highest); it applies to no one until mapped."""
        self._check(settings)
        _check_priority(priority)
        await self._seeded()
        try:
            async with self._db.transaction(conn) as tx:
                await lock_policies(tx)
                policy = await self._insert(tx, settings, priority=priority, is_default=False)
                await self._audit(
                    tx,
                    "created",
                    actor=actor,
                    resource_type="password_policy",
                    resource_id=policy.id,
                    details={"seeded": False, "version": 1},
                )
                await notify_policies(tx)
        except psycopg.errors.UniqueViolation:
            raise PasswordPolicyConflict("that name or priority is already in use") from None
        except psycopg.errors.ForeignKeyViolation:
            raise WatchListNotFound("a watch list to attach does not exist") from None
        finally:
            self.invalidate()
        return policy

    async def update(
        self,
        policy_id: uuid.UUID,
        settings: PolicySettings,
        *,
        expected_version: int,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> PasswordPolicy:
        """Replace a policy's settings, if it is still at ``expected_version``."""
        self._check(settings)
        try:
            async with self._db.transaction(conn) as tx:
                await lock_policies(tx)
                before = await self._fetch(tx, policy_id)
                if before.version != expected_version:
                    raise PasswordPolicyConflict("the policy changed since it was read")
                values = _values(settings)
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET {}, version = version + 1, updated_at = now()"
                        " WHERE id = %(id)s"
                    ).format(
                        _POLICIES,
                        sql.SQL(", ").join(
                            sql.SQL("{} = {}").format(sql.Identifier(k), sql.Placeholder(k))
                            for k in values
                        ),
                    ),
                    {**values, "id": policy_id},
                )
                await self._attach(tx, policy_id, settings.watch_list_ids)
                after = await self._fetch(tx, policy_id)
                changed = [
                    name
                    for name in _SETTING_FIELDS
                    if getattr(before.settings, name) != getattr(after.settings, name)
                ]
                await self._audit(
                    tx,
                    "updated",
                    actor=actor,
                    resource_type="password_policy",
                    resource_id=policy_id,
                    details={"fields": changed, "version": after.version},
                )
                await notify_policies(tx)
        except psycopg.errors.UniqueViolation:
            raise PasswordPolicyConflict("that name is already in use") from None
        except psycopg.errors.ForeignKeyViolation:
            raise WatchListNotFound("a watch list to attach does not exist") from None
        finally:
            self.invalidate()
        return after

    async def delete(
        self, policy_id: uuid.UUID, *, actor: str | None, conn: AsyncConnection[Any] | None = None
    ) -> None:
        """Remove a policy; its users return to a role mapping or the default.

        Never the default, and never a policy pinned on a user: unpin them first,
        so no user's pinned policy is dropped without a decision about them.
        """
        try:
            async with self._db.transaction(conn) as tx:
                await lock_policies(tx)
                policy = await self._fetch(tx, policy_id)
                if policy.is_default:
                    raise PasswordPolicyConflict("the default policy cannot be deleted")
                cur = await tx.execute(
                    sql.SQL("SELECT count(*) FROM {} WHERE policy_id = %s").format(_PINS),
                    (policy_id,),
                )
                pins = await cur.fetchone()
                pinned = 0 if pins is None else int(pins[0])
                if pinned:
                    users = "user" if pinned == 1 else "users"
                    raise PasswordPolicyConflict(
                        f"the policy is pinned on {pinned} {users}; unpin them first"
                    )
                await tx.execute(
                    sql.SQL("DELETE FROM {} WHERE id = %s").format(_POLICIES), (policy_id,)
                )
                await self._audit(
                    tx,
                    "deleted",
                    actor=actor,
                    resource_type="password_policy",
                    resource_id=policy_id,
                    details={
                        "roles_unmapped": len(policy.roles),
                        "pins_removed": pinned,
                    },
                )
                await notify_policies(tx)
        finally:
            self.invalidate()

    async def set_priority(
        self,
        policy_id: uuid.UUID,
        priority: int,
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> PasswordPolicy:
        """Move one policy to a free ``priority``. The default has none."""
        _check_priority(priority)
        try:
            async with self._db.transaction(conn) as tx:
                await lock_policies(tx)
                policy = await self._fetch(tx, policy_id)
                if policy.is_default:
                    raise PasswordPolicyConflict("the default policy has no priority")
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET priority = %s, version = version + 1, updated_at = now()"
                        " WHERE id = %s"
                    ).format(_POLICIES),
                    (priority, policy_id),
                )
                after = await self._fetch(tx, policy_id)
                await self._audit(
                    tx,
                    "updated",
                    actor=actor,
                    resource_type="password_policy",
                    resource_id=policy_id,
                    details={"fields": ["priority"], "version": after.version},
                )
                await notify_policies(tx)
        except psycopg.errors.UniqueViolation:
            raise PasswordPolicyConflict("that priority is already in use") from None
        finally:
            self.invalidate()
        return after

    async def reorder(
        self,
        policy_ids: Sequence[uuid.UUID],
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> builtins.list[PasswordPolicy]:
        """Give every non-default policy, in this order, priorities 1, 2, 3 and so on."""
        try:
            async with self._db.transaction(conn) as tx:
                await lock_policies(tx)
                cur = await tx.execute(
                    sql.SQL("SELECT id FROM {} WHERE NOT is_default").format(_POLICIES)
                )
                existing = {r[0] for r in await cur.fetchall()}
                if len(set(policy_ids)) != len(policy_ids) or set(policy_ids) != existing:
                    raise PasswordPolicyError("reorder must name every non-default policy once")
                await tx.execute("SET CONSTRAINTS warden.password_policies_priority_key DEFERRED")
                for index, policy_id in enumerate(policy_ids, start=1):
                    await tx.execute(
                        sql.SQL(
                            "UPDATE {} SET priority = %s, version = version + 1,"
                            " updated_at = now() WHERE id = %s AND priority IS DISTINCT FROM %s"
                        ).format(_POLICIES),
                        (index, policy_id, index),
                    )
                    await self._audit(
                        tx,
                        "updated",
                        actor=actor,
                        resource_type="password_policy",
                        resource_id=policy_id,
                        details={"fields": ["priority"], "priority": index},
                    )
                await tx.execute("SET CONSTRAINTS warden.password_policies_priority_key IMMEDIATE")
                await notify_policies(tx)
        finally:
            self.invalidate()
        return [p for p in await self.list() if not p.is_default]

    async def map_role(
        self,
        role: str,
        policy_id: uuid.UUID | None,
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> None:
        """Map ``role`` to a policy, or with None remove its mapping."""
        if role not in self._registry:
            raise PasswordPolicyError("the product declares no such role")
        try:
            async with self._db.transaction(conn) as tx:
                await lock_policies(tx)
                if policy_id is None:
                    await tx.execute(
                        sql.SQL("DELETE FROM {} WHERE role = %s").format(_ROLES), (role,)
                    )
                else:
                    policy = await self._fetch(tx, policy_id)
                    if policy.is_default:
                        raise PasswordPolicyConflict(
                            "the default applies to unmapped roles; map a role to another policy"
                        )
                    await tx.execute(
                        sql.SQL(
                            "INSERT INTO {} (role, policy_id) VALUES (%s, %s)"
                            " ON CONFLICT (role) DO UPDATE SET policy_id = EXCLUDED.policy_id,"
                            " created_at = now()"
                        ).format(_ROLES),
                        (role, policy_id),
                    )
                await record_audit(
                    AuditEvent(
                        action="warden.identity.password_policy.assigned",
                        outcome="success",
                        actor=actor,
                        resource_type="role",
                        resource_id=role,
                        details={
                            "role": role,
                            "policy_id": None if policy_id is None else str(policy_id),
                        },
                    ),
                    conn=tx,
                )
                await notify_policies(tx)
        finally:
            self.invalidate()

    async def pin(
        self,
        user_id: uuid.UUID,
        policy_id: uuid.UUID,
        *,
        actor: str | None,
        conn: AsyncConnection[Any] | None = None,
    ) -> None:
        """Pin a policy on one user, overriding the role mapping (PW1)."""
        try:
            async with self._db.transaction(conn) as tx:
                await lock_policies(tx)
                await self._fetch(tx, policy_id)
                await tx.execute(
                    sql.SQL(
                        "INSERT INTO {} (user_id, policy_id) VALUES (%s, %s)"
                        " ON CONFLICT (user_id) DO UPDATE SET policy_id = EXCLUDED.policy_id,"
                        " pinned_at = now()"
                    ).format(_PINS),
                    (user_id, policy_id),
                )
                await self._audit(
                    tx,
                    "pinned",
                    actor=actor,
                    resource_type="user",
                    resource_id=user_id,
                    details={"policy_id": str(policy_id)},
                )
        except psycopg.errors.ForeignKeyViolation:
            raise PasswordPolicyError("no such user") from None

    async def unpin(
        self, user_id: uuid.UUID, *, actor: str | None, conn: AsyncConnection[Any] | None = None
    ) -> bool:
        """Remove a user's pin; False if there was none."""
        async with self._db.transaction(conn) as tx:
            await lock_policies(tx)
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE user_id = %s RETURNING policy_id").format(_PINS),
                (user_id,),
            )
            row = await cur.fetchone()
            if row is None:
                return False
            await self._audit(
                tx,
                "unpinned",
                actor=actor,
                resource_type="user",
                resource_id=user_id,
                details={"policy_id": str(row[0])},
            )
        return True

    async def attach(
        self, policy_id: uuid.UUID, list_id: uuid.UUID, *, actor: str | None
    ) -> PasswordPolicy:
        """Have a policy check a watch list as well."""
        return await self._attachment(policy_id, list_id, attach=True, actor=actor)

    async def detach(
        self, policy_id: uuid.UUID, list_id: uuid.UUID, *, actor: str | None
    ) -> PasswordPolicy:
        """Stop a policy checking a watch list."""
        return await self._attachment(policy_id, list_id, attach=False, actor=actor)

    async def _attachment(
        self, policy_id: uuid.UUID, list_id: uuid.UUID, *, attach: bool, actor: str | None
    ) -> PasswordPolicy:
        try:
            async with self._db.transaction() as tx:
                await lock_policies(tx)
                await self._fetch(tx, policy_id)
                if attach:
                    cur = await tx.execute(
                        sql.SQL(
                            "INSERT INTO {} (policy_id, list_id) VALUES (%s, %s)"
                            " ON CONFLICT DO NOTHING"
                        ).format(_ATTACHED),
                        (policy_id, list_id),
                    )
                else:
                    cur = await tx.execute(
                        sql.SQL("DELETE FROM {} WHERE policy_id = %s AND list_id = %s").format(
                            _ATTACHED
                        ),
                        (policy_id, list_id),
                    )
                changed = cur.rowcount > 0
                if changed:
                    await tx.execute(
                        sql.SQL(
                            "UPDATE {} SET version = version + 1, updated_at = now() WHERE id = %s"
                        ).format(_POLICIES),
                        (policy_id,),
                    )
                after = await self._fetch(tx, policy_id)
                if changed:
                    await self._audit(
                        tx,
                        "updated",
                        actor=actor,
                        resource_type="password_policy",
                        resource_id=policy_id,
                        details={"fields": ["watch_list_ids"], "version": after.version},
                    )
                    await notify_policies(tx)
        except psycopg.errors.ForeignKeyViolation:
            raise WatchListNotFound("no such watch list") from None
        finally:
            self.invalidate()
        return after

    async def largest_history(self, conn: AsyncConnection[Any] | None = None) -> int:
        """The largest history count any policy keeps: history beyond it can go."""
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT coalesce(max(history_count), 0) FROM {}").format(_POLICIES)
            )
            row = await cur.fetchone()
        return 0 if row is None else int(row[0])

    async def listen(self, *, ready: asyncio.Event | None = None) -> None:
        """Drop the cache whenever any replica changes a policy. Runs until cancelled."""
        while True:
            try:
                async with self._db.connection() as conn:
                    await conn.set_autocommit(True)
                    await conn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(POLICY_CHANNEL)))
                    self.invalidate()
                    self._listening = True
                    if ready is not None:
                        ready.set()
                    async for notify in conn.notifies():
                        if notify.payload == PASSWORD_POLICY_NOTIFY:
                            self.invalidate()
            except psycopg.OperationalError:
                logger.warning("password policy listener lost its connection; reconnecting")
                self.invalidate()
                await asyncio.sleep(1.0)
            finally:
                self._listening = False


def _default_id(snapshot: _Snapshot) -> uuid.UUID:
    if snapshot.default_id is None:
        raise PasswordPolicyError("no default password policy is stored")
    return snapshot.default_id


def _check_priority(priority: int) -> None:
    if type(priority) is not int or not 1 <= priority <= 10000:
        raise PasswordPolicyError("priority must be between 1 and 10000")
