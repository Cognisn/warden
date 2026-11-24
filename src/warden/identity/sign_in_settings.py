"""Sign-in settings and sign-in method changes (rulings CS13 to CS18 of 23 November 2026).

The instance's identity settings live in ``warden.sign_in_settings``, one
row: the default sign-in method every user follows unless they have one of
their own (initially ``password_and_sso``, ruling CS16), and the second
factors an administrator allows (initially both ``totp`` and ``passkey``;
stored here, enforced by ``Identity``: ruling CS14). Each replica caches them for
``identity.policy_cache_seconds``, as the single sign-on settings are; a
change invalidates this replica's copy, and sign-in itself never reads the
cache: ``effective_method_sql`` reads the row in the query that decides.

A user's method changes, by their own setting or by a change of the
default, take effect at once when the user holds the credential the new
method needs. Otherwise the change is pending (ruling CS18): the method in
force keeps working, and warden mails a set-up link where the new method
needs one (the passkey registration link, or a single-use set-password
link that opens the reset page). Moving to ``sso_only`` needs no link: the
account links on its first single sign-on, and the change completes then.
When the credential exists, the change completes and whatever the new
method does not allow is removed: a password hash, every security key and
passkey (for ``sso_only``), and the sessions signed in another way. Every
step is audited.

Locks, always in this order: the single sign-on settings lock, shared (so
turning single sign-on off waits for, or is seen by, a change that relies
on it); the settings row, shared by a user's change and exclusive for a
change of the default; then each user's row. A credential arriving (a
passkey registered, a password set, a first single sign-on) holds the
user's row and reads the settings unlocked: a default change waiting on
that row re-reads the user once it has it.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Literal

from psycopg import AsyncConnection, sql

from warden.audit import ActionRegistry, AuditEvent, Severity, record_audit
from warden.audit.registry import register_warden_action
from warden.config import WardenConfig
from warden.db import SSO_SETTINGS_LOCK_KEY, Database, schema, table
from warden.identity.http import SourceIp
from warden.identity.mail import MailDeliveryError, Mailer, MailError, MailKind
from warden.identity.single_use import Purpose, SingleUseTokens
from warden.identity.sso.settings import SsoSettingsStore, usable
from warden.identity.users import (
    SignInMethod,
    SignInMethodConflict,
    UserError,
    UserStatus,
    allows_passkey_sign_in,
    allows_password,
    allows_sso,
    effective_method_sql,
)

__all__ = [
    "SIGN_IN_ACTIONS",
    "UNSET",
    "PendingSignInMethod",
    "SecondFactorKind",
    "SetupLink",
    "SignInMethodChangeRefused",
    "SignInMethodState",
    "SignInMethods",
    "SignInSettings",
    "SignInSettingsChange",
    "SignInSettingsError",
    "register_actions",
    "setup_link_for",
]

SIGN_IN_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    (
        "warden.identity.sign_in_settings_changed",
        Severity.NOTICE,
        "{actor} changed the sign-in settings: {outcome}",
    ),
    (
        "warden.identity.user.sign_in_method_pending",
        Severity.NOTICE,
        "sign-in method change of user {resource_id} waits for its credential",
    ),
    (
        "warden.identity.user.sign_in_method_pending_cancelled",
        Severity.NOTICE,
        "pending sign-in method change of user {resource_id} cancelled: {outcome}",
    ),
    (
        "warden.identity.user.sign_in_method_link_sent",
        Severity.NOTICE,
        "{actor} sent user {resource_id} a sign-in set-up link: {outcome}",
    ),
)

_USERS = table(schema.USERS)
_SETTINGS = table(schema.SIGN_IN_SETTINGS)
_CHANGES = table(schema.SIGN_IN_METHOD_CHANGES)
_CREDENTIALS = table(schema.WEBAUTHN_CREDENTIALS)
_IDENTITIES = table(schema.SSO_IDENTITIES)
_SESSIONS = table(schema.SESSIONS)
_EFFECTIVE = effective_method_sql("u")

# RFC 8176 values on sessions: a password, single sign-on, a hardware key.
_PASSWORD_AMR = "pwd"  # noqa: S105 - an authentication method reference, not a password
_SSO_AMR = "sso"
_KEY_AMR = "hwk"
_REVOKED_REASON = "sign_in_method_changed"


def register_actions(registry: ActionRegistry) -> None:
    for action, severity, summary in SIGN_IN_ACTIONS:
        register_warden_action(registry, action, severity=severity, summary=summary)


class SecondFactorKind(StrEnum):
    """A second factor an administrator may allow (ruling CS14)."""

    TOTP = "totp"
    PASSKEY = "passkey"
    """A security key or passkey."""


class SetupLink(StrEnum):
    """The link that lets a user create the credential a new method needs."""

    PASSKEY_REGISTRATION = "passkey_registration"
    SET_PASSWORD = "set_password"  # noqa: S105 - a link name, not a password


def setup_link_for(method: SignInMethod) -> SetupLink | None:
    """The link a move to ``method`` mails; None for ``sso_only``, which links on first use."""
    if method is SignInMethod.PASSKEY_ONLY:
        return SetupLink.PASSKEY_REGISTRATION
    if allows_password(method):
        return SetupLink.SET_PASSWORD
    return None


@dataclass(frozen=True, slots=True)
class SignInSettings:
    default_sign_in_method: SignInMethod
    """The method every user without one of their own follows."""
    allowed_second_factors: frozenset[SecondFactorKind]
    """The second factors users may enrol and be challenged with (ruling CS14);
    never empty. Recovery codes are always the backup."""
    updated_at: datetime
    updated_by: str | None


@dataclass(frozen=True, slots=True)
class PendingSignInMethod:
    """A change waiting for its credential; ``from_method`` stays in force meanwhile."""

    from_method: SignInMethod
    to_method: SignInMethod
    requested_at: datetime
    requested_by: str | None
    link_sent_at: datetime | None
    """When the current set-up link was mailed; None when none was (or none is needed)."""

    @property
    def link(self) -> SetupLink | None:
        """What completes the change: a link, or (None) the first single sign-on."""
        return setup_link_for(self.to_method)


@dataclass(frozen=True, slots=True)
class SignInMethodState:
    user_id: uuid.UUID
    setting: SignInMethod | None
    """The user's own setting; None when they follow the instance default."""
    effective: SignInMethod
    """The method in force: how the user signs in now."""
    pending: PendingSignInMethod | None


@dataclass(frozen=True, slots=True)
class SignInSettingsChange:
    """A settings change, and what it did to the users who follow the default."""

    settings: SignInSettings
    changed: tuple[uuid.UUID, ...] = ()
    """Users whose method in force changed at once."""
    pending: tuple[uuid.UUID, ...] = ()
    """Users whose change waits for its credential."""
    links_failed: tuple[uuid.UUID, ...] = ()
    """Users whose set-up link was not delivered (audited; resend it)."""


class SignInSettingsError(ValueError):
    """A settings value is not valid. The message names fields, never values."""


class SignInMethodChangeRefused(SignInMethodConflict):
    """A sign-in method change cannot be made now. ``reason`` is the audited reason.

    ``sso_not_configured``: single sign-on is not enabled with an issuer and
    a client id. ``mail_sender``, ``passkey_registration_link``,
    ``reset_password_link``, ``webauthn``: a set-up link is needed and
    cannot be sent (never a silent fall-back). ``not_pending``: there is no
    pending change. ``no_link``: the pending change needs no link.
    ``user_inactive``: links go to active users only.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


UNSET: Final = object()
"""Leaves a setting as it is: the default of each ``update_settings`` keyword."""
_RESOLVED = Literal["unchanged", "changed", "pending"]


@dataclass(frozen=True, slots=True)
class _LinkDue:
    user_id: uuid.UUID
    link: SetupLink
    token: str
    expires_at: datetime
    email: str
    display_name: str | None


@dataclass(frozen=True, slots=True)
class _Outcome:
    resolved: _RESOLVED
    to_method: SignInMethod
    removed: dict[str, Any]
    due: _LinkDue | None = None


def _method(value: object, name: str) -> SignInMethod:
    if isinstance(value, str):
        try:
            return SignInMethod(value)
        except ValueError:
            pass
    raise SignInSettingsError(f"invalid settings: {name}")


def _factors(value: object) -> frozenset[SecondFactorKind]:
    invalid = SignInSettingsError("invalid settings: allowed_second_factors")
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise invalid
    items = list(value)
    if not items or not all(isinstance(v, str) for v in items):
        raise invalid
    try:
        return frozenset(SecondFactorKind(v) for v in items)
    except ValueError:
        raise invalid from None


def _sorted(factors: frozenset[SecondFactorKind]) -> list[str]:
    order = list(SecondFactorKind)
    return [f.value for f in sorted(factors, key=order.index)]


def _settings(row: tuple[Any, ...]) -> SignInSettings:
    return SignInSettings(
        default_sign_in_method=SignInMethod(row[0]),
        allowed_second_factors=frozenset(SecondFactorKind(v) for v in row[1]),
        updated_at=row[2],
        updated_by=row[3],
    )


def _resolve(setting: SignInMethod | None, default: SignInMethod) -> SignInMethod:
    return default if setting is None else setting


def _value(method: SignInMethod | None) -> str | None:
    return None if method is None else method.value


class SignInMethods:
    """The sign-in settings store and every change of a user's sign-in method."""

    def __init__(
        self,
        config: WardenConfig,
        db: Database,
        *,
        mailer: Mailer,
        tokens: SingleUseTokens,
        sso_settings: SsoSettingsStore,
        webauthn: bool,
        max_age: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """``webauthn`` says whether passkeys work here (a relying party is known)."""
        self._config = config
        self._db = db
        self._mailer = mailer
        self._tokens = tokens
        self._sso = sso_settings
        self._webauthn = webauthn
        self._max_age = max_age
        self._clock = clock
        self._cached: SignInSettings | None = None
        self._loaded_at = 0.0

    # The settings

    def invalidate(self) -> None:
        self._cached = None

    async def current(self) -> SignInSettings:
        """The settings, cached for ``identity.policy_cache_seconds``."""
        cached = self._cached
        if cached is not None and self._clock() - self._loaded_at < self._max_age:
            return cached
        async with self._db.connection() as conn:
            settings = await self.read(conn)
        self._cached, self._loaded_at = settings, self._clock()
        return settings

    async def read(self, conn: AsyncConnection[Any]) -> SignInSettings:
        """The settings, read now on ``conn`` (no cache)."""
        return await self._read(conn, lock=None)

    async def read_now(self) -> SignInSettings:
        """The settings, read now (no cache)."""
        async with self._db.connection() as conn:
            return await self.read(conn)

    async def _read(
        self, conn: AsyncConnection[Any], *, lock: Literal["SHARE", "UPDATE"] | None
    ) -> SignInSettings:
        query = sql.SQL(
            "SELECT default_sign_in_method, allowed_second_factors, updated_at, updated_by"
            " FROM {}{}"
        ).format(_SETTINGS, sql.SQL("" if lock is None else f" FOR {lock}"))
        cur = await conn.execute(query)
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError("the sign-in settings row is missing; run warden migrate")
        return _settings(row)

    async def update_settings(
        self,
        *,
        actor: str | None,
        source_ip: SourceIp = None,
        default_sign_in_method: object = UNSET,
        allowed_second_factors: object = UNSET,
    ) -> SignInSettingsChange:
        """Change the default sign-in method, the allowed second factors, or both.

        A new default moves every user who follows it (ruling CS13): at once
        for those holding its credential, as a pending change for the rest,
        each mailed a set-up link where one is needed (after this commits; a
        failed delivery is audited and listed in ``links_failed``).
        ``sso_only`` as the default needs single sign-on enabled with an
        issuer and a client id. The allowed second factors may not be
        emptied, and passkeys alone need WebAuthn configured (ruling CS14).
        Raises ``SignInSettingsError`` for a value that is not valid (an
        empty set among them) and ``SignInMethodChangeRefused`` when the
        change cannot be made (``sso_not_configured``, ``webauthn``, or a
        link that cannot be sent: ``mail_sender`` and the others); nothing
        is changed then, and the refusal is audited. Users holding a security key or passkey
        that a move to ``sso_only`` would not allow lose them when it completes.
        """
        new_default = (
            None
            if default_sign_in_method is UNSET
            else _method(default_sign_in_method, "default_sign_in_method")
        )
        new_factors = None if allowed_second_factors is UNSET else _factors(allowed_second_factors)
        before: SignInSettings | None = None
        outcomes: list[tuple[uuid.UUID, _Outcome]] = []
        try:
            if new_factors is not None and not self._enrolable(new_factors):
                # Users without a factor could never enrol one (ruling CS14).
                raise SignInMethodChangeRefused(
                    "webauthn",
                    "allowing passkeys alone needs WebAuthn configured (a relying party id)",
                )
            async with self._db.transaction() as tx:
                await self._lock_sso(tx)
                before = await self._read(tx, lock="UPDATE")
                default = before.default_sign_in_method if new_default is None else new_default
                factors = before.allowed_second_factors if new_factors is None else new_factors
                moved = default is not before.default_sign_in_method
                if moved and default is SignInMethod.SSO_ONLY and not await self._sso_usable(tx):
                    raise SignInMethodChangeRefused(
                        "sso_not_configured",
                        "sso_only needs single sign-on enabled with an issuer and a client id",
                    )
                in_force: list[tuple[uuid.UUID, SignInMethod]] = []
                if moved:
                    # Every follower's row, locked, with the method in force under
                    # the old default, before the default changes.
                    cur = await tx.execute(
                        sql.SQL(
                            "SELECT u.id, {} FROM {} u WHERE u.sign_in_method IS NULL"
                            " ORDER BY u.id FOR UPDATE OF u"
                        ).format(_EFFECTIVE, _USERS)
                    )
                    in_force = [(row[0], SignInMethod(row[1])) for row in await cur.fetchall()]
                cur = await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET default_sign_in_method = %s, allowed_second_factors = %s,"
                        " updated_at = now(), updated_by = %s"
                        " RETURNING default_sign_in_method, allowed_second_factors,"
                        " updated_at, updated_by"
                    ).format(_SETTINGS),
                    (default.value, _sorted(factors), actor),
                )
                row = await cur.fetchone()
                if row is None:
                    raise RuntimeError("the sign-in settings row is missing; run warden migrate")
                after = _settings(row)
                for user_id, method in in_force:
                    outcome = await self._reconcile(
                        tx, user_id, method, None, actor=actor, source_ip=source_ip, cause="default"
                    )
                    if outcome.resolved == "changed":
                        await self._audit_changed(
                            tx, user_id, method, outcome, actor, source_ip, cause="default"
                        )
                    outcomes.append((user_id, outcome))
                await self._audit(
                    tx,
                    "warden.identity.sign_in_settings_changed",
                    actor,
                    None,
                    source_ip,
                    resource_type="sign_in_settings",
                    default_from=before.default_sign_in_method.value,
                    default_to=after.default_sign_in_method.value,
                    allowed_second_factors_from=_sorted(before.allowed_second_factors),
                    allowed_second_factors_to=_sorted(after.allowed_second_factors),
                    users_changed=sum(1 for _, o in outcomes if o.resolved == "changed"),
                    users_pending=sum(1 for _, o in outcomes if o.resolved == "pending"),
                )
        except SignInMethodChangeRefused as exc:
            await self._audit_failure(
                "warden.identity.sign_in_settings_changed",
                actor,
                None,
                source_ip,
                exc.reason,
                resource_type="sign_in_settings",
                default_to=None if new_default is None else new_default.value,
            )
            raise
        self.invalidate()
        failed: list[uuid.UUID] = []
        for user_id, outcome in outcomes:
            if outcome.due is not None and not await self._deliver(outcome.due, actor, source_ip):
                failed.append(user_id)
        return SignInSettingsChange(
            settings=after,
            changed=tuple(u for u, o in outcomes if o.resolved == "changed"),
            pending=tuple(u for u, o in outcomes if o.resolved == "pending"),
            links_failed=tuple(failed),
        )

    def _enrolable(self, factors: frozenset[SecondFactorKind]) -> bool:
        """Whether a user holding no second factor could enrol one of ``factors``."""
        return SecondFactorKind.TOTP in factors or self._webauthn

    # A user's method

    async def state(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> SignInMethodState:
        """A user's own setting, the method in force and any pending change.

        Raises ``UserError`` if there is no such user.
        """
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT u.sign_in_method, {}, c.from_method, c.to_method, c.requested_at,"
                    " c.requested_by, c.link_sent_at FROM {} u"
                    " LEFT JOIN {} c ON c.user_id = u.id WHERE u.id = %s"
                ).format(_EFFECTIVE, _USERS, _CHANGES),
                (user_id,),
            )
            row = await cur.fetchone()
        if row is None:
            raise UserError(f"user {user_id} does not exist")
        pending = None
        if row[2] is not None:
            pending = PendingSignInMethod(
                from_method=SignInMethod(row[2]),
                to_method=SignInMethod(row[3]),
                requested_at=row[4],
                requested_by=row[5],
                link_sent_at=row[6],
            )
        return SignInMethodState(
            user_id=user_id,
            setting=None if row[0] is None else SignInMethod(row[0]),
            effective=SignInMethod(row[1]),
            pending=pending,
        )

    async def set_user_method(
        self,
        user_id: uuid.UUID,
        method: SignInMethod | None,
        *,
        actor: str | None,
        source_ip: SourceIp = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> SignInMethodState:
        """Set a user's own method; None has them follow the instance default.

        At once when the user holds the new method's credential (and then
        anything it does not allow is removed), else pending, with a set-up
        link mailed in this transaction where one is needed (ruling CS18).
        Raises ``UserError`` for no such user; ``SignInMethodConflict`` when
        the user would be ``sso_only`` while holding a security key or
        passkey (Skuld question 25); ``SignInMethodChangeRefused`` when
        ``sso_only`` is chosen without single sign-on set up, or a link is
        needed and cannot be sent; ``MailDeliveryError`` if the sender
        fails. Nothing changes on any refusal, and each is audited.
        """
        if method is not None and not isinstance(method, SignInMethod):
            method = _method(method, "sign_in_method")
        previous: SignInMethod | None = None
        in_force: SignInMethod | None = None
        try:
            async with self._db.transaction(conn) as tx:
                await self._lock_sso(tx)
                settings = await self._read(tx, lock="SHARE")
                cur = await tx.execute(
                    sql.SQL(
                        "SELECT u.sign_in_method, {} FROM {} u WHERE u.id = %s FOR UPDATE OF u"
                    ).format(_EFFECTIVE, _USERS),
                    (user_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    raise UserError(f"user {user_id} does not exist")
                previous = None if row[0] is None else SignInMethod(row[0])
                in_force = SignInMethod(row[1])
                target = _resolve(method, settings.default_sign_in_method)
                if target is SignInMethod.SSO_ONLY:
                    if await self._holds_any_key(tx, user_id):
                        raise SignInMethodConflict(f"user {user_id} holds WebAuthn credentials")
                    if target is not in_force and not await self._sso_usable(tx):
                        raise SignInMethodChangeRefused(
                            "sso_not_configured",
                            "sso_only needs single sign-on enabled with an issuer and a client id",
                        )
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET sign_in_method = %s, updated_at = now() WHERE id = %s"
                    ).format(_USERS),
                    (_value(method), user_id),
                )
                outcome = await self._reconcile(
                    tx,
                    user_id,
                    in_force,
                    previous,
                    actor=actor,
                    source_ip=source_ip,
                    cause="setting",
                )
                await self._audit_changed(
                    tx,
                    user_id,
                    in_force,
                    outcome,
                    actor,
                    source_ip,
                    cause="setting",
                    setting_from=_value(previous),
                    setting_to=_value(method),
                )
                if outcome.due is not None:
                    await self._send(tx, outcome.due, actor, source_ip)
        except SignInMethodConflict as exc:
            reason = getattr(exc, "reason", "webauthn_credentials")
            await self._audit_failure(
                "warden.identity.user.sign_in_method_changed",
                actor,
                user_id,
                source_ip,
                reason,
                extra={"from": _value(in_force), "to": _value(method)},
            )
            raise
        except MailDeliveryError:
            await self._audit_failure(
                "warden.identity.user.sign_in_method_link_sent",
                actor,
                user_id,
                source_ip,
                "delivery_failed",
            )
            raise
        return await self.state(user_id, conn=conn)

    async def resend(
        self, user_id: uuid.UUID, *, actor: str | None, source_ip: SourceIp = None
    ) -> datetime:
        """Mail a fresh set-up link for a pending change, revoking the earlier one.

        Returns when the new link expires. Raises ``UserError`` for no such
        user, ``SignInMethodChangeRefused`` (``not_pending``, ``no_link``,
        ``user_inactive``, or a link that cannot be sent) and
        ``MailDeliveryError``; refusals are audited.
        """
        try:
            async with self._db.transaction() as tx:
                row = await self._lock_with_change(tx, user_id)
                status, email, display_name, to_method = row[0], row[1], row[2], row[4]
                if to_method is None:
                    raise SignInMethodChangeRefused("not_pending", "no change is pending")
                link = setup_link_for(SignInMethod(to_method))
                if link is None:
                    raise SignInMethodChangeRefused(
                        "no_link", "the change completes at the first single sign-on"
                    )
                if status != UserStatus.ACTIVE:
                    raise SignInMethodChangeRefused(
                        "user_inactive", "set-up links go to active users only"
                    )
                self._require_link(link)
                due = await self._issue_link(tx, user_id, link, email, display_name, actor)
                await self._send(tx, due, actor, source_ip)
        except (SignInMethodChangeRefused, MailDeliveryError) as exc:
            reason = exc.reason if isinstance(exc, SignInMethodChangeRefused) else "delivery_failed"
            await self._audit_failure(
                "warden.identity.user.sign_in_method_link_sent", actor, user_id, source_ip, reason
            )
            raise
        return due.expires_at

    async def cancel(
        self, user_id: uuid.UUID, *, actor: str | None, source_ip: SourceIp = None
    ) -> SignInMethodState:
        """Cancel a pending change: the user stays on the method in force.

        The user's own setting goes back to what it was before the change,
        or, where that would no longer resolve to the method in force (a
        change of the default), to the method in force itself; the set-up
        link stops working. Raises ``UserError`` for no such user and
        ``SignInMethodChangeRefused`` (``not_pending``), audited.
        """
        try:
            async with self._db.transaction() as tx:
                await self._lock_sso(tx)
                settings = await self._read(tx, lock="SHARE")
                row = await self._lock_with_change(tx, user_id)
                own, from_method, to_method, previous_setting = row[3], row[5], row[4], row[6]
                if to_method is None or from_method is None:
                    raise SignInMethodChangeRefused("not_pending", "no change is pending")
                in_force = SignInMethod(from_method)
                restore = None if previous_setting is None else SignInMethod(previous_setting)
                if _resolve(restore, settings.default_sign_in_method) is not in_force:
                    restore = in_force
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET sign_in_method = %s, updated_at = now() WHERE id = %s"
                    ).format(_USERS),
                    (_value(restore), user_id),
                )
                await tx.execute(
                    sql.SQL("DELETE FROM {} WHERE user_id = %s").format(_CHANGES), (user_id,)
                )
                link = setup_link_for(SignInMethod(to_method))
                if link is not None:
                    await self._tokens.revoke_live(tx, user_id, _purpose(link))
                await self._audit(
                    tx,
                    "warden.identity.user.sign_in_method_pending_cancelled",
                    actor,
                    user_id,
                    source_ip,
                    reason="cancelled",
                    **{"from": from_method, "to": to_method},
                    setting_from=own,
                    setting_to=_value(restore),
                )
        except SignInMethodChangeRefused as exc:
            await self._audit_failure(
                "warden.identity.user.sign_in_method_pending_cancelled",
                actor,
                user_id,
                source_ip,
                exc.reason,
            )
            raise
        return await self.state(user_id)

    async def credential_added(
        self,
        tx: AsyncConnection[Any],
        user_id: uuid.UUID,
        *,
        actor: str | None,
        source_ip: SourceIp,
        keep_session: uuid.UUID | None = None,
    ) -> bool:
        """Complete the user's pending change if its credential now exists; whether it did.

        Called in the transaction that added a credential (a passkey, a
        password, a first single sign-on), after it is written. Removes
        whatever the new method does not allow, except the session
        ``keep_session``, and audits the change.
        """
        cur = await tx.execute(
            sql.SQL(
                "SELECT c.from_method, c.to_method, u.password_hash IS NOT NULL FROM {} c"
                " JOIN {} u ON u.id = c.user_id WHERE c.user_id = %s FOR UPDATE OF c"
            ).format(_CHANGES, _USERS),
            (user_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return False
        in_force, target = SignInMethod(row[0]), SignInMethod(row[1])
        if not await self._holds(tx, user_id, target, has_password=bool(row[2])):
            return False
        removed = await self._complete(tx, user_id, target, keep_session=keep_session)
        await self._audit_changed(
            tx,
            user_id,
            in_force,
            _Outcome("changed", target, removed),
            actor,
            source_ip,
            cause="completed",
        )
        return True

    # Internals

    async def _reconcile(
        self,
        tx: AsyncConnection[Any],
        user_id: uuid.UUID,
        in_force: SignInMethod,
        previous_setting: SignInMethod | None,
        *,
        actor: str | None,
        source_ip: SourceIp,
        cause: str,
    ) -> _Outcome:
        """Bring a locked user's pending change in line with their setting and the default.

        ``in_force`` is the method in force before the setting or default
        changed. Completes the move at once, records it as pending (with a
        link due where one is needed), or removes a pending change that the
        user's setting and the default no longer ask for.
        """
        cur = await tx.execute(
            sql.SQL(
                "SELECT u.status, u.sign_in_method, u.password_hash IS NOT NULL, u.email,"
                " u.display_name, c.to_method, c.previous_setting,"
                " (SELECT s.default_sign_in_method FROM {} s)"
                " FROM {} u LEFT JOIN {} c ON c.user_id = u.id WHERE u.id = %s"
            ).format(_SETTINGS, _USERS, _CHANGES),
            (user_id,),
        )
        row = await cur.fetchone()
        if row is None:
            raise UserError(f"user {user_id} does not exist")
        status, own, has_password, email, display_name, pending_to, pending_previous, default = row
        target = _resolve(None if own is None else SignInMethod(own), SignInMethod(default))
        if target is in_force:
            if pending_to is not None:
                await self._drop_change(tx, user_id)
                await self._audit(
                    tx,
                    "warden.identity.user.sign_in_method_pending_cancelled",
                    actor,
                    user_id,
                    source_ip,
                    reason="superseded",
                    cause=cause,
                    **{"from": in_force.value, "to": pending_to},
                )
            return _Outcome("unchanged", target, {})
        if status == UserStatus.INVITED:
            # An invitation is accepted the way the method in force says;
            # there is no credential yet, so nothing to wait for or remove.
            await self._drop_change(tx, user_id)
            return _Outcome("changed", target, {})
        if await self._holds(tx, user_id, target, has_password=bool(has_password)):
            return _Outcome("changed", target, await self._complete(tx, user_id, target))
        link = setup_link_for(target)
        if pending_to == target.value:
            return _Outcome("pending", target, {})
        send = link is not None and status == UserStatus.ACTIVE
        if send and link is not None:
            self._require_link(link)
        await tx.execute(
            sql.SQL(
                "INSERT INTO {} (user_id, from_method, to_method, previous_setting, requested_by)"
                " VALUES (%s, %s, %s, %s, %s)"
                " ON CONFLICT (user_id) DO UPDATE SET to_method = EXCLUDED.to_method,"
                " requested_by = EXCLUDED.requested_by, requested_at = now(), link_sent_at = NULL"
            ).format(_CHANGES),
            (
                user_id,
                in_force.value,
                target.value,
                pending_previous if pending_to is not None else _value(previous_setting),
                actor,
            ),
        )
        await self._audit(
            tx,
            "warden.identity.user.sign_in_method_pending",
            actor,
            user_id,
            source_ip,
            cause=cause,
            link=None if link is None else link.value,
            link_sent=send,
            **{"from": in_force.value, "to": target.value},
        )
        due = None
        if send and link is not None:
            due = await self._issue_link(tx, user_id, link, email, display_name, actor)
        return _Outcome("pending", target, {}, due)

    async def _complete(
        self,
        tx: AsyncConnection[Any],
        user_id: uuid.UUID,
        target: SignInMethod,
        *,
        keep_session: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Put ``target`` in force and remove what it does not allow; what was removed."""
        password_removed = False
        if not allows_password(target):
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET password_hash = NULL, updated_at = now()"
                    " WHERE id = %s AND password_hash IS NOT NULL"
                ).format(_USERS),
                (user_id,),
            )
            password_removed = cur.rowcount == 1
        keys_removed = 0
        if target is SignInMethod.SSO_ONLY:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE user_id = %s").format(_CREDENTIALS), (user_id,)
            )
            keys_removed = cur.rowcount
        # The sessions signed in a way the method no longer allows.
        conditions: list[sql.Composable] = []
        if not allows_password(target):
            conditions.append(sql.SQL("{} = ANY(amr)").format(sql.Literal(_PASSWORD_AMR)))
        if not allows_sso(target):
            conditions.append(sql.SQL("{} = ANY(amr)").format(sql.Literal(_SSO_AMR)))
        if not allows_passkey_sign_in(target):
            conditions.append(sql.SQL("{} = ANY(amr)").format(sql.Literal(_KEY_AMR)))
        ended = 0
        if conditions:
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET revoked_at = now(), revoked_reason = %s WHERE user_id = %s"
                    " AND revoked_at IS NULL AND id IS DISTINCT FROM %s AND ({})"
                ).format(_SESSIONS, sql.SQL(" OR ").join(conditions)),
                (_REVOKED_REASON, user_id, keep_session),
            )
            ended = cur.rowcount
        await self._drop_change(tx, user_id)
        return {
            "password_removed": password_removed,
            "webauthn_removed": keys_removed,
            "sessions_ended": ended,
        }

    async def _holds(
        self,
        tx: AsyncConnection[Any],
        user_id: uuid.UUID,
        method: SignInMethod,
        *,
        has_password: bool,
    ) -> bool:
        """Whether the user holds the credential ``method`` signs in with."""
        if allows_password(method):
            return has_password
        if method is SignInMethod.PASSKEY_ONLY:
            query = sql.SQL(
                "SELECT EXISTS (SELECT 1 FROM {} WHERE user_id = %s"
                " AND discoverable AND user_verified)"
            ).format(_CREDENTIALS)
        else:
            query = sql.SQL("SELECT EXISTS (SELECT 1 FROM {} WHERE user_id = %s)").format(
                _IDENTITIES
            )
        cur = await tx.execute(query, (user_id,))
        row = await cur.fetchone()
        return bool(row and row[0])

    async def _holds_any_key(self, tx: AsyncConnection[Any], user_id: uuid.UUID) -> bool:
        cur = await tx.execute(
            sql.SQL("SELECT EXISTS (SELECT 1 FROM {} WHERE user_id = %s)").format(_CREDENTIALS),
            (user_id,),
        )
        row = await cur.fetchone()
        return bool(row and row[0])

    async def _drop_change(self, tx: AsyncConnection[Any], user_id: uuid.UUID) -> None:
        await tx.execute(sql.SQL("DELETE FROM {} WHERE user_id = %s").format(_CHANGES), (user_id,))

    async def _lock_with_change(
        self, tx: AsyncConnection[Any], user_id: uuid.UUID
    ) -> tuple[Any, ...]:
        """The locked user's status, email, name and setting, and any pending change."""
        cur = await tx.execute(
            sql.SQL(
                "SELECT u.status, u.email, u.display_name, u.sign_in_method, c.to_method,"
                " c.from_method, c.previous_setting FROM {} u LEFT JOIN {} c ON c.user_id = u.id"
                " WHERE u.id = %s FOR UPDATE OF u"
            ).format(_USERS, _CHANGES),
            (user_id,),
        )
        row = await cur.fetchone()
        if row is None:
            raise UserError(f"user {user_id} does not exist")
        return tuple(row)

    async def _lock_sso(self, tx: AsyncConnection[Any]) -> None:
        """Shared with every other user of single sign-on; exclusive with its settings change."""
        await tx.execute("SELECT pg_advisory_xact_lock_shared(%s)", (SSO_SETTINGS_LOCK_KEY,))

    async def _sso_usable(self, tx: AsyncConnection[Any]) -> bool:
        return usable(await self._sso.read(tx))

    def _require_link(self, link: SetupLink) -> None:
        """Refuse, naming what is missing, when this link cannot be sent."""
        http = self._config.http
        if not self._mailer.configured:
            raise SignInMethodChangeRefused(
                "mail_sender",
                "a set-up link is needed and no mail sender is configured: pass mail_sender "
                "to Identity",
            )
        if link is SetupLink.PASSKEY_REGISTRATION:
            if not self._webauthn:
                raise SignInMethodChangeRefused("webauthn", "WebAuthn is not configured")
            if http.passkey_registration_link is None:
                raise SignInMethodChangeRefused(
                    "passkey_registration_link",
                    "a passkey registration link is needed and "
                    "http.passkey_registration_link is not configured",
                )
        elif http.reset_password_link is None:
            raise SignInMethodChangeRefused(
                "reset_password_link",
                "a set-password link is needed and http.reset_password_link is not configured",
            )

    async def _issue_link(
        self,
        tx: AsyncConnection[Any],
        user_id: uuid.UUID,
        link: SetupLink,
        email: str,
        display_name: str | None,
        actor: str | None,
    ) -> _LinkDue:
        purpose = _purpose(link)
        await self._tokens.revoke_live(tx, user_id, purpose)
        issued = await self._tokens.issue(
            tx,
            user_id,
            purpose,
            ttl_seconds=self._config.identity.reset_ttl_seconds,
            created_by=actor,
        )
        await tx.execute(
            sql.SQL("UPDATE {} SET link_sent_at = now() WHERE user_id = %s").format(_CHANGES),
            (user_id,),
        )
        return _LinkDue(user_id, link, issued.token, issued.expires_at, email, display_name)

    async def _send(
        self,
        conn: AsyncConnection[Any] | None,
        due: _LinkDue,
        actor: str | None,
        source_ip: SourceIp,
    ) -> None:
        http = self._config.http
        if due.link is SetupLink.PASSKEY_REGISTRATION:
            kind, template = MailKind.PASSKEY_REGISTRATION, http.passkey_registration_link
        else:
            kind, template = MailKind.PASSWORD_SETUP, http.reset_password_link
        if template is None:
            raise MailError("the set-up link is not configured")
        await self._mailer.send(
            kind,
            email=due.email,
            display_name=due.display_name,
            link=http.render_link(template, token=due.token),
            expires_at=due.expires_at,
        )
        await self._audit(
            conn,
            "warden.identity.user.sign_in_method_link_sent",
            actor,
            due.user_id,
            source_ip,
            link=due.link.value,
            expires_at=due.expires_at.isoformat(),
        )

    async def _deliver(self, due: _LinkDue, actor: str | None, source_ip: SourceIp) -> bool:
        """Send a link after its change committed; a failure is audited, never raised."""
        try:
            await self._send(None, due, actor, source_ip)
        except MailError:
            await self._audit_failure(
                "warden.identity.user.sign_in_method_link_sent",
                actor,
                due.user_id,
                source_ip,
                "delivery_failed",
                link=due.link.value,
            )
            return False
        return True

    async def _audit_changed(
        self,
        tx: AsyncConnection[Any],
        user_id: uuid.UUID,
        in_force: SignInMethod,
        outcome: _Outcome,
        actor: str | None,
        source_ip: SourceIp,
        *,
        cause: str,
        **details: Any,
    ) -> None:
        after = outcome.to_method if outcome.resolved == "changed" else in_force
        await self._audit(
            tx,
            "warden.identity.user.sign_in_method_changed",
            actor,
            user_id,
            source_ip,
            **{"from": in_force.value, "to": after.value},
            cause=cause,
            pending=outcome.resolved == "pending",
            **details,
            **outcome.removed,
        )

    async def _audit(
        self,
        conn: AsyncConnection[Any] | None,
        action: str,
        actor: str | None,
        user_id: uuid.UUID | None,
        source_ip: SourceIp,
        *,
        resource_type: str = "user",
        **details: Any,
    ) -> None:
        await record_audit(
            AuditEvent(
                action=action,
                outcome="success",
                actor=actor,
                resource_type=resource_type,
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details=details,
            ),
            conn=conn,
        )

    async def _audit_failure(
        self,
        action: str,
        actor: str | None,
        user_id: uuid.UUID | None,
        source_ip: SourceIp,
        reason: str,
        *,
        resource_type: str = "user",
        extra: dict[str, Any] | None = None,
        **details: Any,
    ) -> None:
        await record_audit(
            AuditEvent(
                action=action,
                outcome="failure",
                actor=actor,
                resource_type=resource_type,
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details={**(extra or {}), **details, "reason": reason},
            )
        )


def _purpose(link: SetupLink) -> Purpose:
    return (
        Purpose.PASSKEY_REGISTRATION
        if link is SetupLink.PASSKEY_REGISTRATION
        else Purpose.PASSWORD_RESET
    )
