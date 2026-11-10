"""Password reset by emailed link.

``request`` mails a single-use link to an active user who signs in with a
password, revoking any earlier link. Nothing in its result reaches an
unauthenticated caller: the public route answers every request the same
way, after the work, so neither the response nor its timing says whether
an address has an account. The reason a request sent nothing (no such
user, ``sso_only``, not active) goes to the audit trail.

``complete`` sets the new password and ends every session of the user. It
decides under row locks on the user and then the token, and uses the token
up with one guarded write (#127). A link whose user is no longer active,
or now signs in only through single sign-on, is refused and spent.

The new password is checked against the user's password policy (rules,
watch lists and history; not the minimum age, so a user who forgot their
password can always reset it) once the link is known to be live, and
before anything is written: a refused password leaves the link usable. A
bad, used or expired link is refused uniformly whatever the password.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, NoReturn

from psycopg import AsyncConnection, sql

from warden.audit import ActionRegistry, AuditEvent, Severity, record_audit
from warden.audit.registry import register_warden_action
from warden.config import WardenConfig
from warden.db import Database, schema, table
from warden.identity.errors import AuthenticationRefused
from warden.identity.http import SourceIp
from warden.identity.mail import MailDeliveryError, Mailer, MailError, MailKind
from warden.identity.password_enforcement import AcceptedPassword, PasswordEnforcement
from warden.identity.password_policy.rules import UserContext
from warden.identity.single_use import Purpose, SingleUseTokens, well_formed
from warden.identity.tokens import Sessions
from warden.identity.users import SignInMethod, UserStatus, is_email

__all__ = ["RESET_ACTIONS", "PasswordResets", "register_actions"]

RESET_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    (
        "warden.identity.password.reset_requested",
        Severity.NOTICE,
        "password reset for {resource_id} requested: {outcome}",
    ),
    (
        "warden.identity.password.reset",
        Severity.NOTICE,
        "password of {resource_id} reset: {outcome}",
    ),
)

_USERS = table(schema.USERS)
_MAX_IDENTIFIER = 320


def register_actions(registry: ActionRegistry) -> None:
    for action, severity, summary in RESET_ACTIONS:
        register_warden_action(registry, action, severity=severity, summary=summary)


@dataclass(frozen=True, slots=True)
class _Account:
    id: uuid.UUID
    email: str
    display_name: str | None
    status: str
    sign_in_method: str


def _refusal(account: _Account) -> str | None:
    """Why this account cannot use a password reset now, or None."""
    if account.status != UserStatus.ACTIVE:
        return f"user_{account.status}"
    if account.sign_in_method == SignInMethod.PASSKEY_ONLY:
        return "passkey_only"  # ruling P5: no password to reset
    if account.sign_in_method != SignInMethod.PASSWORD_AND_SSO:
        return "sso_only"
    return None


class _Abort(Exception):
    """Ends a transaction without committing it."""


@dataclass(frozen=True, slots=True)
class _Checked:
    """A new password the link's user's policy accepted, before the link is spent."""

    user_id: uuid.UUID
    password: AcceptedPassword


class PasswordResets:
    def __init__(
        self,
        config: WardenConfig,
        db: Database,
        tokens: SingleUseTokens,
        mailer: Mailer,
        passwords: PasswordEnforcement,
        sessions: Sessions,
    ) -> None:
        self._config = config
        self._db = db
        self._tokens = tokens
        self._mailer = mailer
        self._passwords = passwords
        self._sessions = sessions

    async def request(
        self, email: object, *, actor: str | None = None, source_ip: SourceIp = None
    ) -> str | None:
        """Mail a reset link if ``email`` belongs to an active password user.

        Returns None once a link is sent, else the refusal reason (also
        audited). Never show the reason to an unauthenticated caller. Raises
        ``MailError`` without a sender and ``MailDeliveryError`` if the sender
        fails, leaving no link behind.
        """
        if not isinstance(email, str) or not is_email(email):
            await self._audit_request(None, actor, source_ip, "malformed")
            return "malformed"
        if not self._mailer.configured:
            raise MailError("no mail sender is configured; pass mail_sender to Identity")
        reason: str | None = None
        account: _Account | None = None
        try:
            async with self._db.transaction() as tx:
                account = await self._lock_account(tx, email=email)
                reason = "unknown_user" if account is None else _refusal(account)
                if reason is not None or account is None:
                    raise _Abort
                await self._tokens.revoke_live(tx, account.id, Purpose.PASSWORD_RESET)
                issued = await self._tokens.issue(
                    tx,
                    account.id,
                    Purpose.PASSWORD_RESET,
                    ttl_seconds=self._config.identity.reset_ttl_seconds,
                    created_by=actor,
                )
                http = self._config.http
                await self._mailer.send(
                    MailKind.PASSWORD_RESET,
                    email=account.email,
                    display_name=account.display_name,
                    link=http.render_link(http.reset_password_link, token=issued.token),
                    expires_at=issued.expires_at,
                )
                await self._audit_request(
                    account.id,
                    actor,
                    source_ip,
                    None,
                    conn=tx,
                    expires_at=issued.expires_at.isoformat(),
                )
        except _Abort:
            pass
        except MailDeliveryError:
            await self._audit_request(
                None if account is None else account.id, actor, source_ip, "delivery_failed"
            )
            raise
        if reason is not None:
            # As for a refused sign-in, an unknown address is recorded (it is
            # email-shaped by now), so repeated probing shows in the trail.
            if account is None:
                await self._audit_request(None, actor, source_ip, reason, identifier=email)
            else:
                await self._audit_request(account.id, actor, source_ip, reason)
        return reason

    async def complete(
        self, token: object, new_password: object, *, source_ip: SourceIp = None
    ) -> uuid.UUID:
        """Set a new password with a reset link and end every session of its user.

        Raises ``PasswordRejected`` (a ``UserError``) for a password the
        user's policy refuses, naming every failure (the link is untouched),
        and ``AuthenticationRefused`` for any other refusal, with the reason
        in the audit trail. Returns the user's id.
        """
        if not well_formed(token):
            await self._refuse("malformed", None, source_ip)
        accepted = await self._check_password(token, new_password, source_ip)
        reason: str | None = None
        account: _Account | None = None
        try:
            async with self._db.transaction() as tx:
                user_id = await self._tokens.owner(tx, token, Purpose.PASSWORD_RESET)
                account = None if user_id is None else await self._lock_account(tx, user_id=user_id)
                if account is None:
                    reason = "unknown_token"
                    raise _Abort
                if await self._tokens.consume(tx, token, Purpose.PASSWORD_RESET) is None:
                    reason = "token_not_live"
                    raise _Abort
                reason = _refusal(account)
                if reason is not None:
                    # The link is spent; record why in the same transaction.
                    await self._audit_reset(tx, account.id, source_ip, reason)
                elif accepted is None or accepted.user_id != account.id:
                    # Only a link whose user was refused skips the check above.
                    reason = "unknown_token"
                    raise _Abort
                else:
                    await tx.execute(
                        sql.SQL(
                            "UPDATE {} SET password_hash = %s, updated_at = now() WHERE id = %s"
                        ).format(_USERS),
                        (accepted.password.password_hash, account.id),
                    )
                    await self._passwords.record(
                        tx,
                        account.id,
                        accepted.password,
                        place="reset",
                        actor=str(account.id),
                        source_ip=source_ip,
                    )
                    ended = await self._sessions.revoke_all(
                        account.id, reason="password_reset", conn=tx
                    )
                    await self._tokens.revoke_live(tx, account.id, Purpose.PASSWORD_RESET)
                    await self._audit_reset(tx, account.id, source_ip, None, sessions_ended=ended)
        except _Abort:
            await self._refuse(reason or "unknown_token", account, source_ip)
        if reason is not None or account is None:
            raise AuthenticationRefused(reason or "unknown_token")
        return account.id

    async def _check_password(
        self, token: str, new_password: object, source_ip: SourceIp
    ) -> _Checked | None:
        """The new password, checked against the link's user's policy, before any write.

        A link that is not live is refused here, uniformly, so nothing about a
        policy reaches a caller without one. A live link whose user may no
        longer reset (not active, or no password) returns None: the locked
        transaction spends the link and records why, as before.
        """
        async with self._db.connection() as conn:
            owner = await self._tokens.owner(conn, token, Purpose.PASSWORD_RESET)
            account = None if owner is None else await self._read_account(conn, owner)
            live = await self._tokens.peek(conn, token, Purpose.PASSWORD_RESET)
        if account is None:
            await self._refuse("unknown_token", None, source_ip)
        if live is None:
            await self._refuse("token_not_live", account, source_ip)
        if _refusal(account) is not None:
            return None
        accepted = await self._passwords.accept(
            new_password,
            policy=await self._passwords.policy_for(account.id),
            context=UserContext(account.email, account.display_name),
            user_id=account.id,
            place="reset",
            actor=str(account.id),
            source_ip=source_ip,
        )
        return _Checked(account.id, accepted)

    async def subject(self, token: object) -> tuple[uuid.UUID, UserContext] | None:
        """The user a live reset link may set a password for, without touching it; else None.

        For the live feedback routes (ruling PW10): None for a bad, used or
        expired link, or a user who could not complete it.
        """
        if not well_formed(token):
            return None
        async with self._db.connection() as conn:
            live = await self._tokens.peek(conn, token, Purpose.PASSWORD_RESET)
            account = None if live is None else await self._read_account(conn, live.user_id)
        if account is None or _refusal(account) is not None:
            return None
        return account.id, UserContext(account.email, account.display_name)

    async def _read_account(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID
    ) -> _Account | None:
        cur = await conn.execute(
            sql.SQL(
                "SELECT id, email, display_name, status, sign_in_method FROM {} WHERE id = %s"
            ).format(_USERS),
            (user_id,),
        )
        row = await cur.fetchone()
        return None if row is None else _Account(*row)

    async def _lock_account(
        self,
        tx: AsyncConnection[Any],
        *,
        email: str | None = None,
        user_id: uuid.UUID | None = None,
    ) -> _Account | None:
        value: str | uuid.UUID | None
        if email is not None:
            if len(email) > _MAX_IDENTIFIER:
                return None
            where, value = sql.SQL("lower(email) = lower(%s)"), email
        else:
            where, value = sql.SQL("id = %s"), user_id
        cur = await tx.execute(
            sql.SQL(
                "SELECT id, email, display_name, status, sign_in_method FROM {} WHERE {} FOR UPDATE"
            ).format(_USERS, where),
            (value,),
        )
        row = await cur.fetchone()
        return None if row is None else _Account(*row)

    async def _audit_request(
        self,
        user_id: uuid.UUID | None,
        actor: str | None,
        source_ip: SourceIp,
        reason: str | None,
        *,
        conn: AsyncConnection[Any] | None = None,
        **details: Any,
    ) -> None:
        if reason is not None:
            details["reason"] = reason
        await record_audit(
            AuditEvent(
                action="warden.identity.password.reset_requested",
                outcome="success" if reason is None else "failure",
                actor=actor,
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details=details,
            ),
            conn=conn,
        )

    async def _audit_reset(
        self,
        conn: AsyncConnection[Any] | None,
        user_id: uuid.UUID | None,
        source_ip: SourceIp,
        reason: str | None,
        **details: Any,
    ) -> None:
        if reason is not None:
            details["reason"] = reason
        await record_audit(
            AuditEvent(
                action="warden.identity.password.reset",
                outcome="success" if reason is None else "failure",
                actor=None if user_id is None else str(user_id),
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details=details,
            ),
            conn=conn,
        )

    async def _refuse(self, reason: str, account: _Account | None, source_ip: SourceIp) -> NoReturn:
        await self._audit_reset(None, None if account is None else account.id, source_ip, reason)
        raise AuthenticationRefused(reason)
