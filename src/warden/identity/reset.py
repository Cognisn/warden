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
from warden.identity.passwords import MAX_PASSWORD_LENGTH, PasswordHasher
from warden.identity.single_use import Purpose, SingleUseTokens, well_formed
from warden.identity.tokens import Sessions
from warden.identity.users import SignInMethod, UserError, UserStatus, is_email

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
    if account.sign_in_method != SignInMethod.PASSWORD_AND_SSO:
        return "sso_only"
    return None


class _Abort(Exception):
    """Ends a transaction without committing it."""


class PasswordResets:
    def __init__(
        self,
        config: WardenConfig,
        db: Database,
        tokens: SingleUseTokens,
        mailer: Mailer,
        hasher: PasswordHasher,
        sessions: Sessions,
    ) -> None:
        self._config = config
        self._db = db
        self._tokens = tokens
        self._mailer = mailer
        self._hasher = hasher
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

        Raises ``UserError`` for an unacceptable password (the link is
        untouched) and ``AuthenticationRefused`` for any other refusal, with
        the reason in the audit trail. Returns the user's id.
        """
        if not well_formed(token):
            await self._refuse("malformed", None, source_ip)
        minimum = self._config.identity.password_min_length
        if not isinstance(new_password, str) or not (
            minimum <= len(new_password) <= MAX_PASSWORD_LENGTH
        ):
            raise UserError(
                f"password must be between {minimum} and {MAX_PASSWORD_LENGTH} characters"
            )
        password_hash = await self._hasher.hash(new_password)
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
                else:
                    await tx.execute(
                        sql.SQL(
                            "UPDATE {} SET password_hash = %s, updated_at = now() WHERE id = %s"
                        ).format(_USERS),
                        (password_hash, account.id),
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
