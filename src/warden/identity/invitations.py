"""Invitations: an invited user, staged role grants, and a single-use link.

Creating an invitation writes a user in the ``invited`` status with no
password (nothing anyone could sign in with), stages the role grants the
user will receive, issues an invitation token and mails its link, all in one
transaction: if the product's sender cannot deliver, nothing is left
behind. The audit records are written last, so the audit chain lock is not
held while the mail is out.

Staged grants belong to the invited user, not to a token, so a resend (a
new link, the old one revoked) carries them whatever happened to the first
link. Revoking an invitation deletes the invited user, but only while the
user is still invited: one guarded ``DELETE``, so it cannot remove a user
who accepted concurrently (#129).

Acceptance is one function, ``_accept``, used by the password variant and
by the single sign-on entry point. Under row locks on the user and then the
token, it decides:

1. whether the token is live (if not, the uniform refusal);
2. whether the method fits (a password for an ``sso_only`` user, or an SSO
   identity for another address): a mismatch is refused **before** the token
   is touched, so the invitation stays usable (#154);
3. whether the user is still invited (#128): if not, the token is used up
   and the acceptance refused (#154);
4. otherwise it consumes the token with one guarded write (#127), completes
   the method (sets the password, or pins the SSO subject through the
   caller's ``pin``), activates the user and applies the staged grants.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, NoReturn, Protocol

import psycopg
from psycopg import AsyncConnection, sql

from warden.audit import ActionRegistry, AuditEvent, Severity, record_audit
from warden.audit.registry import register_warden_action
from warden.config import WardenConfig
from warden.db import Database, schema, table
from warden.db.schema import INVITATION_GRANTS
from warden.identity.errors import AuthenticationRefused
from warden.identity.http import SourceIp
from warden.identity.mail import MailDeliveryError, Mailer, MailError, MailKind
from warden.identity.passwords import MAX_PASSWORD_LENGTH, PasswordHasher
from warden.identity.roles import RoleError, Roles
from warden.identity.single_use import Purpose, SingleUseTokens, well_formed
from warden.identity.users import SignInMethod, User, UserError, Users, UserStatus, check_email

__all__ = [
    "INVITATION_ACTIONS",
    "INVITATION_GRANTS",
    "AcceptedInvitation",
    "Invitation",
    "InvitationError",
    "InvitationMismatch",
    "Invitations",
    "PendingInvitation",
    "StagedGrant",
    "SubjectPin",
    "VerifiedIdentity",
    "register_actions",
]


INVITATION_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    (
        "warden.identity.invitation.created",
        Severity.NOTICE,
        "{actor} invited {resource_id}: {outcome}",
    ),
    (
        "warden.identity.invitation.resent",
        Severity.NOTICE,
        "{actor} resent the invitation of {resource_id}: {outcome}",
    ),
    (
        "warden.identity.invitation.revoked",
        Severity.NOTICE,
        "{actor} revoked the invitation of {resource_id}: {outcome}",
    ),
    (
        "warden.identity.invitation.accepted",
        Severity.NOTICE,
        "invitation of {resource_id} accepted: {outcome}",
    ),
)

_USERS = table(schema.USERS)
_GRANTS = table(INVITATION_GRANTS)

Method = Literal["password", "sso"]


def register_actions(registry: ActionRegistry) -> None:
    for action, severity, summary in INVITATION_ACTIONS:
        register_warden_action(registry, action, severity=severity, summary=summary)


class InvitationError(Exception):
    """An administrative invitation change was refused. Messages carry no values."""


class InvitationMismatch(InvitationError):
    """The invitation is valid but was accepted the wrong way; it stays usable."""


@dataclass(frozen=True, slots=True)
class StagedGrant:
    """A role the invited user receives on acceptance, optionally expiring."""

    role: str
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Invitation:
    """An invitation just created or resent. The link went by mail and is not kept."""

    user_id: uuid.UUID
    email: str
    expires_at: datetime
    grants: tuple[StagedGrant, ...]


@dataclass(frozen=True, slots=True)
class PendingInvitation:
    user: User
    expires_at: datetime | None
    """When the live link expires; None if it has lapsed (resend to issue another)."""
    grants: tuple[StagedGrant, ...]


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """An identity the caller has already verified with the identity provider."""

    issuer: str
    subject: str
    email: str


class SubjectPin(Protocol):
    """Single sign-on's subject pinning, run inside the acceptance transaction.

    Raising rolls the acceptance back and leaves the invitation usable.
    """

    async def __call__(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, issuer: str, subject: str
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class AcceptedInvitation:
    user_id: uuid.UUID
    email: str
    method: Method
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Invitee:
    id: uuid.UUID
    email: str
    status: str
    sign_in_method: str


class _Abort(Exception):
    """Ends an acceptance transaction without committing it."""


Complete = Callable[[AsyncConnection[Any], _Invitee], Awaitable[None]]
MethodCheck = Callable[[_Invitee], str | None]


class Invitations:
    def __init__(
        self,
        config: WardenConfig,
        db: Database,
        users: Users,
        roles: Roles,
        tokens: SingleUseTokens,
        mailer: Mailer,
        hasher: PasswordHasher,
    ) -> None:
        self._config = config
        self._db = db
        self._users = users
        self._roles = roles
        self._tokens = tokens
        self._mailer = mailer
        self._hasher = hasher

    # Administration

    async def create(
        self,
        email: str,
        *,
        actor: str | None,
        display_name: str | None = None,
        sign_in_method: SignInMethod = SignInMethod.PASSWORD_AND_SSO,
        grants: Sequence[StagedGrant] = (),
        source_ip: SourceIp = None,
    ) -> Invitation:
        """Invite ``email``: an invited user, staged grants, and a mailed link.

        Raises ``UserError`` for an invalid address, ``InvitationError`` if the
        address is taken, ``RoleError`` for a bad grant, ``MailError`` without
        a sender, and ``MailDeliveryError`` if the sender fails; in every case
        nothing is written.
        """
        try:
            check_email(email)
        except UserError:
            raise InvitationError("email address is not valid") from None
        staged = self._check_grants(grants)
        self._require_mail()
        try:
            async with self._db.transaction() as tx:
                user = await self._insert_invitee(tx, email, display_name, sign_in_method)
                await self._stage(tx, user.id, staged, actor)
                issued = await self._tokens.issue(
                    tx,
                    user.id,
                    Purpose.INVITATION,
                    ttl_seconds=self._config.identity.invitation_ttl_seconds,
                    created_by=actor,
                )
                await self._mail(user, issued.token, issued.expires_at)
                await self._audit_success(
                    tx,
                    "warden.identity.user.created",
                    actor,
                    user.id,
                    source_ip,
                    status=UserStatus.INVITED.value,
                    sign_in_method=sign_in_method.value,
                )
                await self._audit_success(
                    tx,
                    "warden.identity.invitation.created",
                    actor,
                    user.id,
                    source_ip,
                    roles=[g.role for g in staged],
                    expires_at=issued.expires_at.isoformat(),
                )
        except MailDeliveryError:
            await self._audit_failure(
                "warden.identity.invitation.created", actor, None, source_ip, "delivery_failed"
            )
            raise
        return Invitation(user.id, user.email, issued.expires_at, staged)

    async def resend(
        self, user_id: uuid.UUID, *, actor: str | None, source_ip: SourceIp = None
    ) -> Invitation:
        """Mail a new link, revoking the old; the staged grants carry over.

        If the mail fails, nothing changes and the previous link still works.
        """
        self._require_mail()
        try:
            async with self._db.transaction() as tx:
                cur = await tx.execute(
                    sql.SQL(
                        "SELECT id, email, display_name, status FROM {} WHERE id = %s FOR UPDATE"
                    ).format(_USERS),
                    (user_id,),
                )
                row = await cur.fetchone()
                if row is None or row[3] != UserStatus.INVITED:
                    raise InvitationError("the invitation is not pending")
                user = await self._users.get(user_id, conn=tx)
                if user is None:
                    raise InvitationError("the invitation is not pending")
                revoked = await self._tokens.revoke_live(tx, user_id, Purpose.INVITATION)
                issued = await self._tokens.issue(
                    tx,
                    user_id,
                    Purpose.INVITATION,
                    ttl_seconds=self._config.identity.invitation_ttl_seconds,
                    created_by=actor,
                )
                staged = await self._staged(tx, user_id)
                await self._mail(user, issued.token, issued.expires_at)
                await self._audit_success(
                    tx,
                    "warden.identity.invitation.resent",
                    actor,
                    user_id,
                    source_ip,
                    previous_links_revoked=revoked,
                    expires_at=issued.expires_at.isoformat(),
                )
        except MailDeliveryError:
            await self._audit_failure(
                "warden.identity.invitation.resent", actor, user_id, source_ip, "delivery_failed"
            )
            raise
        return Invitation(user_id, user.email, issued.expires_at, staged)

    async def revoke(
        self, user_id: uuid.UUID, *, actor: str | None, source_ip: SourceIp = None
    ) -> None:
        """Withdraw a pending invitation, deleting the invited user.

        One guarded delete: a user who has accepted, even concurrently, is
        never removed, and the revocation is refused instead (#129).
        """
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE id = %s AND status = %s RETURNING 1").format(_USERS),
                (user_id, UserStatus.INVITED.value),
            )
            deleted = await cur.fetchone() is not None
            if deleted:
                await self._audit_success(
                    tx, "warden.identity.invitation.revoked", actor, user_id, source_ip
                )
        if not deleted:
            await self._audit_failure(
                "warden.identity.invitation.revoked", actor, user_id, source_ip, "not_pending"
            )
            raise InvitationError("the invitation is not pending")

    async def pending(self) -> list[PendingInvitation]:
        """Every invited user, with the expiry of their live link and their staged grants."""
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("SELECT id FROM {} WHERE status = %s ORDER BY created_at, id").format(
                    _USERS
                ),
                (UserStatus.INVITED.value,),
            )
            found: list[PendingInvitation] = []
            for (user_id,) in await cur.fetchall():
                user = await self._users.get(user_id, conn=tx)
                if user is None:
                    continue
                expiry = await self._tokens.live_expiry(tx, user_id, Purpose.INVITATION)
                found.append(PendingInvitation(user, expiry, await self._staged(tx, user_id)))
        return found

    # Acceptance

    async def accept_with_password(
        self, token: object, password: object, *, source_ip: SourceIp = None
    ) -> AcceptedInvitation:
        """Accept with a new password.

        Raises ``UserError`` for an unacceptable password (the invitation is
        untouched), ``InvitationMismatch`` if the user signs in only through
        single sign-on (untouched, #154), and ``AuthenticationRefused`` for
        everything else, with the reason in the audit trail.
        """
        if not well_formed(token):
            await self._refuse("malformed", None, "password", source_ip)
        if not isinstance(password, str) or not (
            self._config.identity.password_min_length <= len(password) <= MAX_PASSWORD_LENGTH
        ):
            raise UserError(
                f"password must be between {self._config.identity.password_min_length}"
                f" and {MAX_PASSWORD_LENGTH} characters"
            )
        password_hash = await self._hasher.hash(password)

        def check(invitee: _Invitee) -> str | None:
            if invitee.sign_in_method != SignInMethod.PASSWORD_AND_SSO:
                return "method_mismatch"
            return None

        async def complete(conn: AsyncConnection[Any], invitee: _Invitee) -> None:
            await conn.execute(
                sql.SQL("UPDATE {} SET password_hash = %s WHERE id = %s").format(_USERS),
                (password_hash, invitee.id),
            )

        return await self._accept(token, "password", check, complete, source_ip, {})

    async def accept_with_sso(
        self,
        token: object,
        verified: VerifiedIdentity,
        *,
        pin: SubjectPin,
        source_ip: SourceIp = None,
    ) -> AcceptedInvitation:
        """Accept with an identity the caller has already verified with the provider.

        ``verified.email`` must be the invited address (ignoring case), or
        ``InvitationMismatch`` is raised and the invitation stays usable.
        ``pin(conn, user_id, issuer, subject)`` runs inside the acceptance
        transaction to pin the subject; if it raises, nothing is accepted.
        No password is set. Every other refusal is ``AuthenticationRefused``.
        """

        def check(invitee: _Invitee) -> str | None:
            if verified.email.lower() != invitee.email.lower():
                return "identity_mismatch"
            return None

        async def complete(conn: AsyncConnection[Any], invitee: _Invitee) -> None:
            await pin(conn, invitee.id, verified.issuer, verified.subject)

        return await self._accept(
            token, "sso", check, complete, source_ip, {"issuer": verified.issuer}
        )

    async def _accept(
        self,
        token: object,
        method: Method,
        check: MethodCheck,
        complete: Complete,
        source_ip: SourceIp,
        details: dict[str, Any],
    ) -> AcceptedInvitation:
        """The one acceptance path: status, method and single use, decided under locks."""
        if not well_formed(token):
            await self._refuse("malformed", None, method, source_ip)
        reason: str | None = None
        mismatch: str | None = None
        invitee: _Invitee | None = None
        roles: tuple[str, ...] = ()
        try:
            async with self._db.transaction() as tx:
                user_id = await self._tokens.owner(tx, token, Purpose.INVITATION)
                # The user first, then the token: the same order a revocation's
                # delete (user, then its tokens by cascade) takes its locks in.
                invitee = None if user_id is None else await self._lock_invitee(tx, user_id)
                if invitee is None:
                    reason = "unknown_token"
                    raise _Abort
                if await self._tokens.lock_live(tx, token, Purpose.INVITATION) is None:
                    reason = "token_not_live"
                    raise _Abort
                mismatch = check(invitee)
                if mismatch is not None:
                    raise _Abort  # decided before the consume: the invitation stays usable
                if await self._tokens.consume(tx, token, Purpose.INVITATION) is None:
                    reason = "token_not_live"
                    raise _Abort
                if invitee.status != UserStatus.INVITED:
                    # A status refusal uses the invitation up, and says so in the trail.
                    reason = f"user_{invitee.status}"
                    await self._audit_failure(
                        "warden.identity.invitation.accepted",
                        None,
                        invitee.id,
                        source_ip,
                        reason,
                        conn=tx,
                        method=method,
                    )
                else:
                    await complete(tx, invitee)
                    if not await self._activate(tx, invitee.id):
                        reason = "concurrent_change"
                        raise _Abort
                    roles = await self._apply_grants(tx, invitee.id)
                    await self._tokens.revoke_live(tx, invitee.id, Purpose.INVITATION)
                    await self._audit_success(
                        tx,
                        "warden.identity.invitation.accepted",
                        str(invitee.id),
                        invitee.id,
                        source_ip,
                        method=method,
                        roles=list(roles),
                        **details,
                    )
        except _Abort:
            pass
        user = None if invitee is None else invitee.id
        if mismatch is not None:
            await self._audit_failure(
                "warden.identity.invitation.accepted",
                None,
                user,
                source_ip,
                mismatch,
                method=method,
            )
            if mismatch == "method_mismatch":
                raise InvitationMismatch("this invitation must be accepted through single sign-on")
            raise InvitationMismatch("the identity does not match the invitation")
        if reason is not None:
            if reason.startswith("user_"):
                raise AuthenticationRefused(reason)  # already audited with the consume
            await self._refuse(reason, user, method, source_ip)
        if invitee is None:
            raise RuntimeError("acceptance finished without an invitee")
        return AcceptedInvitation(invitee.id, invitee.email, method, roles)

    # Internals

    def _require_mail(self) -> None:
        if not self._mailer.configured:
            raise MailError("no mail sender is configured; pass mail_sender to Identity")

    def _check_grants(self, grants: Sequence[StagedGrant]) -> tuple[StagedGrant, ...]:
        registry = self._roles.registry
        now = datetime.now(UTC)
        staged: dict[str, StagedGrant] = {}
        for grant in grants:
            if grant.role not in registry:
                raise RoleError("an invitation grants a role that is not defined")
            if grant.expires_at is not None:
                if registry.role(grant.role).administrator:
                    raise RoleError(f"administrator role {grant.role} cannot carry an expiry")
                if grant.expires_at.tzinfo is None or grant.expires_at <= now:
                    raise RoleError("a staged grant's expiry must be a future, zoned time")
            staged[grant.role] = grant
        return tuple(staged[name] for name in sorted(staged))

    async def _insert_invitee(
        self,
        tx: AsyncConnection[Any],
        email: str,
        display_name: str | None,
        sign_in_method: SignInMethod,
    ) -> User:
        try:
            async with tx.transaction():
                cur = await tx.execute(
                    sql.SQL(
                        "INSERT INTO {} (email, display_name, status, sign_in_method)"
                        " VALUES (%s, %s, %s, %s) RETURNING id"
                    ).format(_USERS),
                    (email, display_name, UserStatus.INVITED.value, sign_in_method.value),
                )
                row = await cur.fetchone()
        except psycopg.errors.UniqueViolation:
            raise InvitationError("a user with that email address already exists") from None
        user = None if row is None else await self._users.get(row[0], conn=tx)
        if user is None:
            raise InvitationError("the invited user was not recorded")
        return user

    async def _stage(
        self,
        tx: AsyncConnection[Any],
        user_id: uuid.UUID,
        grants: Sequence[StagedGrant],
        actor: str | None,
    ) -> None:
        for grant in grants:
            await tx.execute(
                sql.SQL(
                    "INSERT INTO {} (user_id, role, expires_at, staged_by) VALUES (%s, %s, %s, %s)"
                ).format(_GRANTS),
                (user_id, grant.role, grant.expires_at, actor),
            )

    async def _staged(
        self, tx: AsyncConnection[Any], user_id: uuid.UUID
    ) -> tuple[StagedGrant, ...]:
        cur = await tx.execute(
            sql.SQL("SELECT role, expires_at FROM {} WHERE user_id = %s ORDER BY role").format(
                _GRANTS
            ),
            (user_id,),
        )
        return tuple(StagedGrant(role, expires_at) for role, expires_at in await cur.fetchall())

    async def _mail(self, user: User, token: str, expires_at: datetime) -> None:
        http = self._config.http
        await self._mailer.send(
            MailKind.INVITATION,
            email=user.email,
            display_name=user.display_name,
            link=http.render_link(http.accept_invitation_link, token=token),
            expires_at=expires_at,
        )

    async def _lock_invitee(self, tx: AsyncConnection[Any], user_id: uuid.UUID) -> _Invitee | None:
        cur = await tx.execute(
            sql.SQL(
                "SELECT id, email, status, sign_in_method FROM {} WHERE id = %s FOR UPDATE"
            ).format(_USERS),
            (user_id,),
        )
        row = await cur.fetchone()
        return None if row is None else _Invitee(*row)

    async def _activate(self, tx: AsyncConnection[Any], user_id: uuid.UUID) -> bool:
        cur = await tx.execute(
            sql.SQL(
                "UPDATE {} SET status = %s, updated_at = now() WHERE id = %s AND status = %s"
                " RETURNING 1"
            ).format(_USERS),
            (UserStatus.ACTIVE.value, user_id, UserStatus.INVITED.value),
        )
        return await cur.fetchone() is not None

    async def _apply_grants(self, tx: AsyncConnection[Any], user_id: uuid.UUID) -> tuple[str, ...]:
        cur = await tx.execute(
            sql.SQL(
                "DELETE FROM {} WHERE user_id = %s RETURNING role, expires_at, staged_by"
            ).format(_GRANTS),
            (user_id,),
        )
        applied: list[str] = []
        for role, expires_at, staged_by in sorted(await cur.fetchall()):
            if role not in self._roles.registry:
                continue  # the product no longer defines it; it would grant nothing
            await self._roles.assign(user_id, role, actor=staged_by, expires_at=expires_at, conn=tx)
            applied.append(role)
        return tuple(applied)

    async def _audit_success(
        self,
        conn: AsyncConnection[Any],
        action: str,
        actor: str | None,
        user_id: uuid.UUID,
        source_ip: SourceIp,
        **details: Any,
    ) -> None:
        await record_audit(
            AuditEvent(
                action=action,
                outcome="success",
                actor=actor,
                resource_type="user",
                resource_id=str(user_id),
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
        conn: AsyncConnection[Any] | None = None,
        **details: Any,
    ) -> None:
        await record_audit(
            AuditEvent(
                action=action,
                outcome="failure",
                actor=actor,
                resource_type="user" if user_id is not None else None,
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details={"reason": reason, **details},
            ),
            conn=conn,
        )

    async def _refuse(
        self, reason: str, user_id: uuid.UUID | None, method: Method, source_ip: SourceIp
    ) -> NoReturn:
        await self._audit_failure(
            "warden.identity.invitation.accepted",
            None,
            user_id,
            source_ip,
            reason,
            method=method,
        )
        raise AuthenticationRefused(reason)
