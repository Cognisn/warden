"""``Identity``: the object a product constructs once and mounts.

It ties together users, passwords, second factors, sessions, roles and the
session policy, and implements the sign-in flows the public routes expose.

Every refusal raises ``AuthenticationRefused`` after recording its reason in
the audit trail; the routes turn every refusal into the same response.
Where an outcome and its audit event must stand or fall together (a session
issued, a credential used up), both are written in one transaction.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any, NoReturn
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI
from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, get_recorder, record_audit
from warden.config import WardenConfig
from warden.db import Database, schema, table
from warden.identity import apikeys, invitations, prune, reset
from warden.identity.actions import register_actions
from warden.identity.crypto import SecretBox, SecretStore
from warden.identity.dependencies import APP_STATE_KEY, Principal, ResourceScopeHook
from warden.identity.errors import AuthenticationRefused, MfaError
from warden.identity.http import SourceIp
from warden.identity.mail import Mailer, MailError, MailKind, MailSender
from warden.identity.mfa import Challenge, ChallengePurpose, Enrolment, Mfa
from warden.identity.passwords import MAX_PASSWORD_LENGTH, PasswordHasher
from warden.identity.policy import PolicyStore, SessionPolicy
from warden.identity.roles import PermissionRegistry, Roles
from warden.identity.single_use import SingleUseTokens
from warden.identity.sso.service import SingleSignOn
from warden.identity.throttle import SignInThrottle
from warden.identity.tokens import NewSession, Sessions, TokenPair
from warden.identity.users import SignInMethod, UserError, Users, UserStatus, is_email
from warden.keys import KeyStore

__all__ = ["ChallengeIssued", "Identity", "SignInResult"]

logger = logging.getLogger(__name__)

_USERS = table(schema.USERS)
# Longest identifier looked up; nothing longer can be an email address.
_MAX_IDENTIFIER = 320


@dataclass(frozen=True, slots=True)
class ChallengeIssued:
    """The password was right; a second factor (or enrolment) is needed next."""

    token: str
    purpose: ChallengePurpose
    expires_in: int


@dataclass(frozen=True, slots=True)
class SignInResult:
    """Exactly one of ``tokens`` and ``challenge`` is set."""

    tokens: TokenPair | None = None
    challenge: ChallengeIssued | None = None


@dataclass(frozen=True, slots=True)
class _Account:
    id: uuid.UUID
    email: str
    status: str
    sign_in_method: str
    password_hash: str | None


class Identity:
    """warden's identity subsystem for one deployment."""

    def __init__(
        self,
        config: WardenConfig,
        db: Database,
        keys: KeyStore,
        permissions: PermissionRegistry,
        *,
        secrets: SecretStore,
        hasher: PasswordHasher | None = None,
        resource_scope: ResourceScopeHook | None = None,
        policy_max_age: float | None = None,
        sign_in_attempt_limit: int | None = None,
        sign_in_window_seconds: int | None = None,
        clock: Callable[[], float] = time.time,
        mail_sender: MailSender | None = None,
    ) -> None:
        """``secrets`` is konfig's secrets store. It must hold the TOTP encryption
        key (named by ``identity.totp_key_secret``) or construction fails.

        ``mail_sender`` is the product's ``MailSender``; invitations and
        password resets need one.

        ``policy_max_age``, ``sign_in_attempt_limit`` and ``sign_in_window_seconds``
        override ``identity.policy_cache_seconds``, ``identity.sign_in_attempt_limit``
        and ``identity.sign_in_window_seconds``; normally leave them unset.
        """
        settings = config.identity
        box = SecretBox.from_secrets(
            secrets,
            current_name=settings.totp_key_secret,
            previous_name=settings.totp_previous_key_secret,
        )
        register_actions(get_recorder().registry)
        self.config = config
        self.db = db
        self.keys = keys
        self.resource_scope = resource_scope
        self.passwords = hasher or PasswordHasher()
        self.roles = Roles(db, permissions)
        self.users = Users(
            db,
            self.passwords,
            self.roles,
            password_min_length=config.identity.password_min_length,
        )
        self.policy = PolicyStore(
            db,
            SessionPolicy.from_config(settings),
            max_age=settings.policy_cache_seconds if policy_max_age is None else policy_max_age,
        )
        issuer = config.http.public_base_url
        self.mfa = Mfa(
            db,
            issuer=settings.totp_issuer or urlsplit(issuer).hostname or issuer,
            box=box,
            clock=clock,
            challenge_ttl_seconds=settings.mfa_challenge_ttl_seconds,
            max_failures=settings.mfa_max_failures,
            recovery_code_count=settings.recovery_code_count,
        )
        self.throttle = SignInThrottle(
            db,
            limit=settings.sign_in_attempt_limit
            if sign_in_attempt_limit is None
            else sign_in_attempt_limit,
            window_seconds=settings.sign_in_window_seconds
            if sign_in_window_seconds is None
            else sign_in_window_seconds,
        )
        self.sessions = Sessions(db, keys, self.policy, issuer=issuer, clock=clock)
        # Single sign-on (warden.identity.sso). Built even while disabled, since an
        # administrator may enable it at run time.
        self.sso = SingleSignOn(
            config,
            db,
            self.sessions,
            self.policy,
            secrets,
            settings_max_age=settings.policy_cache_seconds,
        )
        self._init_lifecycle(mail_sender)

    def _init_lifecycle(self, mail_sender: MailSender | None) -> None:
        """Identity lifecycle: mail, single-use tokens, invitations, password reset, API keys."""
        for module in (invitations, reset, apikeys):
            module.register_actions(get_recorder().registry)
        self.api_keys = apikeys.ApiKeys(self.config.identity, self.db, self.roles)
        self.mailer = Mailer(self.config.mail, mail_sender)
        self.single_use = SingleUseTokens(self.db)
        self.invitations = invitations.Invitations(
            self.config,
            self.db,
            self.users,
            self.roles,
            self.single_use,
            self.mailer,
            self.passwords,
        )
        self.resets = reset.PasswordResets(
            self.config, self.db, self.single_use, self.mailer, self.passwords, self.sessions
        )
        self.pruner = prune.Pruner(self.db, self.single_use, self.throttle)

    async def prune(self) -> prune.PruneReport:
        """Delete expired refresh tokens, single-use tokens, MFA challenges and throttle windows."""
        return await self.pruner.prune()

    def pruning(
        self, *, every_seconds: float = 3600
    ) -> contextlib.AbstractAsyncContextManager[None]:
        """Run ``prune`` every ``every_seconds`` for a block, such as the product's lifespan."""
        prune.check_interval(every_seconds)
        return prune.scheduled(lambda: self.prune(), every_seconds)

    async def _notify_enrolled(self, user_id: uuid.UUID) -> None:
        """Mail the MFA-enrolled notice, after the enrolment committed.

        Best effort: without a sender nothing is sent, and a failed delivery
        is logged, never allowed to undo or fail the enrolment.
        """
        if not self.mailer.configured:
            return
        async with self.db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT u.email, u.display_name, t.confirmed_at FROM {} u"
                    " JOIN {} t ON t.user_id = u.id WHERE u.id = %s"
                ).format(_USERS, table(schema.TOTP_CREDENTIALS)),
                (user_id,),
            )
            row = await cur.fetchone()
        if row is None:
            return
        try:
            await self.mailer.send(
                MailKind.MFA_ENROLLED, email=row[0], display_name=row[1], enrolled_at=row[2]
            )
        except MailError as exc:
            logger.warning(
                "MFA-enrolled notice for user %s not sent (%s)", user_id, type(exc).__name__
            )

    def lifecycle_router(self) -> APIRouter:
        """Invitation acceptance and password reset; mount under ``config.http.auth_prefix``."""
        from warden.identity.routers.lifecycle import build_lifecycle_router

        return build_lifecycle_router(self)

    def admin_router(
        self,
        *,
        permission: str,
        roles: str | None = None,
        invitations: str | None = None,
        api_keys: str | None = None,
    ) -> APIRouter:
        """Administration routes; mount under ``config.http.admin_prefix``.

        ``permission`` guards the user routes, and the role, invitation and
        API key routes unless they are given their own permission.
        """
        from warden.identity.routers.admin import build_admin_router

        return build_admin_router(
            self, users=permission, roles=roles, invitations=invitations, api_keys=api_keys
        )

    @property
    def permissions(self) -> PermissionRegistry:
        return self.roles.registry

    def install(self, app: FastAPI) -> None:
        """Make this Identity the one ``require_user`` and ``require_permission`` use."""
        setattr(app.state, APP_STATE_KEY, self)

    def auth_router(self) -> APIRouter:
        """The public sign-in routes; mount under ``config.http.auth_prefix``."""
        from warden.identity.routers.auth import build_auth_router

        return build_auth_router(self)

    def sso_router(self) -> APIRouter:
        """The single sign-on routes; mount under ``config.http.auth_prefix`` too."""
        from warden.identity.routers.sso import build_sso_router

        return build_sso_router(self)

    def sso_settings_router(self, *, authorise: Callable[..., Any]) -> APIRouter:
        """Single sign-on administration; mount under ``config.http.admin_prefix``.

        ``authorise`` is a FastAPI dependency that refuses the caller or returns
        their actor id (for example a ``require_permission`` the product chose).
        """
        from warden.identity.routers.sso_settings import build_sso_settings_router

        return build_sso_settings_router(self, authorise=authorise)

    @contextlib.asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        """Run identity's background work (the session-policy listener) for a block.

        Wrap the product's FastAPI lifespan in it::

            @asynccontextmanager
            async def lifespan(app):
                async with identity.running():
                    yield
        """
        ready = asyncio.Event()
        task = asyncio.create_task(self.policy.listen(ready=ready))
        try:
            try:
                await asyncio.wait_for(ready.wait(), timeout=10)
            except TimeoutError:
                logger.warning("session policy listener not ready; it keeps retrying")
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await self.sso.aclose()

    async def prune_sign_in_attempts(self) -> int:
        """Delete sign-in throttle records whose window has ended."""
        return await self.throttle.prune()

    # Sign-in

    async def sign_in(
        self, email: object, password: object, *, source_ip: SourceIp = None
    ) -> SignInResult:
        """Check a password. Every failure costs one password verification.

        Unknown users, wrong passwords, SSO-only users and inactive users all
        take the same path and get the same refusal; only the audit trail
        records which it was.
        """
        if not isinstance(email, str) or not isinstance(password, str):
            await self._refuse_sign_in("malformed", None, None, source_ip)
        if not await self.throttle.reserve(email, source_ip):
            await self._refuse_sign_in("throttled", None, email, source_ip)
        account = await self._account(email)
        if account is None or account.password_hash is None:
            await self.passwords.dummy_verify(password)
            verification = None
        else:
            verification = await self.passwords.verify(account.password_hash, password)
        if account is None:
            await self._refuse_sign_in("unknown_user", None, email, source_ip)
        if verification is None or not verification.ok:
            await self._refuse_sign_in("wrong_password", account.id, email, source_ip)
        if account.sign_in_method != SignInMethod.PASSWORD_AND_SSO:
            await self._refuse_sign_in("sso_only", account.id, email, source_ip)
        if account.status != UserStatus.ACTIVE:
            await self._refuse_sign_in("user_inactive", account.id, email, source_ip)

        new_hash = None
        if verification.needs_rehash:
            new_hash = await self.passwords.hash(password)
        policy = await self.policy.current()
        challenge: ChallengeIssued | None = None
        new: NewSession | None = None
        async with self.db.transaction() as tx:
            rehashed = False
            if new_hash is not None:
                cur = await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET password_hash = %s, updated_at = now()"
                        " WHERE id = %s AND password_hash = %s"
                    ).format(_USERS),
                    (new_hash, account.id, account.password_hash),
                )
                rehashed = cur.rowcount == 1
            purpose: ChallengePurpose | None = None
            if await self.mfa.has_confirmed_totp(account.id, conn=tx):
                purpose = "verify"
            elif policy.require_mfa:
                purpose = "enrol"
            details: dict[str, Any] = {"rehashed": True} if rehashed else {}
            if purpose is not None:
                token = await self.mfa.create_challenge(tx, account.id, purpose)
                challenge = ChallengeIssued(token, purpose, self.mfa.challenge_ttl_seconds)
                await self._audit(
                    tx,
                    "warden.identity.mfa.challenge",
                    account.id,
                    source_ip,
                    purpose=purpose,
                    **details,
                )
            else:
                new = await self.sessions.start(tx, account.id, ["pwd"], policy)
                await self.throttle.clear(tx, email, source_ip)
                await self._audit(
                    tx, "warden.identity.sign_in", account.id, source_ip, amr=["pwd"], **details
                )
        if challenge is not None:
            return SignInResult(challenge=challenge)
        if new is None:
            raise RuntimeError("sign-in produced neither a session nor a challenge")
        return SignInResult(tokens=await self.sessions.finish(new))

    async def verify_totp(
        self, challenge: object, code: object, *, source_ip: SourceIp = None
    ) -> TokenPair:
        """Complete a sign-in with a TOTP code. A code is accepted once per step."""
        return await self._second_factor(challenge, code, "totp", source_ip)

    async def use_recovery_code(
        self, challenge: object, code: object, *, source_ip: SourceIp = None
    ) -> TokenPair:
        """Complete a sign-in with a recovery code, using it up."""
        return await self._second_factor(challenge, code, "recovery_code", source_ip)

    async def _second_factor(
        self, token: object, code: object, method: str, source_ip: SourceIp
    ) -> TokenPair:
        policy = await self.policy.current()
        reason: str | None = None
        opened: Challenge | None = None
        new: NewSession | None = None
        try:
            async with self.db.transaction() as tx:
                opened = await self.mfa.open_challenge(tx, token, "verify")
                if opened is None:
                    reason = "unknown_challenge"
                else:
                    reason = await self._account_refusal(tx, opened.user_id)
                if reason is None and opened is not None:
                    if method == "totp":
                        ok = await self.mfa.claim_totp(tx, opened.user_id, code)
                        amr = ["pwd", "otp"]
                    else:
                        ok = await self.mfa.consume_recovery_code(tx, opened.user_id, code)
                        amr = ["pwd", "recovery_code"]
                    if not ok:
                        reason = "wrong_code"
                    elif not await self.mfa.consume_challenge(tx, opened):
                        # Another request completed this challenge first: undo the
                        # claim, so a recovery code is not used up for nothing.
                        reason = "challenge_used"
                        raise _Rollback
                    else:
                        new = await self.sessions.start(tx, opened.user_id, amr, policy)
                        await self._clear_throttle(tx, opened.user_id, source_ip)
                        await self._audit(
                            tx, "warden.identity.sign_in", opened.user_id, source_ip, amr=amr
                        )
        except _Rollback:
            pass
        if reason is not None or new is None:
            if reason == "wrong_code" and opened is not None:
                await self.mfa.record_failure(opened)
            await self._refuse_second_factor(
                reason or "unknown_challenge", opened, method, source_ip
            )
        return await self.sessions.finish(new)

    # Enrolment

    async def begin_enrolment(
        self,
        *,
        challenge: object = None,
        principal: Principal | None = None,
        source_ip: SourceIp = None,
    ) -> Enrolment:
        """Start TOTP enrolment, for a signed-in user or under an enrolment challenge."""
        user_id = await self._enrolling_user(challenge, principal, source_ip)
        user = await self.users.get(user_id)
        if user is None:
            raise AuthenticationRefused("user_missing")
        try:
            return await self.mfa.begin_enrolment(user_id, account=user.email)
        except MfaError:
            if principal is not None:
                raise  # a signed-in user is told; the routes answer 409
            raise AuthenticationRefused("already_enrolled") from None

    async def confirm_enrolment(
        self,
        code: object,
        *,
        challenge: object = None,
        principal: Principal | None = None,
        source_ip: SourceIp = None,
    ) -> tuple[list[str], TokenPair | None]:
        """Confirm enrolment. Under a challenge, also completes the sign-in."""
        if principal is not None:
            codes = await self.mfa.confirm_enrolment(principal.user_id, code)
            if codes is None:
                # Signed in: say the code was wrong, not that authentication failed.
                await self._audit_second_factor_failure(
                    "wrong_code", str(principal.user_id), "enrolment", source_ip
                )
                raise MfaError("code not accepted")
            await self._notify_enrolled(principal.user_id)
            return codes, None
        policy = await self.policy.current()
        reason: str | None = None
        opened: Challenge | None = None
        new: NewSession | None = None
        codes = None
        try:
            async with self.db.transaction() as tx:
                opened = await self.mfa.open_challenge(tx, challenge, "enrol")
                if opened is None:
                    reason = "unknown_challenge"
                else:
                    reason = await self._account_refusal(tx, opened.user_id)
                if reason is None and opened is not None:
                    codes = await self.mfa.confirm_enrolment(opened.user_id, code, conn=tx)
                    if codes is None:
                        reason = "wrong_code"
                    elif not await self.mfa.consume_challenge(tx, opened):
                        reason = "challenge_used"
                        raise _Rollback
                    else:
                        amr = ["pwd", "otp"]
                        new = await self.sessions.start(tx, opened.user_id, amr, policy)
                        await self._clear_throttle(tx, opened.user_id, source_ip)
                        await self._audit(
                            tx, "warden.identity.sign_in", opened.user_id, source_ip, amr=amr
                        )
        except _Rollback:
            pass
        if reason is not None or new is None or codes is None:
            if reason == "wrong_code" and opened is not None:
                await self.mfa.record_failure(opened)
            await self._refuse_second_factor(
                reason or "unknown_challenge", opened, "enrolment", source_ip
            )
        await self._notify_enrolled(new.user_id)
        return codes, await self.sessions.finish(new)

    async def reset_totp(
        self, user_id: uuid.UUID, *, actor: str, source_ip: SourceIp = None
    ) -> bool:
        """Remove a user's TOTP enrolment and recovery codes, and end their sessions.

        For an administrator helping a user who has lost both factors: the
        next password sign-in enrols again where the policy requires a second
        factor. One transaction deletes the credential and every recovery
        code, ends every session of the user (as a password reset does) and
        records ``warden.identity.mfa.reset``. A user with nothing enrolled is
        not an error; the reset is still audited. Returns whether a credential
        was removed, and raises ``UserError`` if there is no such user.
        """
        async with self.db.transaction() as tx:
            # KEY SHARE, not UPDATE: an enrolment's recovery codes and a new
            # session take that lock on the user too, through their foreign keys.
            cur = await tx.execute(
                sql.SQL("SELECT 1 FROM {} WHERE id = %s FOR KEY SHARE").format(_USERS), (user_id,)
            )
            if await cur.fetchone() is None:
                raise UserError(f"user {user_id} does not exist")
            removed, codes = await self.mfa.remove(tx, user_id)
            ended = await self.sessions.revoke_all(user_id, reason="totp_reset", conn=tx)
            await record_audit(
                AuditEvent(
                    action="warden.identity.mfa.reset",
                    outcome="success",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    source_ip=source_ip,
                    details={
                        "totp_removed": removed,
                        "recovery_codes_removed": codes,
                        "sessions_ended": ended,
                    },
                ),
                conn=tx,
            )
        return removed

    async def _enrolling_user(
        self, challenge: object, principal: Principal | None, source_ip: SourceIp
    ) -> uuid.UUID:
        if principal is not None:
            return principal.user_id
        async with self.db.transaction() as tx:
            opened = await self.mfa.open_challenge(tx, challenge, "enrol")
            reason = (
                "unknown_challenge"
                if opened is None
                else await self._account_refusal(tx, opened.user_id)
            )
        if reason is not None or opened is None:
            await self._refuse_second_factor(
                reason or "unknown_challenge", opened, "enrolment", source_ip
            )
        return opened.user_id

    # Sessions

    async def refresh(self, refresh_token: object, *, source_ip: SourceIp = None) -> TokenPair:
        return await self.sessions.rotate(refresh_token, source_ip=source_ip)

    async def authenticate(self, access_token: object) -> Principal:
        """The principal behind a live access token, or ``AuthenticationRefused``.

        Checks the signature with a live key, then that the session is live
        and the user active, then loads the user's current roles.
        """
        claims = await self.sessions.verify_access_token(access_token)
        if claims is None:
            raise AuthenticationRefused("invalid_token")
        async with self.db.connection() as conn:
            email = await self.sessions.live_email(conn, claims.user_id, claims.session_id)
            if email is None:
                raise AuthenticationRefused("session_not_live")
            roles = await self.roles.roles_of(claims.user_id, conn=conn)
        return Principal(
            user_id=claims.user_id,
            session_id=claims.session_id,
            email=email,
            roles=frozenset(roles),
            permissions=self.permissions.permissions_for(roles),
            amr=claims.amr,
        )

    async def sign_out(self, principal: Principal, *, source_ip: SourceIp = None) -> None:
        async with self.db.transaction() as tx:
            await self.sessions.revoke(principal.session_id, reason="sign_out", conn=tx)
            await self._audit(
                tx,
                "warden.identity.sign_out",
                principal.user_id,
                source_ip,
                resource=("session", str(principal.session_id)),
            )

    async def change_password(
        self,
        principal: Principal,
        current: object,
        new_password: object,
        *,
        source_ip: SourceIp = None,
    ) -> str | None:
        """Change the signed-in user's password; None on success, else a refusal reason.

        Ends the user's other sessions.
        """
        account = await self._account_by_id(principal.user_id)
        reason: str | None = None
        if (
            account is None
            or not isinstance(current, str)
            or not isinstance(new_password, str)
            or account.sign_in_method != SignInMethod.PASSWORD_AND_SSO
            or account.password_hash is None
        ):
            if isinstance(current, str):
                await self.passwords.dummy_verify(current)
            reason = "not_permitted"
        elif not (await self.passwords.verify(account.password_hash, current)).ok:
            reason = "wrong_password"
        elif not (
            self.config.identity.password_min_length <= len(new_password) <= MAX_PASSWORD_LENGTH
        ):
            reason = "weak_password"
        if reason is not None:
            await record_audit(
                AuditEvent(
                    action="warden.identity.password.changed",
                    outcome="failure",
                    actor=str(principal.user_id),
                    resource_type="user",
                    resource_id=str(principal.user_id),
                    source_ip=source_ip,
                    details={"reason": reason},
                )
            )
            return reason
        if account is None or not isinstance(new_password, str):  # narrowed above
            return "not_permitted"
        new_hash = await self.passwords.hash(new_password)
        async with self.db.transaction() as tx:
            await tx.execute(
                sql.SQL(
                    "UPDATE {} SET password_hash = %s, updated_at = now() WHERE id = %s"
                ).format(_USERS),
                (new_hash, account.id),
            )
            ended = await self.sessions.revoke_all(
                account.id, reason="password_changed", keep=principal.session_id, conn=tx
            )
            await self._audit(
                tx,
                "warden.identity.password.changed",
                account.id,
                source_ip,
                other_sessions_ended=ended,
            )
        return None

    async def permissions_of(self, user_id: uuid.UUID) -> frozenset[str]:
        return self.permissions.permissions_for(await self.roles.roles_of(user_id))

    # Internals

    async def _account(self, email: str) -> _Account | None:
        if len(email) > _MAX_IDENTIFIER:
            return None
        async with self.db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT id, email, status, sign_in_method, password_hash FROM {}"
                    " WHERE lower(email) = lower(%s)"
                ).format(_USERS),
                (email,),
            )
            row = await cur.fetchone()
        return None if row is None else _Account(*row)

    async def _account_by_id(self, user_id: uuid.UUID) -> _Account | None:
        async with self.db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT id, email, status, sign_in_method, password_hash FROM {} WHERE id = %s"
                ).format(_USERS),
                (user_id,),
            )
            row = await cur.fetchone()
        return None if row is None else _Account(*row)

    async def _account_refusal(self, conn: AsyncConnection[Any], user_id: uuid.UUID) -> str | None:
        """Why this user may not complete a password sign-in now, or None."""
        cur = await conn.execute(
            sql.SQL("SELECT status, sign_in_method FROM {} WHERE id = %s").format(_USERS),
            (user_id,),
        )
        row = await cur.fetchone()
        if row is None or row[0] != UserStatus.ACTIVE:
            return "user_inactive"
        if row[1] != SignInMethod.PASSWORD_AND_SSO:
            return "sso_only"
        return None

    async def _audit(
        self,
        conn: AsyncConnection[Any],
        action: str,
        user_id: uuid.UUID,
        source_ip: SourceIp,
        *,
        resource: tuple[str, str] | None = None,
        **details: Any,
    ) -> None:
        resource_type, resource_id = resource or ("user", str(user_id))
        await record_audit(
            AuditEvent(
                action=action,
                outcome="success",
                actor=str(user_id),
                resource_type=resource_type,
                resource_id=resource_id,
                source_ip=source_ip,
                details=details,
            ),
            conn=conn,
        )

    async def _refuse_sign_in(
        self,
        reason: str,
        user_id: uuid.UUID | None,
        identifier: str | None,
        source_ip: SourceIp,
    ) -> NoReturn:
        details: dict[str, Any] = {"reason": reason}
        if identifier is not None:
            # Only an email-shaped identifier is recorded: anything else may be a
            # password typed into the wrong field.
            if is_email(identifier):
                details["identifier"] = identifier
            else:
                details["identifier_recorded"] = False
        await record_audit(
            AuditEvent(
                action="warden.identity.sign_in",
                outcome="failure",
                actor=None if user_id is None else str(user_id),
                resource_type="user" if user_id is not None else None,
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details=details,
            )
        )
        raise AuthenticationRefused(reason)

    async def _refuse_second_factor(
        self, reason: str, challenge: Challenge | None, method: str, source_ip: SourceIp
    ) -> NoReturn:
        user = None if challenge is None else str(challenge.user_id)
        await self._audit_second_factor_failure(reason, user, method, source_ip)
        raise AuthenticationRefused(reason)

    async def _audit_second_factor_failure(
        self, reason: str, user: str | None, method: str, source_ip: SourceIp
    ) -> None:
        await record_audit(
            AuditEvent(
                action="warden.identity.mfa.verify",
                outcome="failure",
                actor=user,
                resource_type="user" if user else None,
                resource_id=user,
                source_ip=source_ip,
                details={"reason": reason, "method": method},
            )
        )

    async def _clear_throttle(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, source_ip: SourceIp
    ) -> None:
        cur = await conn.execute(
            sql.SQL("SELECT email FROM {} WHERE id = %s").format(_USERS), (user_id,)
        )
        row = await cur.fetchone()
        if row is not None:
            await self.throttle.clear(conn, row[0], source_ip)


class _Rollback(Exception):
    """Abandons a transaction whose refusal must also undo earlier writes."""
