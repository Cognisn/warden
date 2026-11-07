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
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI
from fido2.utils import websafe_decode
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
from warden.identity.invitations import AcceptedInvitation
from warden.identity.mail import MailDeliveryError, Mailer, MailError, MailKind, MailSender
from warden.identity.mfa import (
    Challenge,
    ChallengePurpose,
    Enrolment,
    LastSecondFactorError,
    Mfa,
    SecondFactor,
    WebAuthnUnavailable,
)
from warden.identity.passwords import MAX_PASSWORD_LENGTH, PasswordHasher
from warden.identity.policy import PolicyStore, SessionPolicy
from warden.identity.roles import PermissionRegistry, Roles
from warden.identity.single_use import Purpose, SingleUseTokens, well_formed
from warden.identity.sso.service import SingleSignOn
from warden.identity.throttle import SignInThrottle
from warden.identity.tokens import NewSession, Sessions, TokenPair
from warden.identity.users import SignInMethod, UserError, Users, UserStatus, is_email
from warden.identity.webauthn import (
    WebAuthn,
    WebAuthnCredential,
    WebAuthnCredentials,
    WebAuthnError,
    WebAuthnOptions,
    WebAuthnPurpose,
    WebAuthnRefusal,
)
from warden.keys import KeyStore

__all__ = [
    "ChallengeIssued",
    "Identity",
    "PasskeyInvitationAccepted",
    "PasskeyLinkNotConfigured",
    "PasskeyLinkRefused",
    "SignInResult",
    "WebAuthnEnrolled",
]

logger = logging.getLogger(__name__)

_USERS = table(schema.USERS)
# Longest identifier looked up; nothing longer can be an email address.
_MAX_IDENTIFIER = 320
# RFC 8176: a password and a hardware-bound key (ruling P7).
_KEY_AMR = ["pwd", "hwk"]
# RFC 8176: a hardware-bound key that verified its user, alone (ruling P7).
_PASSKEY_AMR = ["hwk", "mfa"]
# The longest credential id a response may name (WebAuthn caps it at 1023 bytes).
_MAX_CREDENTIAL_ID = 1023
# Refusals that say nothing about the second factor offered, so cost no attempt.
_NOT_AN_ATTEMPT = frozenset({"unknown_challenge", "user_inactive", "sso_only", "challenge_used"})


@dataclass(frozen=True, slots=True)
class ChallengeIssued:
    """The password was right; a second factor (or enrolment) is needed next."""

    token: str
    purpose: ChallengePurpose
    expires_in: int
    methods: tuple[SecondFactor, ...] = ()
    """For ``verify``: the kinds of second factor the user holds (``totp``, ``webauthn``)."""


@dataclass(frozen=True, slots=True)
class SignInResult:
    """Exactly one of ``tokens`` and ``challenge`` is set."""

    tokens: TokenPair | None = None
    challenge: ChallengeIssued | None = None


@dataclass(frozen=True, slots=True)
class WebAuthnEnrolled:
    """A security key or passkey registered as a second factor."""

    credential: WebAuthnCredential
    recovery_codes: list[str]
    """Fresh codes when it is the user's first second factor; otherwise none."""
    tokens: TokenPair | None = None
    """The new session, when registered under an enrolment challenge."""


@dataclass(frozen=True, slots=True)
class PasskeyInvitationAccepted:
    """A ``passkey_only`` invitation accepted by registering a passkey; not signed in."""

    invitation: AcceptedInvitation
    credential: WebAuthnCredential
    recovery_codes: list[str]


class PasskeyLinkRefused(Exception):
    """No registration link for this user: ``sso_only``, or not active (ruling P8).

    ``reason`` is the audited reason. Messages carry identifiers only.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"passkey registration link refused: {reason}")
        self.reason = reason


class PasskeyLinkNotConfigured(MailError):
    """``http.passkey_registration_link`` is not set, so there is nothing to mail."""


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
        # Passkeys and security keys: built only where a relying party id is
        # known, so a deployment on an IP address without WebAuthn settings
        # boots as before (wave 9 decision D17). The credential store needs no
        # relying party, so a user can always list and remove their keys.
        self.webauthn: WebAuthn | None = (
            WebAuthn(config, db) if config.webauthn.relying_party_id(config.http) else None
        )
        self.webauthn_credentials = WebAuthnCredentials(db)
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
        self.pruner = prune.Pruner(self.db, self.single_use, self.throttle, webauthn=self.webauthn)

    async def prune(self) -> prune.PruneReport:
        """Delete expired tokens, MFA and WebAuthn challenges, and ended throttle windows."""
        return await self.pruner.prune()

    def pruning(
        self, *, every_seconds: float = 3600
    ) -> contextlib.AbstractAsyncContextManager[None]:
        """Run ``prune`` every ``every_seconds`` for a block, such as the product's lifespan."""
        prune.check_interval(every_seconds)
        return prune.scheduled(lambda: self.prune(), every_seconds)

    async def _notify_enrolled(
        self, user_id: uuid.UUID, *, key: WebAuthnCredential | None = None
    ) -> None:
        """Mail the MFA-enrolled notice, after the user's first second factor committed.

        Best effort: without a sender nothing is sent, and a failed delivery
        is logged, never allowed to undo or fail the enrolment. ``key`` is the
        security key or passkey that was the first factor; otherwise it was TOTP.
        """
        if not self.mailer.configured:
            return
        async with self.db.connection() as conn:
            if key is None:
                cur = await conn.execute(
                    sql.SQL(
                        "SELECT u.email, u.display_name, t.confirmed_at FROM {} u"
                        " JOIN {} t ON t.user_id = u.id WHERE u.id = %s"
                    ).format(_USERS, table(schema.TOTP_CREDENTIALS)),
                    (user_id,),
                )
            else:
                cur = await conn.execute(
                    sql.SQL(
                        "SELECT email, display_name, %s::timestamptz FROM {} WHERE id = %s"
                    ).format(_USERS),
                    (key.created_at, user_id),
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
            # A passkey_only user is refused as a wrong password is (ruling P5).
            reason = (
                "passkey_only"
                if account.sign_in_method == SignInMethod.PASSKEY_ONLY
                else "sso_only"
            )
            await self._refuse_sign_in(reason, account.id, email, source_ip)
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
            # Any confirmed second factor, TOTP or a key, is asked for (ruling P4).
            methods = await self.mfa.methods(account.id, conn=tx)
            if methods:
                purpose = "verify"
            elif policy.require_mfa:
                purpose = "enrol"
            details: dict[str, Any] = {"rehashed": True} if rehashed else {}
            if purpose is not None:
                token = await self.mfa.create_challenge(tx, account.id, purpose)
                challenge = ChallengeIssued(
                    token, purpose, self.mfa.challenge_ttl_seconds, tuple(methods)
                )
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

    # Passkey-only sign-in (rulings P5, P6 and P7)

    async def begin_passkey_sign_in(self, *, source_ip: SourceIp = None) -> WebAuthnOptions:
        """The options for signing in with a passkey alone.

        Discoverable only: no ``allowCredentials``, so the options are the
        same for every caller and say nothing about any account, and user
        verification is required. Usable with conditional mediation. Without
        a relying party the refusal is ``AuthenticationRefused``, audited.

        Throttled by source address on a budget of its own, checked before
        a challenge is issued: once spent, the refusal is
        ``AuthenticationRefused``, audited with reason ``options_throttled``.
        A passkey sign-in that issues a session clears it for its address.
        """
        if not await self.throttle.reserve_passkey_options(source_ip):
            await self._refuse_passkey("options_throttled", None, None, source_ip)
        if self.webauthn is None:
            await self._refuse_passkey("webauthn_unavailable", None, None, source_ip)
        return await self.webauthn.begin_authentication(None, require_user_verification=True)

    async def passkey_sign_in(self, credential: object, *, source_ip: SourceIp = None) -> TokenPair:
        """Sign in with a passkey alone: ``amr`` ``["hwk", "mfa"]``.

        That satisfies ``require_mfa`` with no second step. The user is the
        one holding the credential, found by the response's user handle and
        credential id together. Open to ``password_and_sso`` and
        ``passkey_only`` users, with a credential that is discoverable and
        was registered with user verification. Throttled by source address
        and, separately, by the credential id's hash. Every failure is
        ``AuthenticationRefused``, its reason recorded as a failed
        ``warden.identity.sign_in``.

        The ceremony is finished with no transaction of this method's open,
        as ``verify_webauthn`` does; the user's status and sign-in method are
        checked again in the transaction that issues the session.
        """
        raw_id = _credential_id(credential)
        if not await self.throttle.reserve_passkey(source_ip, raw_id or b""):
            await self._refuse_passkey("throttled", None, None, source_ip)
        if raw_id is None:
            await self._refuse_passkey("malformed", None, None, source_ip)
        if self.webauthn is None:
            await self._refuse_passkey("webauthn_unavailable", None, None, source_ip)
        policy = await self.policy.current()
        try:
            assertion = await self.webauthn.finish_authentication(None, credential)
        except WebAuthnError as exc:
            if exc.suspected_clone:
                await self._audit_clone(exc, source_ip)
            await self._refuse_passkey(exc.reason.value, exc.user_id, exc.credential_id, source_ip)
        user_id, key = assertion.user_id, assertion.credential
        new: NewSession | None = None
        async with self.db.transaction() as tx:
            reason = await self._passkey_refusal(tx, user_id)
            if reason is None:
                new = await self.sessions.start(tx, user_id, _PASSKEY_AMR, policy)
                await self.throttle.clear_passkey(tx, source_ip, raw_id)
                await self._audit(
                    tx,
                    "warden.identity.sign_in",
                    user_id,
                    source_ip,
                    amr=_PASSKEY_AMR,
                    credential_id=str(key.id),
                )
        if reason is not None or new is None:
            await self._refuse_passkey(reason or "inactive_user", user_id, key.id, source_ip)
        return await self.sessions.finish(new)

    async def _passkey_refusal(self, conn: AsyncConnection[Any], user_id: uuid.UUID) -> str | None:
        """Why this user may not sign in with a passkey now, or None."""
        cur = await conn.execute(
            sql.SQL("SELECT status, sign_in_method FROM {} WHERE id = %s").format(_USERS),
            (user_id,),
        )
        row = await cur.fetchone()
        if row is None or row[0] != UserStatus.ACTIVE:
            return "inactive_user"
        if row[1] == SignInMethod.SSO_ONLY:
            return "sso_only"
        return None

    async def _refuse_passkey(
        self,
        reason: str,
        user_id: uuid.UUID | None,
        credential_id: uuid.UUID | None,
        source_ip: SourceIp,
    ) -> NoReturn:
        """Audit a refused passkey sign-in, identifiers only, and refuse it."""
        details: dict[str, Any] = {"reason": reason, "method": "passkey"}
        if credential_id is not None:
            details["credential_id"] = str(credential_id)
        await record_audit(
            AuditEvent(
                action="warden.identity.sign_in",
                outcome="failure",
                actor=None if user_id is None else str(user_id),
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details=details,
            )
        )
        raise AuthenticationRefused(reason)

    # The administrator's passkey registration link (ruling P8)

    async def send_passkey_registration(
        self, user_id: uuid.UUID, *, actor: str | None, source_ip: SourceIp = None
    ) -> datetime:
        """Mail a user a single-use link for registering a passkey; when it expires.

        For a ``passkey_only`` user with no passkey, or one who lost every
        passkey (after ``reset_mfa``: reset, then link). Sending again
        revokes the live link. The link lasts ``identity.reset_ttl_seconds``.
        Raises ``UserError`` for no such user, ``PasskeyLinkRefused`` for an
        ``sso_only`` or inactive user, ``WebAuthnUnavailable`` without a
        relying party, ``PasskeyLinkNotConfigured`` without
        ``http.passkey_registration_link``, ``MailError`` without a sender
        and ``MailDeliveryError`` if the sender fails; in every case no link
        is left behind.
        """
        self._relying_party()
        http = self.config.http
        if http.passkey_registration_link is None:
            raise PasskeyLinkNotConfigured("http.passkey_registration_link is not configured")
        if not self.mailer.configured:
            raise MailError("no mail sender is configured; pass mail_sender to Identity")
        refused: str | None = None
        try:
            async with self.db.transaction() as tx:
                cur = await tx.execute(
                    sql.SQL(
                        "SELECT email, display_name, status, sign_in_method FROM {}"
                        " WHERE id = %s FOR UPDATE"
                    ).format(_USERS),
                    (user_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    raise UserError(f"user {user_id} does not exist")
                email, display_name, status, method = row
                refused = _link_refusal(status, method)
                if refused is not None:
                    raise PasskeyLinkRefused(refused)
                revoked = await self.single_use.revoke_live(
                    tx, user_id, Purpose.PASSKEY_REGISTRATION
                )
                issued = await self.single_use.issue(
                    tx,
                    user_id,
                    Purpose.PASSKEY_REGISTRATION,
                    ttl_seconds=self.config.identity.reset_ttl_seconds,
                    created_by=actor,
                )
                await self.mailer.send(
                    MailKind.PASSKEY_REGISTRATION,
                    email=email,
                    display_name=display_name,
                    link=http.render_link(http.passkey_registration_link, token=issued.token),
                    expires_at=issued.expires_at,
                )
                await record_audit(
                    AuditEvent(
                        action="warden.identity.passkey.link_sent",
                        outcome="success",
                        actor=actor,
                        resource_type="user",
                        resource_id=str(user_id),
                        source_ip=source_ip,
                        details={
                            "previous_links_revoked": revoked,
                            "expires_at": issued.expires_at.isoformat(),
                        },
                    ),
                    conn=tx,
                )
        except (PasskeyLinkRefused, MailDeliveryError) as exc:
            reason = exc.reason if isinstance(exc, PasskeyLinkRefused) else "delivery_failed"
            await record_audit(
                AuditEvent(
                    action="warden.identity.passkey.link_sent",
                    outcome="failure",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    source_ip=source_ip,
                    details={"reason": reason},
                )
            )
            raise
        return issued.expires_at

    async def begin_passkey_registration(
        self, token: object, *, source_ip: SourceIp = None
    ) -> WebAuthnOptions:
        """The options for registering a passkey with an administrator's link.

        Resident key and user verification required. Changes nothing but
        the ceremony's challenge: the link stays usable. Every refusal (a
        bad, used or expired link, a user who is no longer active or is now
        ``sso_only``) is ``AuthenticationRefused``, its reason audited;
        ``WebAuthnError`` (``limit_reached``) when the user holds as many
        credentials as allowed.
        """
        if not well_formed(token):
            await self._refuse_link("malformed", None, source_ip)
        if self.webauthn is None:
            await self._refuse_link("webauthn_unavailable", None, source_ip)
        reason: str | None = None
        user_id: uuid.UUID | None = None
        options: WebAuthnOptions | None = None
        async with self.db.transaction() as tx:
            user_id = await self.single_use.owner(tx, token, Purpose.PASSKEY_REGISTRATION)
            if user_id is None:
                reason = "unknown_token"
            elif await self.single_use.lock_live(tx, token, Purpose.PASSKEY_REGISTRATION) is None:
                reason = "token_not_live"
            else:
                reason = await self._link_user_refusal(tx, user_id, lock=False)
            if reason is None and user_id is not None:
                options = await self.webauthn.begin_registration(
                    user_id, WebAuthnPurpose.PASSKEY, conn=tx
                )
        if reason is not None or options is None:
            await self._refuse_link(reason or "unknown_token", user_id, source_ip)
        return options

    async def finish_passkey_registration(
        self,
        token: object,
        credential: object,
        *,
        nickname: object = None,
        source_ip: SourceIp = None,
    ) -> WebAuthnEnrolled:
        """Register a passkey with an administrator's link, using the link up. No session.

        In one transaction, under row locks on the user and then the link:
        the browser's answer is checked and the passkey stored, the link is
        used up by one guarded write (sending a link revokes the earlier
        one, so it is the only live one), and a user holding no recovery
        codes gets fresh ones (the
        shared rule of ruling P4). A link whose user is no longer active, or
        is now ``sso_only``, is refused and spent. An answer that is not a
        passkey raises ``WebAuthnError`` and leaves the link usable; every
        other refusal is ``AuthenticationRefused``. Reasons are audited.
        """
        if not well_formed(token):
            await self._refuse_link("malformed", None, source_ip)
        if nickname is not None and not isinstance(nickname, str):
            raise WebAuthnError(WebAuthnRefusal.NICKNAME)
        if self.webauthn is None:
            await self._refuse_link("webauthn_unavailable", None, source_ip)
        webauthn = self.webauthn
        reason: str | None = None
        user_id: uuid.UUID | None = None
        enrolled: WebAuthnEnrolled | None = None
        try:
            async with self.db.transaction() as tx:
                user_id = await self.single_use.owner(tx, token, Purpose.PASSKEY_REGISTRATION)
                # The user first, then the link, as every single-use token is taken.
                reason = (
                    "unknown_token"
                    if user_id is None
                    else await self._link_user_refusal(tx, user_id, lock=True)
                )
                if reason == "unknown_token" or user_id is None:
                    raise _Rollback
                if await self.single_use.lock_live(tx, token, Purpose.PASSKEY_REGISTRATION) is None:
                    reason = "token_not_live"
                    raise _Rollback
                if reason is None:
                    registration = await webauthn.finish_registration(
                        user_id, credential, nickname=nickname, conn=tx
                    )
                if await self.single_use.consume(tx, token, Purpose.PASSKEY_REGISTRATION) is None:
                    reason = "token_not_live"
                    raise _Rollback
                if reason is not None:
                    # The link is spent; record why in the same transaction.
                    await self._audit_link(tx, reason, user_id, source_ip)
                else:
                    key = registration.credential
                    codes = await self.mfa.issue_codes_if_none(tx, user_id)
                    await self._audit(
                        tx,
                        "warden.identity.passkey.registered",
                        user_id,
                        source_ip,
                        credential_id=str(key.id),
                        first_factor=bool(codes),
                    )
                    enrolled = WebAuthnEnrolled(key, codes)
        except _Rollback:
            await self._refuse_link(reason or "unknown_token", user_id, source_ip)
        except WebAuthnError as exc:
            await self._audit_link(None, exc.reason.value, user_id, source_ip)
            if exc.reason in (WebAuthnRefusal.INACTIVE_USER, WebAuthnRefusal.SSO_ONLY):
                raise AuthenticationRefused(exc.reason.value) from None
            raise
        if reason is not None or enrolled is None:
            raise AuthenticationRefused(reason or "unknown_token")  # audited with the spend
        if enrolled.recovery_codes:
            await self._notify_enrolled(enrolled.credential.user_id, key=enrolled.credential)
        return enrolled

    async def _link_user_refusal(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, *, lock: bool
    ) -> str | None:
        """Why this user may not register a passkey from a link now, or None."""
        query = "SELECT status, sign_in_method FROM {} WHERE id = %s"
        if lock:
            query += " FOR UPDATE"
        cur = await conn.execute(sql.SQL(query).format(_USERS), (user_id,))
        row = await cur.fetchone()
        if row is None:
            return "unknown_token"
        return _link_refusal(row[0], row[1])

    async def _audit_link(
        self,
        conn: AsyncConnection[Any] | None,
        reason: str,
        user_id: uuid.UUID | None,
        source_ip: SourceIp,
    ) -> None:
        await record_audit(
            AuditEvent(
                action="warden.identity.passkey.registered",
                outcome="failure",
                actor=None if user_id is None else str(user_id),
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details={"reason": reason},
            ),
            conn=conn,
        )

    async def _refuse_link(
        self, reason: str, user_id: uuid.UUID | None, source_ip: SourceIp
    ) -> NoReturn:
        await self._audit_link(None, reason, user_id, source_ip)
        raise AuthenticationRefused(reason)

    # Invitations accepted by registering a passkey (ruling P9)

    async def begin_passkey_invitation(
        self, token: object, *, source_ip: SourceIp = None
    ) -> WebAuthnOptions:
        """The options for accepting a ``passkey_only`` invitation with a passkey.

        Resident key and user verification required; the invitation stays
        usable. Raises ``InvitationMismatch`` for an invitation accepted
        another way, and ``AuthenticationRefused`` for every other refusal.
        """
        if self.webauthn is None:
            await self._refuse_invitation_unavailable(source_ip)
        user_id = await self.invitations.passkey_invitee(token, source_ip=source_ip)
        return await self.webauthn.begin_registration(
            user_id, WebAuthnPurpose.PASSKEY, for_invitation=True
        )

    async def _refuse_invitation_unavailable(self, source_ip: SourceIp) -> NoReturn:
        await record_audit(
            AuditEvent(
                action="warden.identity.invitation.accepted",
                outcome="failure",
                source_ip=source_ip,
                details={"reason": "webauthn_unavailable", "method": "passkey"},
            )
        )
        raise AuthenticationRefused("webauthn_unavailable")

    async def accept_invitation_with_passkey(
        self,
        token: object,
        credential: object,
        *,
        nickname: object = None,
        source_ip: SourceIp = None,
    ) -> PasskeyInvitationAccepted:
        """Accept a ``passkey_only`` invitation by registering a passkey. No session.

        In the acceptance transaction (wave 9 question 20): the ceremony,
        through its explicit invitation keyword, stores the passkey; the
        invitation is used up; the user is activated with the staged roles
        and given recovery codes (the shared rule of ruling P4). An answer
        that is not a passkey raises ``WebAuthnError`` and leaves the
        invitation usable; ``InvitationMismatch`` for an invitation accepted
        another way; ``AuthenticationRefused`` for every other refusal.
        """
        if nickname is not None and not isinstance(nickname, str):
            raise WebAuthnError(WebAuthnRefusal.NICKNAME)
        webauthn = self.webauthn
        if webauthn is None:
            await self._refuse_invitation_unavailable(source_ip)
        stored: list[WebAuthnCredential] = []
        codes: list[str] = []

        async def register(conn: AsyncConnection[Any], user_id: uuid.UUID) -> dict[str, Any]:
            registration = await webauthn.finish_registration(
                user_id, credential, nickname=nickname, for_invitation=True, conn=conn
            )
            stored.append(registration.credential)
            codes.extend(await self.mfa.issue_codes_if_none(conn, user_id))
            return {"credential_id": str(registration.credential.id)}

        try:
            accepted = await self.invitations.accept_with_passkey(
                token, register=register, source_ip=source_ip
            )
        except WebAuthnError as exc:
            await record_audit(
                AuditEvent(
                    action="warden.identity.invitation.accepted",
                    outcome="failure",
                    actor=None,
                    resource_type="user" if exc.user_id else None,
                    resource_id=None if exc.user_id is None else str(exc.user_id),
                    source_ip=source_ip,
                    details={"reason": exc.reason.value, "method": "passkey"},
                )
            )
            if exc.reason in (WebAuthnRefusal.INACTIVE_USER, WebAuthnRefusal.SSO_ONLY):
                raise AuthenticationRefused(exc.reason.value) from None
            raise
        return PasskeyInvitationAccepted(accepted, stored[0], codes)

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
            if codes:  # the user's first second factor
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
        if codes:  # the user's first second factor
            await self._notify_enrolled(new.user_id)
        return codes, await self.sessions.finish(new)

    # Security keys and passkeys as a second factor (rulings P4 and P7)

    def _relying_party(self) -> WebAuthn:
        if self.webauthn is None:
            raise WebAuthnUnavailable("WebAuthn is not configured")
        return self.webauthn

    async def begin_webauthn_sign_in(
        self, challenge: object, *, source_ip: SourceIp = None
    ) -> WebAuthnOptions:
        """The options for completing an ``mfa_required`` challenge with a key.

        They list only the user's own credentials: the challenge already
        proves the password. User verification is preferred, not required
        (ruling P7). Every refusal is ``AuthenticationRefused``, its reason audited.
        """
        reason: str | None = None
        opened: Challenge | None = None
        options: WebAuthnOptions | None = None
        async with self.db.transaction() as tx:
            opened = await self.mfa.open_challenge(tx, challenge, "verify")
            if opened is None:
                reason = "unknown_challenge"
            else:
                reason = await self._account_refusal(tx, opened.user_id)
            if reason is None and opened is not None:
                try:
                    options = await self._relying_party().begin_authentication(
                        opened.user_id, require_user_verification=False, conn=tx
                    )
                except WebAuthnUnavailable:
                    reason = "webauthn_unavailable"
                except WebAuthnError as exc:
                    reason = exc.reason.value
        if reason is not None or options is None:
            await self._refuse_second_factor(
                reason or "unknown_challenge", opened, "webauthn", source_ip
            )
        return options

    async def verify_webauthn(
        self, challenge: object, credential: object, *, source_ip: SourceIp = None
    ) -> TokenPair:
        """Complete a sign-in with a security key or passkey; ``amr`` ``["pwd", "hwk"]``.

        Under the challenge's attempt limit and single use, with the user's
        status and sign-in method checked again in the transaction that
        issues the session, as ``verify_totp`` does. A refused response
        costs an attempt; a signature counter that did not increase is also
        audited as a suspected clone.

        The ceremony is finished with no transaction of this method's open:
        it uses its challenge up on a connection of its own, and holding one
        here meanwhile would let concurrent sign-ins exhaust the pool.
        """
        policy = await self.policy.current()
        opened, reason = await self._open_challenge(challenge, "verify")
        new: NewSession | None = None
        clone: WebAuthnError | None = None
        if reason is None and opened is not None:
            try:
                assertion = await self._relying_party().finish_authentication(
                    opened.user_id, credential
                )
            except WebAuthnUnavailable:
                reason = "webauthn_unavailable"
            except WebAuthnError as exc:
                reason = exc.reason.value
                clone = exc if exc.suspected_clone else None
            else:
                async with self.db.transaction() as tx:
                    reason = await self._account_refusal(tx, opened.user_id)
                    if reason is None and not await self.mfa.consume_challenge(tx, opened):
                        reason = "challenge_used"
                    if reason is None:
                        new = await self.sessions.start(tx, opened.user_id, _KEY_AMR, policy)
                        await self._clear_throttle(tx, opened.user_id, source_ip)
                        await self._audit(
                            tx,
                            "warden.identity.sign_in",
                            opened.user_id,
                            source_ip,
                            amr=_KEY_AMR,
                            credential_id=str(assertion.credential.id),
                        )
        if reason is not None or new is None:
            if opened is not None and reason not in _NOT_AN_ATTEMPT:
                await self.mfa.record_failure(opened)
            if clone is not None:
                await self._audit_clone(clone, source_ip)
            await self._refuse_second_factor(
                reason or "unknown_challenge", opened, "webauthn", source_ip
            )
        return await self.sessions.finish(new)

    async def begin_webauthn_registration(
        self,
        *,
        challenge: object = None,
        principal: Principal | None = None,
        source_ip: SourceIp = None,
    ) -> WebAuthnOptions:
        """Start registering a key as a second factor, signed in or under an enrolment challenge.

        Resident key and user verification are preferred. Signed in, a
        refusal is raised as ``WebAuthnError`` or ``WebAuthnUnavailable``;
        under a challenge it is ``AuthenticationRefused``.
        """
        user_id = await self._enrolling_user(challenge, principal, source_ip)
        try:
            return await self._relying_party().begin_registration(
                user_id, WebAuthnPurpose.SECOND_FACTOR
            )
        except (WebAuthnError, WebAuthnUnavailable) as exc:
            if principal is not None:
                raise
            reason = exc.reason.value if isinstance(exc, WebAuthnError) else "webauthn_unavailable"
            await self._audit_second_factor_failure(reason, str(user_id), "enrolment", source_ip)
            raise AuthenticationRefused(reason) from None

    async def finish_webauthn_registration(
        self,
        credential: object,
        *,
        nickname: object = None,
        challenge: object = None,
        principal: Principal | None = None,
        source_ip: SourceIp = None,
    ) -> WebAuthnEnrolled:
        """Register a key as a second factor. Under a challenge, also completes the sign-in.

        A user holding no recovery codes gets fresh ones, and the
        MFA-enrolled notice, with their first second factor; a later one
        brings neither. A credential that came out discoverable with user
        verification is recorded as such. Under a challenge that is refused
        once the key is stored (used up meanwhile, or the user no longer
        active), the key is removed again.
        """
        user = None if principal is None else principal.user_id
        if nickname is not None and not isinstance(nickname, str):
            raise WebAuthnError(WebAuthnRefusal.NICKNAME, user_id=user)
        if principal is not None:
            return await self._register_signed_in(principal, credential, nickname, source_ip)
        policy = await self.policy.current()
        opened, reason = await self._open_challenge(challenge, "enrol")
        new: NewSession | None = None
        enrolled: WebAuthnEnrolled | None = None
        if reason is None and opened is not None:
            try:
                registration = await self._relying_party().finish_registration(
                    opened.user_id, credential, nickname=nickname
                )
            except WebAuthnUnavailable:
                reason = "webauthn_unavailable"
            except WebAuthnError as exc:
                reason = exc.reason.value
            else:
                key = registration.credential
                async with self.db.transaction() as tx:
                    reason = await self._account_refusal(tx, opened.user_id)
                    if reason is None and not await self.mfa.consume_challenge(tx, opened):
                        reason = "challenge_used"
                    if reason is None:
                        try:
                            enrolled = await self._registered(tx, key, source_ip)
                        except WebAuthnError as exc:
                            reason = exc.reason.value
                    if reason is not None or enrolled is None:
                        await self.webauthn_credentials.remove(opened.user_id, key.id, conn=tx)
                    else:
                        new = await self.sessions.start(tx, opened.user_id, _KEY_AMR, policy)
                        await self._clear_throttle(tx, opened.user_id, source_ip)
                        await self._audit(
                            tx,
                            "warden.identity.sign_in",
                            opened.user_id,
                            source_ip,
                            amr=_KEY_AMR,
                            credential_id=str(key.id),
                        )
        if reason is not None or new is None or enrolled is None:
            if opened is not None and reason not in _NOT_AN_ATTEMPT:
                await self.mfa.record_failure(opened)
            await self._refuse_second_factor(
                reason or "unknown_challenge", opened, "enrolment", source_ip
            )
        if enrolled.recovery_codes:
            await self._notify_enrolled(new.user_id, key=enrolled.credential)
        return WebAuthnEnrolled(
            enrolled.credential, enrolled.recovery_codes, await self.sessions.finish(new)
        )

    async def _register_signed_in(
        self, principal: Principal, credential: object, nickname: str | None, source_ip: SourceIp
    ) -> WebAuthnEnrolled:
        try:
            registration = await self._relying_party().finish_registration(
                principal.user_id, credential, nickname=nickname
            )
            async with self.db.transaction() as tx:
                enrolled = await self._registered(tx, registration.credential, source_ip)
        except WebAuthnError as exc:
            await self._audit_failure(
                "warden.identity.mfa.webauthn.registered",
                principal.user_id,
                source_ip,
                reason=exc.reason.value,
            )
            raise
        if enrolled.recovery_codes:
            await self._notify_enrolled(principal.user_id, key=enrolled.credential)
        return enrolled

    async def _registered(
        self, tx: AsyncConnection[Any], key: WebAuthnCredential, source_ip: SourceIp
    ) -> WebAuthnEnrolled:
        """Issue codes to a user holding none, and audit the key, in ``tx``.

        The user's row is locked first, so of two second factors added at
        once exactly one brings the codes.
        """
        await self.mfa.lock_user(tx, key.user_id)
        if await self.webauthn_credentials.get(key.user_id, key.id, conn=tx) is None:
            # An administrator's reset removed it after it was stored.
            raise WebAuthnError(
                WebAuthnRefusal.UNKNOWN_CREDENTIAL, user_id=key.user_id, credential_id=key.id
            )
        codes = await self.mfa.issue_codes_if_none(tx, key.user_id)
        await self._audit(
            tx,
            "warden.identity.mfa.webauthn.registered",
            key.user_id,
            source_ip,
            credential_id=str(key.id),
            discoverable=key.discoverable,
            user_verified=key.user_verified,
            first_factor=bool(codes),
        )
        return WebAuthnEnrolled(key, codes)

    async def _open_challenge(
        self, token: object, purpose: ChallengePurpose
    ) -> tuple[Challenge | None, str | None]:
        """The live challenge and why its user may not continue (None if they may)."""
        async with self.db.transaction() as tx:
            opened = await self.mfa.open_challenge(tx, token, purpose)
            if opened is None:
                return None, "unknown_challenge"
            return opened, await self._account_refusal(tx, opened.user_id)

    async def list_webauthn(self, principal: Principal) -> list[WebAuthnCredential]:
        """The signed-in user's security keys and passkeys, oldest first."""
        return await self.webauthn_credentials.list(principal.user_id)

    async def rename_webauthn(
        self,
        principal: Principal,
        credential_id: uuid.UUID,
        nickname: object,
        *,
        source_ip: SourceIp = None,
    ) -> WebAuthnCredential | None:
        """Set or clear a key's nickname; None if the user holds no such key.

        Raises ``WebAuthnError`` (``nickname``) unless the nickname is None or
        1 to 64 characters without control characters.
        """
        if nickname is not None and not isinstance(nickname, str):
            raise WebAuthnError(WebAuthnRefusal.NICKNAME, user_id=principal.user_id)
        async with self.db.transaction() as tx:
            renamed = await self.webauthn_credentials.rename(
                principal.user_id, credential_id, nickname, conn=tx
            )
            if renamed is not None:
                await self._audit(
                    tx,
                    "warden.identity.mfa.webauthn.renamed",
                    principal.user_id,
                    source_ip,
                    credential_id=str(renamed.id),
                )
        return renamed

    async def remove_webauthn(
        self, principal: Principal, credential_id: uuid.UUID, *, source_ip: SourceIp = None
    ) -> bool:
        """Remove one of the signed-in user's keys; False if they hold no such key.

        Refused with ``LastSecondFactorError`` when it is the user's last
        second factor and the session policy requires one (ruling P4). Where
        none is required, the last factor takes the recovery codes with it.
        The user's row is locked first, so concurrent removals are decided
        one at a time and never leave a required factor missing.
        """
        user_id = principal.user_id
        policy = await self.policy.current()
        async with self.db.transaction() as tx:
            await self.mfa.lock_user(tx, user_id)
            if await self.webauthn_credentials.get(user_id, credential_id, conn=tx) is None:
                return False
            last = await self.mfa.count_factors(tx, user_id) <= 1
            if not (last and policy.require_mfa):
                await self.webauthn_credentials.remove(user_id, credential_id, conn=tx)
                codes = await self.mfa.remove_recovery_codes(tx, user_id) if last else 0
                await self._audit(
                    tx,
                    "warden.identity.mfa.webauthn.removed",
                    user_id,
                    source_ip,
                    credential_id=str(credential_id),
                    recovery_codes_removed=codes,
                )
                return True
        await self._audit_failure(
            "warden.identity.mfa.webauthn.removed",
            user_id,
            source_ip,
            credential_id=str(credential_id),
            reason="last_factor",
        )
        raise LastSecondFactorError(f"user {user_id} would be left without a second factor")

    async def _audit_clone(self, error: WebAuthnError, source_ip: SourceIp) -> None:
        if error.user_id is not None:
            await self._audit_failure(
                "warden.identity.mfa.webauthn.clone_suspected",
                error.user_id,
                source_ip,
                credential_id=str(error.credential_id),
            )

    async def _audit_failure(
        self, action: str, user_id: uuid.UUID, source_ip: SourceIp, **details: Any
    ) -> None:
        await record_audit(
            AuditEvent(
                action=action,
                outcome="failure",
                actor=str(user_id),
                resource_type="user",
                resource_id=str(user_id),
                source_ip=source_ip,
                details=details,
            )
        )

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

    async def reset_mfa(
        self, user_id: uuid.UUID, *, actor: str, source_ip: SourceIp = None
    ) -> None:
        """Remove every second factor of a user, and end their sessions.

        For an administrator helping a user who has lost their factors
        (ruling P4, Skuld question 21): one transaction removes the TOTP
        enrolment (confirmed or not), every security key and passkey and
        every recovery code, ends every session of the user, and records
        ``warden.identity.mfa.reset`` with counts. A user with nothing
        enrolled is not an error; the reset is still audited. Raises
        ``UserError`` if there is no such user. ``reset_totp`` is unchanged.
        """
        async with self.db.transaction() as tx:
            # The user's row first, as every change to their second factors
            # takes it: a key being registered is either removed here or added
            # after, with fresh codes; never left with codes for nothing.
            if not await self.mfa.lock_user(tx, user_id):
                raise UserError(f"user {user_id} does not exist")
            totp_removed, codes = await self.mfa.remove(tx, user_id)
            keys = await self.webauthn_credentials.remove_all(user_id, conn=tx)
            ended = await self.sessions.revoke_all(user_id, reason="mfa_reset", conn=tx)
            await record_audit(
                AuditEvent(
                    action="warden.identity.mfa.reset",
                    outcome="success",
                    actor=actor,
                    resource_type="user",
                    resource_id=str(user_id),
                    source_ip=source_ip,
                    details={
                        "totp_removed": totp_removed,
                        "webauthn_removed": keys,
                        "recovery_codes_removed": codes,
                        "sessions_ended": ended,
                    },
                ),
                conn=tx,
            )

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


def _link_refusal(status: str, method: str) -> str | None:
    """Why a user may not have a passkey registration link, or None (ruling P8)."""
    if status != UserStatus.ACTIVE:
        return f"user_{status}"
    if method == SignInMethod.SSO_ONLY:
        return "sso_only"
    return None


def _credential_id(credential: object) -> bytes | None:
    """The credential id a sign-in response names, for the throttle; None if unreadable."""
    raw = credential.get("rawId") if isinstance(credential, Mapping) else None
    if not isinstance(raw, str) or not 0 < len(raw) <= 2 * _MAX_CREDENTIAL_ID:
        return None
    try:
        decoded = websafe_decode(raw)
    except ValueError:
        return None
    return decoded if 0 < len(decoded) <= _MAX_CREDENTIAL_ID else None


class _Rollback(Exception):
    """Abandons a transaction whose refusal must also undo earlier writes."""
