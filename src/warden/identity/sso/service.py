"""``SingleSignOn``: OIDC authorisation code with PKCE, for one provider.

The flow, through the routes in ``warden.identity.routers.sso``:

1. ``begin``: a login transaction (state, nonce, PKCE verifier) is stored,
   bound to a random value the browser holds in an HttpOnly, Secure,
   SameSite=Lax cookie, and the browser is sent to the provider.
2. ``complete`` (the callback): the transaction is used up by one guarded
   write that also checks the cookie, the code is exchanged at the token
   endpoint with the verifier, the id_token is validated, and the account is
   matched. Only pre-provisioned, active users are matched: the first sign-in
   matches a verified email (ignoring case) and pins the provider's
   (issuer, subject) to the user; later sign-ins match by subject, and the
   email must still agree. Success stores a one-time handoff code, also bound
   to the cookie, and the browser lands on ``http.sso_completion_link`` with
   only that code in the query.
3. ``exchange`` (the handoff): the product's screen posts the code with the
   cookie and gets the session's tokens in the response body. The code is
   used up by one guarded write, the user's status is checked again, and the
   session is issued through identity's ``Sessions`` with ``amr`` ``["sso"]``.
   Single sign-on never asks for a second factor, so forced TOTP enrolment
   does not apply to these sessions.

No token, verifier or secret ever appears in a URL. Every refusal is recorded
as ``warden.identity.sso.sign_in`` with its reason; the browser always gets
the same failure.

An invitation link can complete through single sign-on. ``begin`` is given
the invitation token and seals it into the login transaction
(``warden.identity.sso.sealing``): AES-256-GCM under a key derived from the
browser's binding, which the database holds only as a hash, with the
transaction's state hash as associated data. Neither the token nor its hash
is stored in clear. At the callback, after the binding check, the token is
opened with the browser's binding; a value that does not open is refused
and leaves the invitation usable. Once the provider's identity is verified
(email verified and in an allowed domain), the token goes to identity
lifecycle's ``accept_with_sso``, which requires the invited address
(ignoring case) and decides method, status and the single consume. The pin it calls
inside its transaction pins the subject and stores the handoff code, so the
acceptance, the pin and the sign-in commit together or not at all. The
session is then issued at the handoff as for any SSO sign-in.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol, runtime_checkable
from urllib.parse import urlencode

import httpx
from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, get_recorder, record_audit
from warden.config import WardenConfig
from warden.db import Database, schema, table
from warden.identity.errors import AuthenticationRefused
from warden.identity.http import SourceIp
from warden.identity.invitations import (
    AcceptedInvitation,
    InvitationMismatch,
    SubjectPin,
    VerifiedIdentity,
)
from warden.identity.policy import PolicyStore
from warden.identity.sso.actions import register_sso_actions
from warden.identity.sso.errors import SsoError
from warden.identity.sso.provider import Discovery, JwksCache, ProviderHttp, ProviderMetadata
from warden.identity.sso.schema import (
    SSO_HANDOFF_CODES,
    SSO_IDENTITIES,
    SSO_LOGIN_TRANSACTIONS,
    SSO_SETTINGS_LOCK_KEY,
)
from warden.identity.sso.sealing import open_invitation, seal_invitation
from warden.identity.sso.settings import SSO_AMR, SsoSettings, SsoSettingsStore
from warden.identity.sso.validation import IdTokenClaims, IdTokenValidator
from warden.identity.tokens import NewSession, Sessions, TokenPair
from warden.identity.users import SignInMethod, UserStatus, is_email

__all__ = [
    "COOKIE_NAME",
    "SSO_FAILURE_MESSAGE",
    "ConfigurationCheck",
    "ConfigurationReport",
    "InvitationAcceptance",
    "LoginStart",
    "SingleSignOn",
]

COOKIE_NAME = "__Secure-warden-sso"
SSO_FAILURE_MESSAGE = "Single sign-on did not complete. Try again, or contact your administrator."
"""The one message a product shows when single sign-on fails, whatever the reason."""

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_PROVIDER_CODE = re.compile(r"[\x21-\x7e]{1,2048}")
_PROVIDER_ERROR = re.compile(r"[a-z_]{1,64}")
_MAX_SECRET = 4096

_USERS = table(schema.USERS)
_IDENTITIES = table(SSO_IDENTITIES)
_TRANSACTIONS = table(SSO_LOGIN_TRANSACTIONS)
_HANDOFFS = table(SSO_HANDOFF_CODES)


class SecretReader(Protocol):
    def get(self, key: str) -> str | None: ...


@runtime_checkable
class SecretWriter(Protocol):
    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...


class InvitationAcceptance(Protocol):
    """Identity lifecycle's SSO acceptance entry point (``identity.invitations``)."""

    async def accept_with_sso(
        self,
        token: object,
        verified: VerifiedIdentity,
        *,
        pin: SubjectPin,
        source_ip: SourceIp = None,
    ) -> AcceptedInvitation: ...


class _PinRefused(Exception):
    """Raised by the acceptance pin, so the whole acceptance rolls back."""

    def __init__(self, reason: str, user_id: uuid.UUID) -> None:
        super().__init__(reason)
        self.reason = reason
        self.user_id = user_id


@dataclass(frozen=True, slots=True)
class LoginStart:
    """Where to send the browser, and the cookie value that binds the sign-in to it."""

    redirect_url: str
    binding: str
    max_age: int


@dataclass(frozen=True, slots=True)
class ConfigurationCheck:
    name: str
    ok: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ConfigurationReport:
    ok: bool
    checks: tuple[ConfigurationCheck, ...]


def _hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii")).digest()


def _challenge(verifier: str) -> str:
    import base64

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _token(value: object) -> str | None:
    return value if isinstance(value, str) and _TOKEN.fullmatch(value) else None


class SingleSignOn:
    def __init__(
        self,
        config: WardenConfig,
        db: Database,
        sessions: Sessions,
        policy: PolicyStore,
        secrets_store: SecretReader,
        *,
        http: ProviderHttp | None = None,
        settings_max_age: float = 30.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        register_sso_actions(get_recorder().registry)
        sso = config.sso
        self.config = config
        self.db = db
        self.settings = SsoSettingsStore(db, config, max_age=settings_max_age)
        self._sessions = sessions
        self._policy = policy
        self._secrets = secrets_store
        self._http = http
        self._clock = clock
        self._discovery: Discovery | None = None
        self._jwks: JwksCache | None = None
        self._validator: IdTokenValidator | None = None
        self.client_secret_name = sso.client_secret
        self.callback_url = config.http.sso_callback_url

    # Provider plumbing, created on first use so no client is opened unless needed.

    def _provider(self) -> tuple[Discovery, IdTokenValidator, JwksCache]:
        if self._discovery is None or self._validator is None or self._jwks is None:
            sso = self.config.sso
            http = self._http or ProviderHttp(
                httpx.AsyncClient(timeout=10.0, follow_redirects=False)
            )
            self._http = http
            self._discovery = Discovery(http, cache_seconds=sso.discovery_cache_seconds)
            self._jwks = JwksCache(
                http,
                cache_seconds=sso.jwks_cache_seconds,
                refetch_min_seconds=sso.jwks_refetch_min_seconds,
            )
            self._validator = IdTokenValidator(
                self._jwks,
                allowed_algorithms=sso.allowed_algorithms,
                clock_skew_seconds=sso.clock_skew_seconds,
                clock=self._clock,
            )
        return self._discovery, self._validator, self._jwks

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()

    # 1. Begin

    async def begin(self, *, source_ip: SourceIp = None, invitation: object = None) -> LoginStart:
        """Start a sign-in; with ``invitation`` (the link's token), an invitation acceptance.

        The token is sealed into the login transaction to the binding this
        returns, so it opens only at a callback from the browser holding it.
        """
        settings = await self.settings.current()
        if not settings.enabled or settings.issuer_url is None or settings.client_id is None:
            await self._refuse("sso_disabled", source_ip)
        offered: str | None = None
        if invitation is not None:
            offered = _token(invitation)
            if offered is None:
                await self._refuse("invitation_malformed", source_ip)
        discovery, _, _ = self._provider()
        try:
            metadata = await discovery.get(settings.issuer_url)
        except SsoError as exc:
            await self._refuse(exc.reason, source_ip)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        binding = secrets.token_urlsafe(32)
        state_hash = _hash(state)
        sealed = (
            None
            if offered is None
            else seal_invitation(offered, binding=binding, state_hash=state_hash)
        )
        ttl = self.config.sso.login_transaction_ttl_seconds
        async with self.db.connection() as conn:
            await conn.execute(
                sql.SQL(
                    "INSERT INTO {} (state_hash, binding_hash, nonce, code_verifier, issuer,"
                    " invitation_sealed, expires_at)"
                    " VALUES (%s, %s, %s, %s, %s, %s, now() + %s * interval '1 second')"
                ).format(_TRANSACTIONS),
                (state_hash, _hash(binding), nonce, verifier, settings.issuer_url, sealed, ttl),
            )
        query = urlencode(
            {
                "response_type": "code",
                "client_id": settings.client_id,
                "redirect_uri": self.callback_url,
                "scope": " ".join(settings.scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": _challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if "?" in metadata.authorization_endpoint else "?"
        return LoginStart(f"{metadata.authorization_endpoint}{separator}{query}", binding, ttl)

    # 2. Callback

    async def complete(
        self,
        *,
        state: object,
        code: object,
        error: object,
        binding: object,
        source_ip: SourceIp = None,
        invitations: InvitationAcceptance | None = None,
    ) -> str:
        """Finish at the provider and match the account; returns a one-time handoff code.

        If the login transaction was started with an invitation, its sealed
        token must open with ``binding``, and the verified identity accepts
        it through ``invitations`` instead of being matched.
        """
        settings = await self.settings.current()
        if not settings.enabled or settings.issuer_url is None or settings.client_id is None:
            await self._refuse("sso_disabled", source_ip)
        bound = _token(binding)
        if bound is None:
            await self._refuse("no_cookie", source_ip)
        checked_state = _token(state)
        if checked_state is None:
            await self._refuse("transaction_unknown", source_ip)
        transaction = await self._use_transaction(checked_state, bound, source_ip)
        nonce, verifier, issuer, sealed = transaction
        accepting: tuple[str, InvitationAcceptance] | None = None
        if sealed is not None:
            # After the binding check, so the transaction is this browser's.
            token = open_invitation(sealed, binding=bound, state_hash=_hash(checked_state))
            if token is None or invitations is None:
                await self._refuse("invitation_not_bound", source_ip)
            accepting = (token, invitations)
        if error is not None:
            shown = (
                error if isinstance(error, str) and _PROVIDER_ERROR.fullmatch(error) else "other"
            )
            await self._refuse("provider_error", source_ip, provider_error=shown)
        if not isinstance(code, str) or _PROVIDER_CODE.fullmatch(code) is None:
            await self._refuse("token_exchange_failed", source_ip)
        if issuer != settings.issuer_url:
            await self._refuse("issuer_changed", source_ip)
        discovery, validator, _ = self._provider()
        try:
            metadata = await discovery.get(issuer)
            id_token = await self._redeem(metadata, settings.client_id, code, verifier)
            claims = await validator.validate(
                id_token, metadata=metadata, client_id=settings.client_id, nonce=nonce
            )
        except SsoError as exc:
            reason = exc.reason
            if reason in _VALIDATION_REASONS:
                reason = f"id_token_invalid:{reason}"
            await self._refuse(reason, source_ip)
        if accepting is not None:
            token, acceptance = accepting
            return await self._accept_invitation(
                claims, settings, token, acceptance, bound, source_ip
            )
        return await self._match(claims, settings, bound, source_ip)

    async def _use_transaction(
        self, state: str, binding: str, source_ip: SourceIp
    ) -> tuple[str, str, str, bytes | None]:
        async with self.db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET consumed_at = now() WHERE state_hash = %s AND binding_hash = %s"
                    " AND consumed_at IS NULL AND expires_at > now()"
                    " RETURNING nonce, code_verifier, issuer, invitation_sealed"
                ).format(_TRANSACTIONS),
                (_hash(state), _hash(binding)),
            )
            row = await cur.fetchone()
            if row is not None:
                sealed = None if row[3] is None else bytes(row[3])
                return str(row[0]), str(row[1]), str(row[2]), sealed
            cur = await tx.execute(
                sql.SQL(
                    "SELECT binding_hash = %s, consumed_at IS NOT NULL, expires_at <= now()"
                    " FROM {} WHERE state_hash = %s"
                ).format(_TRANSACTIONS),
                (_hash(binding), _hash(state)),
            )
            seen = await cur.fetchone()
        if seen is None:
            reason = "transaction_unknown"
        elif not seen[0]:
            reason = "binding_mismatch"
        elif seen[1]:
            reason = "transaction_used"
        else:
            reason = "transaction_expired"
        await self._refuse(reason, source_ip)

    async def _redeem(
        self, metadata: ProviderMetadata, client_id: str, code: str, verifier: str
    ) -> str:
        secret = self._secrets.get(self.client_secret_name)
        if not secret:
            raise SsoError("client_secret_missing")
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.callback_url,
            "code_verifier": verifier,
            "client_id": client_id,
        }
        auth: tuple[str, str] | None = None
        if "client_secret_basic" in metadata.token_auth_methods:
            auth = (client_id, secret)
        elif "client_secret_post" in metadata.token_auth_methods:
            form["client_secret"] = secret
        else:
            raise SsoError("token_auth_unsupported")
        assert self._http is not None  # created by _provider()  # noqa: S101
        status, body = await self._http.post_form(
            metadata.token_endpoint, form, failure="token_exchange_failed", auth=auth
        )
        if status != 200 or body is None:
            raise SsoError("token_exchange_failed")
        id_token = body.get("id_token")
        token_type = body.get("token_type")
        if not isinstance(id_token, str) or not (
            isinstance(token_type, str) and token_type.lower() == "bearer"
        ):
            raise SsoError("token_exchange_failed")
        return id_token

    async def _verified_email(
        self, claims: IdTokenClaims, settings: SsoSettings, source_ip: SourceIp
    ) -> tuple[str, dict[str, Any]]:
        """The id_token's email, verified and in an allowed domain; and what to audit."""
        email = claims.email
        about: dict[str, Any] = {"subject": claims.subject}
        if email is not None and is_email(email):
            about["email"] = email
        if email is None or not is_email(email):
            await self._refuse("email_missing", source_ip, **about)
        if not claims.email_verified:
            await self._refuse("email_unverified", source_ip, **about)
        domain = email.rpartition("@")[2].lower()
        if settings.allowed_email_domains and domain not in settings.allowed_email_domains:
            await self._refuse("domain_not_allowed", source_ip, **about)
        return email, about

    async def _issue_handoff(
        self, tx: AsyncConnection[Any], code: str, binding: str, user_id: uuid.UUID
    ) -> None:
        await tx.execute(
            sql.SQL(
                "INSERT INTO {} (code_hash, binding_hash, user_id, expires_at)"
                " VALUES (%s, %s, %s, now() + %s * interval '1 second')"
            ).format(_HANDOFFS),
            (_hash(code), _hash(binding), user_id, self.config.sso.handoff_code_ttl_seconds),
        )

    async def _match(
        self, claims: IdTokenClaims, settings: SsoSettings, binding: str, source_ip: SourceIp
    ) -> str:
        email, about = await self._verified_email(claims, settings, source_ip)
        reason: str | None = None
        user_id: uuid.UUID | None = None
        code = secrets.token_urlsafe(32)
        async with self.db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT u.id, u.email, u.status, u.sign_in_method FROM {} i"
                    " JOIN {} u ON u.id = i.user_id"
                    " WHERE i.issuer = %s AND i.subject = %s FOR SHARE OF i"
                ).format(_IDENTITIES, _USERS),
                (claims.issuer, claims.subject),
            )
            pinned = await cur.fetchone()
            if pinned is not None:
                user_id = pinned[0]
                if str(pinned[1]).lower() != email.lower():
                    reason = "email_mismatch"
                elif pinned[2] != UserStatus.ACTIVE:
                    reason = "user_inactive"
                elif pinned[3] == SignInMethod.PASSKEY_ONLY:
                    reason = "passkey_only"
            else:
                user_id, reason = await self._first_sign_in(tx, claims, email, source_ip)
            if reason is None and user_id is not None:
                await self._issue_handoff(tx, code, binding, user_id)
        if reason is not None or user_id is None:
            await self._refuse(reason or "no_account", source_ip, user_id=user_id, **about)
        return code

    async def _accept_invitation(
        self,
        claims: IdTokenClaims,
        settings: SsoSettings,
        token: str,
        invitations: InvitationAcceptance,
        binding: str,
        source_ip: SourceIp,
    ) -> str:
        """Accept the invitation with the verified identity; returns a one-time handoff code.

        Lifecycle decides the email match, method, status and the single
        consume under its locks. Its pin, run in the acceptance transaction
        after the consume, pins this subject and stores the handoff code; a
        subject or user already pinned raises, so nothing is accepted and the
        invitation stays usable.
        """
        email, about = await self._verified_email(claims, settings, source_ip)
        code = secrets.token_urlsafe(32)

        async def pin(
            conn: AsyncConnection[Any], user_id: uuid.UUID, issuer: str, subject: str
        ) -> None:
            cur = await conn.execute(
                sql.SQL(
                    "INSERT INTO {} (user_id, issuer, subject) VALUES (%s, %s, %s)"
                    " ON CONFLICT DO NOTHING RETURNING user_id"
                ).format(_IDENTITIES),
                (user_id, issuer, subject),
            )
            if await cur.fetchone() is None:
                raise _PinRefused("already_pinned", user_id)
            await record_audit(
                AuditEvent(
                    action="warden.identity.sso.subject_pinned",
                    outcome="success",
                    actor=str(user_id),
                    resource_type="user",
                    resource_id=str(user_id),
                    source_ip=source_ip,
                    details={"issuer": issuer, "subject": subject},
                ),
                conn=conn,
            )
            await self._issue_handoff(conn, code, binding, user_id)

        verified = VerifiedIdentity(issuer=claims.issuer, subject=claims.subject, email=email)
        try:
            await invitations.accept_with_sso(token, verified, pin=pin, source_ip=source_ip)
        except _PinRefused as exc:
            await self._refuse(exc.reason, source_ip, user_id=exc.user_id, **about)
        except InvitationMismatch:
            # Lifecycle has recorded the mismatch; the invitation stays usable.
            await self._refuse("invitation_mismatch", source_ip, **about)
        except AuthenticationRefused:
            # Lifecycle has recorded why (unknown, spent, or the user's status).
            await self._refuse("invitation_refused", source_ip, **about)
        return code

    async def _first_sign_in(
        self,
        tx: AsyncConnection[Any],
        claims: IdTokenClaims,
        email: str,
        source_ip: SourceIp,
    ) -> tuple[uuid.UUID | None, str | None]:
        """Match a verified email to a pre-provisioned user and pin the subject."""
        cur = await tx.execute(
            sql.SQL(
                "SELECT id, status, sign_in_method FROM {} WHERE lower(email) = lower(%s)"
            ).format(_USERS),
            (email,),
        )
        row = await cur.fetchone()
        if row is None:
            return None, "no_account"
        user_id: uuid.UUID = row[0]
        if row[1] != UserStatus.ACTIVE:
            return user_id, "user_inactive"
        if row[2] == SignInMethod.PASSKEY_ONLY:
            # A passkey_only user signs in with a passkey alone (Skuld question 26).
            return user_id, "passkey_only"
        cur = await tx.execute(
            sql.SQL(
                "INSERT INTO {} (user_id, issuer, subject) VALUES (%s, %s, %s)"
                " ON CONFLICT DO NOTHING RETURNING user_id"
            ).format(_IDENTITIES),
            (user_id, claims.issuer, claims.subject),
        )
        if await cur.fetchone() is None:
            # Already pinned: to another subject (refused), or to this one by a
            # sign-in that committed while this one waited (accepted).
            cur = await tx.execute(
                sql.SQL("SELECT issuer, subject FROM {} WHERE user_id = %s").format(_IDENTITIES),
                (user_id,),
            )
            existing = await cur.fetchone()
            if existing is None or (existing[0], existing[1]) != (claims.issuer, claims.subject):
                return user_id, "subject_mismatch"
            return user_id, None
        await record_audit(
            AuditEvent(
                action="warden.identity.sso.subject_pinned",
                outcome="success",
                actor=str(user_id),
                resource_type="user",
                resource_id=str(user_id),
                source_ip=source_ip,
                details={"issuer": claims.issuer, "subject": claims.subject},
            ),
            conn=tx,
        )
        return user_id, None

    # 3. Handoff

    async def exchange(
        self, code: object, binding: object, *, source_ip: SourceIp = None
    ) -> TokenPair:
        """Use up a handoff code and issue the session; ``AuthenticationRefused`` otherwise."""
        checked, bound = _token(code), _token(binding)
        if checked is None or bound is None:
            await self._refuse_handoff("handoff_unknown", None, source_ip)
        policy = await self._policy.current()
        reason: str | None = None
        user_id: uuid.UUID | None = None
        new: NewSession | None = None
        async with self.db.transaction() as tx:
            # Shared with every other issuance; exclusive with a settings change.
            await tx.execute("SELECT pg_advisory_xact_lock_shared(%s)", (SSO_SETTINGS_LOCK_KEY,))
            settings = await self.settings.read(tx)
            if not settings.enabled:
                reason = "sso_disabled"
            else:
                cur = await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET consumed_at = now() WHERE code_hash = %s"
                        " AND binding_hash = %s AND consumed_at IS NULL AND expires_at > now()"
                        " RETURNING user_id"
                    ).format(_HANDOFFS),
                    (_hash(checked), _hash(bound)),
                )
                row = await cur.fetchone()
                if row is None:
                    reason = "handoff_unknown"
                else:
                    user_id = row[0]
                    reason = await self._handoff_refusal(tx, row[0], settings)
            if reason is None and user_id is not None:
                new = await self._sessions.start(tx, user_id, [SSO_AMR], policy)
                await tx.execute(
                    sql.SQL("UPDATE {} SET last_sign_in_at = now() WHERE user_id = %s").format(
                        _IDENTITIES
                    ),
                    (user_id,),
                )
                await record_audit(
                    AuditEvent(
                        action="warden.identity.sign_in",
                        outcome="success",
                        actor=str(user_id),
                        resource_type="user",
                        resource_id=str(user_id),
                        source_ip=source_ip,
                        details={"amr": [SSO_AMR]},
                    ),
                    conn=tx,
                )
        if reason is not None or new is None:
            await self._refuse_handoff(reason or "handoff_unknown", user_id, source_ip)
        return await self._sessions.finish(new)

    async def _handoff_refusal(
        self, tx: AsyncConnection[Any], user_id: uuid.UUID, settings: SsoSettings
    ) -> str | None:
        cur = await tx.execute(
            sql.SQL(
                "SELECT u.status, i.issuer, u.sign_in_method FROM {} u"
                " LEFT JOIN {} i ON i.user_id = u.id WHERE u.id = %s FOR SHARE OF u"
            ).format(_USERS, _IDENTITIES),
            (user_id,),
        )
        row = await cur.fetchone()
        if row is None or row[0] != UserStatus.ACTIVE:
            return "user_inactive"
        if row[2] == SignInMethod.PASSKEY_ONLY:
            return "passkey_only"
        if row[1] != settings.issuer_url:
            return "not_pinned"
        return None

    # Administration

    async def set_client_secret(
        self, value: object, *, actor: str | None, source_ip: SourceIp = None
    ) -> None:
        """Store the client secret in konfig's secrets store. It is never read back out."""
        if (
            not isinstance(value, str)
            or not 0 < len(value) <= _MAX_SECRET
            or any(ch < " " or ch == "\x7f" for ch in value)
        ):
            raise ValueError("the client secret must be 1 to 4096 printable characters")
        if not isinstance(self._secrets, SecretWriter):
            raise RuntimeError("the secrets store cannot be written")
        self._secrets.set(self.client_secret_name, value)
        await record_audit(
            AuditEvent(
                action="warden.identity.sso.client_secret_set",
                outcome="success",
                actor=actor,
                resource_type="sso_settings",
                source_ip=source_ip,
                details={"secret_name": self.client_secret_name},
            )
        )

    def client_secret_set(self) -> bool:
        return bool(self._secrets.get(self.client_secret_name))

    async def test_configuration(
        self, *, actor: str | None, source_ip: SourceIp = None
    ) -> ConfigurationReport:
        """Check the settings against the provider. Signs nobody in and redeems nothing."""
        settings = await self.settings.current()
        checks: list[ConfigurationCheck] = []
        configured = settings.issuer_url is not None and settings.client_id is not None
        checks.append(ConfigurationCheck("settings", configured, None if configured else "missing"))
        has_secret = self.client_secret_set()
        checks.append(
            ConfigurationCheck("client_secret", has_secret, None if has_secret else "missing")
        )
        if settings.issuer_url is not None:
            discovery, validator, jwks = self._provider()
            metadata: ProviderMetadata | None = None
            try:
                metadata = await discovery.fetch(settings.issuer_url)
                checks.append(ConfigurationCheck("discovery", True))
            except SsoError as exc:
                checks.append(ConfigurationCheck("discovery", False, exc.reason))
            if metadata is not None:
                usable = validator.usable_algorithms(metadata)
                checks.append(
                    ConfigurationCheck(
                        "algorithms", bool(usable), None if usable else "none_shared"
                    )
                )
                try:
                    keys = await jwks.fetch_all(metadata.jwks_uri)
                    ok = any(k.get("alg") in (None, *usable) for k in keys.values())
                    checks.append(ConfigurationCheck("jwks", ok, None if ok else "no_usable_key"))
                except SsoError as exc:
                    checks.append(ConfigurationCheck("jwks", False, exc.reason))
        report = ConfigurationReport(all(c.ok for c in checks), tuple(checks))
        await record_audit(
            AuditEvent(
                action="warden.identity.sso.configuration_tested",
                outcome="success" if report.ok else "failure",
                actor=actor,
                resource_type="sso_settings",
                source_ip=source_ip,
                details={"failed": [c.name for c in checks if not c.ok]},
            )
        )
        return report

    async def unpin(self, user_id: uuid.UUID, *, actor: str | None) -> bool:
        """Remove a user's pinned subject, so their next sign-in pins afresh."""
        async with self.db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE user_id = %s").format(_IDENTITIES), (user_id,)
            )
            removed = cur.rowcount == 1
            if removed:
                await record_audit(
                    AuditEvent(
                        action="warden.identity.sso.subject_unpinned",
                        outcome="success",
                        actor=actor,
                        resource_type="user",
                        resource_id=str(user_id),
                    ),
                    conn=tx,
                )
        return removed

    async def prune(self) -> int:
        """Delete expired login transactions and handoff codes."""
        removed = 0
        async with self.db.transaction() as tx:
            for name in (_TRANSACTIONS, _HANDOFFS):
                cur = await tx.execute(
                    sql.SQL("DELETE FROM {} WHERE expires_at <= now()").format(name)
                )
                removed += cur.rowcount
        return removed

    # Refusals

    async def _refuse(
        self,
        reason: str,
        source_ip: SourceIp,
        *,
        user_id: uuid.UUID | None = None,
        **details: Any,
    ) -> NoReturn:
        await record_audit(
            AuditEvent(
                action="warden.identity.sso.sign_in",
                outcome="failure",
                actor=None if user_id is None else str(user_id),
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details={"reason": reason, **details},
            )
        )
        raise SsoError(reason)

    async def _refuse_handoff(
        self, reason: str, user_id: uuid.UUID | None, source_ip: SourceIp
    ) -> NoReturn:
        try:
            await self._refuse(reason, source_ip, user_id=user_id)
        except SsoError:
            raise AuthenticationRefused(reason) from None


# Reasons from id_token validation, recorded as ``id_token_invalid:<reason>``.
_VALIDATION_REASONS = frozenset(
    {
        "malformed",
        "algorithm_not_allowed",
        "unknown_key",
        "bad_signature",
        "issuer",
        "audience",
        "authorised_party",
        "expired",
        "issued_in_future",
        "nonce",
    }
)
