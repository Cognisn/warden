"""The WebAuthn ceremonies: registering and signing in with passkeys and security keys.

Built on fido2's relying-party primitives (its WebAuthn data types, COSE
keys and attestation verifiers), with every check written out here so each
can be seen and tested on its own. Every response is checked for:

- a challenge this relying party issued for this ceremony and this user,
  unexpired and unused, used up by one guarded write before anything else
  is checked;
- the client data's type, an origin equal to an allowed origin, and no
  ``crossOrigin``;
- the relying party id hash, user presence, and user verification where the
  ceremony requires it;
- on registration, an allowed algorithm and, with trusted roots configured,
  an attestation chaining to one of them (ruling P3);
- on sign-in, a credential the user holds (by user handle and credential id
  together for a discoverable sign-in), its signature, its backup
  eligibility, and the counter rule: a non-zero counter that does not
  increase is refused as a suspected clone.

A user who is not active, or who signs in only through single sign-on
(ruling P5), is refused at every step. The one exception is explicit: a
registration begun and finished with ``for_invitation`` admits an invited
user (and only an invited one), for a ``passkey_only`` invitation accepted
by registering a passkey (wave 9 question 20). A discoverable sign-in
accepts only a credential that is discoverable and was registered with
user verification (rulings P6 and P7). User verification is preferred for a
second factor and required for a passkey (ruling P7). Nothing here records
an audit event or logs: the callers that face a browser record each outcome
with the refusal's reason.
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, cast

import psycopg
from cryptography.exceptions import InvalidSignature
from fido2 import cbor
from fido2.cose import ES256, RS256, CoseKey, EdDSA
from fido2.utils import sha256
from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticationResponse,
    AuthenticatorData,
    AuthenticatorSelectionCriteria,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from psycopg import AsyncConnection, sql

from warden.config import ConfigError, WardenConfig
from warden.db import Database, schema, table
from warden.identity.users import SignInMethod, UserStatus
from warden.identity.webauthn.attestation import AttestationNotTrusted, TrustedRoots
from warden.identity.webauthn.challenges import Ceremony, Challenges
from warden.identity.webauthn.errors import WebAuthnError, WebAuthnRefusal
from warden.identity.webauthn.store import (
    COLUMNS,
    WebAuthnCredential,
    WebAuthnCredentials,
    check_nickname,
    credential_from_row,
)

__all__ = [
    "WebAuthn",
    "WebAuthnAssertion",
    "WebAuthnOptions",
    "WebAuthnPurpose",
    "WebAuthnRegistration",
]

R = WebAuthnRefusal

# Offered in this order: Ed25519, ES256, then RS256 (Windows Hello).
_ALGORITHMS = (EdDSA.ALGORITHM, ES256.ALGORITHM, RS256.ALGORITHM)
_TRANSPORTS = ("usb", "nfc", "ble", "hybrid", "internal", "smart-card")
_MAX_CREDENTIAL_ID = 1023
_USER_HANDLE_BYTES = 64

_USERS = table(schema.USERS)
_CREDENTIALS = table(schema.WEBAUTHN_CREDENTIALS)
_HANDLES = table(schema.WEBAUTHN_USER_HANDLES)


class WebAuthnPurpose(StrEnum):
    """What a credential is registered for."""

    SECOND_FACTOR = "second_factor"
    """After a password: resident key and user verification preferred."""
    PASSKEY = "passkey"
    """Sign-in on its own: a discoverable credential with user verification required."""


@dataclass(frozen=True, slots=True)
class WebAuthnOptions:
    """What the browser passes to ``navigator.credentials.create()`` or ``get()``."""

    public_key: dict[str, Any]
    """The ``publicKey`` member, as JSON (bytes base64url-encoded)."""
    expires_at: datetime
    """When the ceremony's challenge stops being usable."""


@dataclass(frozen=True, slots=True)
class WebAuthnRegistration:
    credential: WebAuthnCredential
    purpose: WebAuthnPurpose


@dataclass(frozen=True, slots=True)
class WebAuthnAssertion:
    """A successful sign-in with a credential."""

    user_id: uuid.UUID
    credential: WebAuthnCredential
    user_verified: bool


@dataclass(frozen=True, slots=True)
class _Stored:
    id: uuid.UUID
    user_id: uuid.UUID
    public_key: CoseKey
    backup_eligible: bool
    discoverable: bool
    user_verified: bool


class WebAuthn:
    """The WebAuthn relying party: ceremonies and the credential store.

    A ``begin_*`` call issues a challenge and returns the browser's options;
    the matching ``finish_*`` call checks the browser's response. Both join
    the caller's transaction when given ``conn``, except that a finish uses
    the challenge up in a transaction of its own (see ``challenges``).
    """

    def __init__(self, config: WardenConfig, db: Database) -> None:
        settings = config.webauthn
        rp_id = settings.relying_party_id(config.http)
        if rp_id is None:
            raise ConfigError(
                "invalid warden configuration:\n"
                "  warden.webauthn.rp_id: is required when http.public_base_url's host"
                " is not a domain"
            )
        self._db = db
        self._rp = PublicKeyCredentialRpEntity(
            name=settings.relying_party_name(config.http), id=rp_id
        )
        self._rp_id_hash = sha256(rp_id.encode("ascii"))
        self._origins = frozenset(settings.origins(config.http))
        self._roots = TrustedRoots(settings.attestation_roots)
        self._ttl_seconds = settings.challenge_ttl_seconds
        self._timeout_ms = settings.client_timeout_seconds * 1000
        self._limit = settings.max_credentials_per_user
        self._challenges = Challenges(db)
        self.credentials = WebAuthnCredentials(db)

    # Registration.

    async def begin_registration(
        self,
        user_id: uuid.UUID,
        purpose: WebAuthnPurpose,
        *,
        for_invitation: bool = False,
        conn: AsyncConnection[Any] | None = None,
    ) -> WebAuthnOptions:
        """Start registering a credential for an active user, for ``purpose``.

        ``for_invitation`` admits an invited user instead (and refuses an
        active one): only for accepting a ``passkey_only`` invitation.
        """
        passkey = purpose is WebAuthnPurpose.PASSKEY
        async with self._db.transaction(conn) as tx:
            email, display_name = await self._active_user(
                tx, user_id, for_invitation=for_invitation
            )
            existing = await self._descriptors(tx, user_id)
            if len(existing) >= self._limit:
                raise WebAuthnError(R.LIMIT_REACHED, user_id=user_id)
            handle = await self._user_handle(tx, user_id)
            issued = await self._challenges.issue(
                tx,
                Ceremony.REGISTRATION,
                user_id,
                user_verification_required=passkey,
                resident_key_required=passkey,
                ttl_seconds=self._ttl_seconds,
            )
        requirement = "required" if passkey else "preferred"
        options = PublicKeyCredentialCreationOptions(
            rp=self._rp,
            user=PublicKeyCredentialUserEntity(
                name=email, id=handle, display_name=display_name or email
            ),
            challenge=issued.challenge,
            pub_key_cred_params=[
                PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg)
                for alg in _ALGORITHMS
            ],
            timeout=self._timeout_ms,
            exclude_credentials=existing or None,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement(requirement),
                user_verification=UserVerificationRequirement(requirement),
            ),
            attestation=(
                AttestationConveyancePreference.DIRECT
                if self._roots
                else AttestationConveyancePreference.NONE
            ),
            extensions={"credProps": True},
        )
        return WebAuthnOptions(dict(options), issued.expires_at)

    async def finish_registration(
        self,
        user_id: uuid.UUID,
        response: object,
        *,
        nickname: str | None = None,
        for_invitation: bool = False,
        conn: AsyncConnection[Any] | None = None,
    ) -> WebAuthnRegistration:
        """Check the browser's registration response and store the credential.

        ``for_invitation`` admits an invited user, as for ``begin_registration``;
        the caller activates the user in the same transaction (``conn``).
        """
        check_nickname(nickname, user_id)
        parsed = _parse(RegistrationResponse, response, user_id)
        client_data = parsed.response.client_data
        attestation = parsed.response.attestation_object
        challenge = await self._challenges.consume(
            client_data.challenge, Ceremony.REGISTRATION, user_id
        )
        self._check_client_data(client_data, CollectedClientData.TYPE.CREATE, user_id)
        auth_data = attestation.auth_data
        self._check_authenticator_data(auth_data, challenge.user_verification_required, user_id)

        credential = auth_data.credential_data
        if (
            credential is None
            or not auth_data.is_attested()
            or credential.credential_id != parsed.raw_id
            or len(credential.credential_id) > _MAX_CREDENTIAL_ID
        ):
            raise WebAuthnError(R.MALFORMED, user_id=user_id)
        if credential.public_key.ALGORITHM not in _ALGORITHMS:
            raise WebAuthnError(R.ALGORITHM, user_id=user_id)
        resident = _reported_resident_key(response)
        if challenge.resident_key_required and resident is False:
            raise WebAuthnError(R.NOT_DISCOVERABLE, user_id=user_id)
        if self._roots:
            try:
                self._roots.check(attestation, client_data.hash)
            except AttestationNotTrusted:
                raise WebAuthnError(R.ATTESTATION, user_id=user_id) from None

        try:
            async with self._db.transaction(conn) as tx:
                await self._active_user(tx, user_id, lock=True, for_invitation=for_invitation)
                cur = await tx.execute(
                    sql.SQL("SELECT count(*) FROM {} WHERE user_id = %s").format(_CREDENTIALS),
                    (user_id,),
                )
                counted = await cur.fetchone()
                if counted is not None and counted[0] >= self._limit:
                    raise WebAuthnError(R.LIMIT_REACHED, user_id=user_id)
                cur = await tx.execute(
                    sql.SQL(
                        "INSERT INTO {} (user_id, credential_id, public_key, algorithm,"
                        " sign_count, aaguid, transports, backup_eligible, backup_state,"
                        " discoverable, user_verified, attestation_verified, nickname)"
                        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                        " RETURNING {}"
                    ).format(_CREDENTIALS, COLUMNS),
                    (
                        user_id,
                        credential.credential_id,
                        cbor.encode(dict(credential.public_key)),
                        credential.public_key.ALGORITHM,
                        auth_data.counter,
                        uuid.UUID(bytes=bytes(credential.aaguid)),
                        _transports(response),
                        auth_data.is_backup_eligible(),
                        auth_data.is_backed_up(),
                        challenge.resident_key_required or resident is True,
                        auth_data.is_user_verified(),
                        bool(self._roots),
                        nickname,
                    ),
                )
                row = await cur.fetchone()
        except psycopg.errors.UniqueViolation:
            raise WebAuthnError(R.CREDENTIAL_EXISTS, user_id=user_id) from None
        if row is None:
            raise RuntimeError("the credential was not recorded")
        purpose = (
            WebAuthnPurpose.PASSKEY
            if challenge.resident_key_required
            else WebAuthnPurpose.SECOND_FACTOR
        )
        return WebAuthnRegistration(credential_from_row(row), purpose)

    # Sign-in.

    async def begin_authentication(
        self,
        user_id: uuid.UUID | None,
        *,
        require_user_verification: bool,
        conn: AsyncConnection[Any] | None = None,
    ) -> WebAuthnOptions:
        """Start a sign-in: for a known user, or discoverable (``user_id`` None).

        A known user's options list their credentials; a discoverable
        sign-in lists none, so nothing reveals whether an account exists,
        and always requires user verification (ruling P7).
        """
        if user_id is None and not require_user_verification:
            raise ValueError("a discoverable sign-in always requires user verification")
        async with self._db.transaction(conn) as tx:
            allowed: list[PublicKeyCredentialDescriptor] | None = None
            if user_id is not None:
                await self._active_user(tx, user_id)
                allowed = await self._descriptors(tx, user_id)
                if not allowed:
                    raise WebAuthnError(R.NO_CREDENTIALS, user_id=user_id)
            issued = await self._challenges.issue(
                tx,
                Ceremony.AUTHENTICATION,
                user_id,
                user_verification_required=require_user_verification,
                resident_key_required=False,
                ttl_seconds=self._ttl_seconds,
            )
        options = PublicKeyCredentialRequestOptions(
            challenge=issued.challenge,
            timeout=self._timeout_ms,
            rp_id=self._rp.id,
            allow_credentials=allowed,
            user_verification=(
                UserVerificationRequirement.REQUIRED
                if require_user_verification
                else UserVerificationRequirement.PREFERRED
            ),
        )
        return WebAuthnOptions(dict(options), issued.expires_at)

    async def finish_authentication(
        self,
        user_id: uuid.UUID | None,
        response: object,
        *,
        conn: AsyncConnection[Any] | None = None,
    ) -> WebAuthnAssertion:
        """Check the browser's sign-in response; the signed-in user and credential.

        ``user_id`` is the user the ceremony began for, or None for a
        discoverable sign-in, which finds the user by the response's user
        handle and credential id together.
        """
        parsed = _parse(AuthenticationResponse, response, user_id)
        client_data = parsed.response.client_data
        auth_data = parsed.response.authenticator_data
        challenge = await self._challenges.consume(
            client_data.challenge, Ceremony.AUTHENTICATION, user_id
        )
        self._check_client_data(client_data, CollectedClientData.TYPE.GET, user_id)
        self._check_authenticator_data(auth_data, challenge.user_verification_required, user_id)
        if len(parsed.raw_id) > _MAX_CREDENTIAL_ID:
            raise WebAuthnError(R.MALFORMED, user_id=user_id)

        async with self._db.transaction(conn) as tx:
            stored = await self._stored(tx, parsed.raw_id)
            if stored is None:
                raise WebAuthnError(R.UNKNOWN_CREDENTIAL, user_id=user_id)
            owner, refusal = stored.user_id, {"user_id": stored.user_id, "credential_id": stored.id}
            if user_id is not None and owner != user_id:
                raise WebAuthnError(R.CREDENTIAL_NOT_ALLOWED, user_id=user_id)
            handle = parsed.response.user_handle
            if user_id is None or handle is not None:
                expected = await self._stored_user_handle(tx, owner)
                if handle is None or expected is None or not hmac.compare_digest(handle, expected):
                    raise WebAuthnError(R.USER_HANDLE, **refusal)
            if user_id is None:
                # Signing in with the credential alone: it must be a passkey.
                if not stored.discoverable:
                    raise WebAuthnError(R.NOT_DISCOVERABLE, **refusal)
                if not stored.user_verified:
                    raise WebAuthnError(R.USER_VERIFICATION, **refusal)
            await self._active_user(tx, owner)
            if auth_data.is_backup_eligible() != stored.backup_eligible:
                raise WebAuthnError(R.BACKUP_ELIGIBILITY, **refusal)
            try:
                stored.public_key.verify(
                    bytes(auth_data) + client_data.hash, parsed.response.signature
                )
            except (InvalidSignature, ValueError, TypeError):
                raise WebAuthnError(R.SIGNATURE, **refusal) from None
            # The counter rule, as one guarded write: a counter that does not
            # increase (unless both are zero) changes nothing and is refused.
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET sign_count = %(count)s, backup_state = %(backed_up)s,"
                    " last_used_at = now()"
                    " WHERE id = %(id)s"
                    " AND (sign_count < %(count)s OR (sign_count = 0 AND %(count)s = 0))"
                    " RETURNING {}"
                ).format(_CREDENTIALS, COLUMNS),
                {
                    "count": auth_data.counter,
                    "backed_up": auth_data.is_backed_up(),
                    "id": stored.id,
                },
            )
            row = await cur.fetchone()
            if row is None:
                if await self._stored(tx, parsed.raw_id) is None:
                    raise WebAuthnError(R.UNKNOWN_CREDENTIAL, **refusal)
                raise WebAuthnError(R.SUSPECTED_CLONE, **refusal)
        return WebAuthnAssertion(owner, credential_from_row(row), auth_data.is_user_verified())

    async def prune(self) -> int:
        """Delete expired challenges; returns how many."""
        return await self._challenges.prune()

    # Checks shared by both ceremonies.

    def _check_client_data(
        self, client_data: CollectedClientData, expected: str, user_id: uuid.UUID | None
    ) -> None:
        if client_data.type != expected:
            raise WebAuthnError(R.TYPE, user_id=user_id)
        if client_data.origin not in self._origins:
            raise WebAuthnError(R.ORIGIN, user_id=user_id)
        if client_data.cross_origin is not False:
            raise WebAuthnError(R.CROSS_ORIGIN, user_id=user_id)

    def _check_authenticator_data(
        self, auth_data: AuthenticatorData, user_verification: bool, user_id: uuid.UUID | None
    ) -> None:
        if not hmac.compare_digest(auth_data.rp_id_hash, self._rp_id_hash):
            raise WebAuthnError(R.RP_ID_HASH, user_id=user_id)
        if not auth_data.is_user_present():
            raise WebAuthnError(R.USER_PRESENCE, user_id=user_id)
        if user_verification and not auth_data.is_user_verified():
            raise WebAuthnError(R.USER_VERIFICATION, user_id=user_id)
        if auth_data.is_backed_up() and not auth_data.is_backup_eligible():
            raise WebAuthnError(R.FLAGS, user_id=user_id)

    # Queries.

    async def _active_user(
        self,
        conn: AsyncConnection[Any],
        user_id: uuid.UUID,
        *,
        lock: bool = False,
        for_invitation: bool = False,
    ) -> tuple[str, str | None]:
        """The user's email and display name; refuses unless active and not SSO-only.

        ``lock`` holds the user's row until the transaction ends, so two
        registrations for one user count their credentials one at a time.
        ``for_invitation`` requires the user to be invited instead of active.
        """
        query = "SELECT email, display_name, status, sign_in_method FROM {} WHERE id = %s"
        if lock:
            query += " FOR NO KEY UPDATE"
        cur = await conn.execute(sql.SQL(query).format(_USERS), (user_id,))
        row = await cur.fetchone()
        if row is None:
            raise WebAuthnError(R.UNKNOWN_USER, user_id=user_id)
        wanted = UserStatus.INVITED if for_invitation else UserStatus.ACTIVE
        if row[2] != wanted.value:
            raise WebAuthnError(R.INACTIVE_USER, user_id=user_id)
        if row[3] == SignInMethod.SSO_ONLY.value:
            raise WebAuthnError(R.SSO_ONLY, user_id=user_id)
        return row[0], row[1]

    async def _descriptors(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID
    ) -> list[PublicKeyCredentialDescriptor]:
        cur = await conn.execute(
            sql.SQL(
                "SELECT credential_id, transports FROM {} WHERE user_id = %s"
                " ORDER BY created_at, id"
            ).format(_CREDENTIALS),
            (user_id,),
        )
        return [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY, id=bytes(row[0]), transports=row[1] or None
            )
            for row in await cur.fetchall()
        ]

    async def _user_handle(self, conn: AsyncConnection[Any], user_id: uuid.UUID) -> bytes:
        """The user's handle, created on first use: random, never derived from the id."""
        await conn.execute(
            sql.SQL(
                "INSERT INTO {} (user_id, handle) VALUES (%s, %s) ON CONFLICT (user_id) DO NOTHING"
            ).format(_HANDLES),
            (user_id, secrets.token_bytes(_USER_HANDLE_BYTES)),
        )
        handle = await self._stored_user_handle(conn, user_id)
        if handle is None:
            raise RuntimeError("the user handle was not recorded")
        return handle

    async def _stored_user_handle(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID
    ) -> bytes | None:
        cur = await conn.execute(
            sql.SQL("SELECT handle FROM {} WHERE user_id = %s").format(_HANDLES), (user_id,)
        )
        row = await cur.fetchone()
        return None if row is None else bytes(row[0])

    async def _stored(self, conn: AsyncConnection[Any], credential_id: bytes) -> _Stored | None:
        cur = await conn.execute(
            sql.SQL(
                "SELECT id, user_id, public_key, backup_eligible, discoverable, user_verified"
                " FROM {} WHERE credential_id = %s"
            ).format(_CREDENTIALS),
            (credential_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        # warden wrote this COSE key itself at registration, so it is a map.
        public_key = CoseKey.parse(cast(Mapping[int, Any], cbor.decode(bytes(row[2]))))
        return _Stored(row[0], row[1], public_key, row[3], row[4], row[5])


def _parse[T: (RegistrationResponse, AuthenticationResponse)](
    kind: type[T], response: object, user_id: uuid.UUID | None
) -> T:
    """The browser's response, or a ``malformed`` refusal; never the response in an error."""
    if not isinstance(response, Mapping):
        raise WebAuthnError(R.MALFORMED, user_id=user_id)
    try:
        return kind.from_dict(response)
    except Exception:  # untrusted input: any failure to read it is malformed
        raise WebAuthnError(R.MALFORMED, user_id=user_id) from None


def _extension_results(response: object) -> Mapping[str, Any]:
    results = response.get("clientExtensionResults") if isinstance(response, Mapping) else None
    return results if isinstance(results, Mapping) else {}


def _reported_resident_key(response: object) -> bool | None:
    """``credProps.rk`` where the browser reports it."""
    properties = _extension_results(response).get("credProps")
    resident = properties.get("rk") if isinstance(properties, Mapping) else None
    return resident if isinstance(resident, bool) else None


def _transports(response: object) -> list[str]:
    """The transports the browser reports, known values only, in order, once each."""
    inner = response.get("response") if isinstance(response, Mapping) else None
    reported = inner.get("transports") if isinstance(inner, Mapping) else None
    if not isinstance(reported, list):
        return []
    return [name for name in _TRANSPORTS if name in reported]
