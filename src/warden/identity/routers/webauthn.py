"""Security keys and passkeys as a second factor. Included in the auth router.

| Route | Body | Success |
|---|---|---|
| ``POST /webauthn/verify/options`` | ``challenge`` | options |
| ``POST /webauthn/verify`` | ``challenge``, ``credential`` | tokens |
| ``POST /webauthn/registration`` | bearer token, or ``challenge`` | options |
| ``POST /webauthn/registration/confirm`` | bearer or ``challenge``; (+) | (*) |
| ``GET /webauthn/credentials`` | bearer token | ``credentials`` |
| ``PATCH /webauthn/credentials/{id}`` | bearer token; ``nickname`` | ``credential`` |
| ``DELETE /webauthn/credentials/{id}`` | bearer token | 204 |

Options are ``{"public_key", "expires_at"}``. (+) ``credential`` and an
optional ``nickname``. (*) ``credential`` and ``recovery_codes``; under a
challenge, the tokens as well.

The verify routes complete an ``mfa_required`` challenge as ``/totp/verify``
does, with the same uniform refusal. Registration under an
``mfa_enrolment_required`` challenge is a forced enrolment, beside
``/totp/enrolment``. Every other error is a fixed message.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import Response

from warden.identity.dependencies import Principal, bearer_token
from warden.identity.errors import AuthenticationRefused
from warden.identity.http import SourceIp, client_ip, json_response, read_object, refusal
from warden.identity.mfa import LastSecondFactorError, WebAuthnUnavailable
from warden.identity.routers.contract import (
    REFUSED,
    EnrolmentBody,
    WardenSignedIn,
    WardenWebAuthnCredentialEnvelope,
    WardenWebAuthnCredentialList,
    WardenWebAuthnOptions,
    WardenWebAuthnRegistrationConfirmed,
    WebAuthnRegistrationConfirmBody,
    WebAuthnRenameBody,
    WebAuthnVerifyBody,
    WebAuthnVerifyOptionsBody,
    detail,
    json_body,
    no_store,
)
from warden.identity.routers.tokens import token_body
from warden.identity.webauthn import WebAuthnCredential, WebAuthnError, WebAuthnOptions
from warden.identity.webauthn import WebAuthnRefusal as R

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_webauthn_router"]

_UNAVAILABLE = "WebAuthn is not configured"
_NOT_ACCEPTED = "credential not accepted"
_NICKNAME = "the nickname is not valid"
_LIMIT = "the credential limit is reached"
_SSO_ONLY = "security keys are not available to this user"
_LAST_FACTOR = "the last second factor cannot be removed while a second factor is required"
_NOT_FOUND = "not found"


def _credential(key: WebAuthnCredential) -> dict[str, object]:
    return {
        "id": str(key.id),
        "nickname": key.nickname,
        "created_at": key.created_at.isoformat(),
        "last_used_at": None if key.last_used_at is None else key.last_used_at.isoformat(),
        "aaguid": str(key.aaguid),
        "backup_eligible": key.backup_eligible,
        "backup_state": key.backup_state,
        "discoverable": key.discoverable,
    }


def _options(options: WebAuthnOptions) -> Response:
    return json_response(
        {"public_key": options.public_key, "expires_at": options.expires_at.isoformat()}
    )


def _registration_error(exc: WebAuthnError | WebAuthnUnavailable) -> Response:
    """A signed-in user's refused registration, as a fixed message."""
    if isinstance(exc, WebAuthnUnavailable):
        return json_response({"detail": _UNAVAILABLE}, 409)
    if exc.reason is R.LIMIT_REACHED:
        return json_response({"detail": _LIMIT}, 409)
    if exc.reason is R.SSO_ONLY:
        return json_response({"detail": _SSO_ONLY}, 409)
    if exc.reason in (R.INACTIVE_USER, R.UNKNOWN_USER):
        return refusal()
    if exc.reason is R.NICKNAME:
        return json_response({"detail": _NICKNAME}, 400)
    return json_response({"detail": _NOT_ACCEPTED}, 400)


def _id(text: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(text)
    except ValueError:
        return None


def build_webauthn_router(identity: Identity) -> APIRouter:
    router = APIRouter(tags=["warden: sign-in"])
    trusted_proxies = tuple(identity.config.audit.trusted_proxies)

    def source(request: Request) -> SourceIp:
        return client_ip(request, trusted_proxies)

    async def principal_or_none(request: Request) -> Principal | None:
        """The bearer's principal; None without a bearer; refused if the bearer is bad."""
        token = bearer_token(request)
        if token is None:
            if request.headers.get("authorization") is not None:
                raise AuthenticationRefused("malformed_authorization")
            return None
        return await identity.authenticate(token)

    async def signed_in(request: Request) -> Principal | None:
        try:
            return await principal_or_none(request)
        except AuthenticationRefused:
            return None

    # The second factor at sign-in.

    @router.post(
        "/webauthn/verify/options",
        summary="Begin completing sign-in with a security key or passkey",
        description=(
            "Sends the `mfa_required` challenge; answers with the options for "
            "`navigator.credentials.get()`, listing only the user's own credentials. User "
            "verification is preferred, not required. A user without a key, like every other "
            "failure, gets the uniform refusal."
        ),
        responses={
            200: {"model": WardenWebAuthnOptions, "description": "The browser's options."},
            **REFUSED,
        },
        openapi_extra=json_body(WebAuthnVerifyOptionsBody),
    )
    async def verify_options(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            options = await identity.begin_webauthn_sign_in(
                body.get("challenge"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        return _options(options)

    @router.post(
        "/webauthn/verify",
        summary="Complete sign-in with a security key or passkey",
        description=(
            "Sends the `mfa_required` challenge with the browser's answer to "
            '`navigator.credentials.get()`. The session\'s `amr` is `["pwd", "hwk"]`. Each '
            "options' challenge is accepted once; a refused answer counts as a wrong code "
            "does, and too many end the challenge."
        ),
        responses={200: {"model": WardenSignedIn, "description": "Signed in."}, **REFUSED},
        openapi_extra=json_body(WebAuthnVerifyBody),
    )
    async def verify(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.verify_webauthn(
                body.get("challenge"), body.get("credential"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        return json_response(token_body(pair))

    # Registration as a second factor.

    @router.post(
        "/webauthn/registration",
        summary="Begin registering a security key or passkey as a second factor",
        description=(
            "Under an access token (bearer) for a signed-in user, or under an "
            "`mfa_enrolment_required` challenge during a forced enrolment. Answers with the "
            "options for `navigator.credentials.create()`: resident key and user verification "
            "preferred, and the user's existing credentials excluded."
        ),
        responses={
            200: {"model": WardenWebAuthnOptions, "description": "The browser's options."},
            409: detail(
                "WebAuthn is not configured, the user has as many credentials as allowed, or "
                "the user signs in only through single sign-on.",
                _UNAVAILABLE,
                _LIMIT,
                _SSO_ONLY,
            ),
            **REFUSED,
        },
        openapi_extra=json_body(EnrolmentBody, required=False),
    )
    async def begin_registration(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            principal = await principal_or_none(request)
            options = await identity.begin_webauthn_registration(
                challenge=body.get("challenge"), principal=principal, source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        except (WebAuthnError, WebAuthnUnavailable) as exc:
            return _registration_error(exc)
        return _options(options)

    @router.post(
        "/webauthn/registration/confirm",
        summary="Register a security key or passkey with the browser's answer",
        description=(
            "Sends the browser's answer to `navigator.credentials.create()` and an optional "
            "nickname. Answers with the credential and, when it is the user's first second "
            "factor, fresh recovery codes, shown once (otherwise an empty list). Under a "
            "challenge (a forced enrolment) the answer is also the new session, with `amr` "
            '`["pwd", "hwk"]`. A refused answer from a signed-in user is a 400, so a '
            "client does not take it for a sign-out."
        ),
        responses={
            200: {
                "model": WardenWebAuthnRegistrationConfirmed,
                "description": "Registered; with a session under a challenge.",
            },
            400: detail("The answer or the nickname was not accepted.", _NOT_ACCEPTED, _NICKNAME),
            409: detail(
                "WebAuthn is not configured, the user has as many credentials as allowed, or "
                "the user signs in only through single sign-on.",
                _UNAVAILABLE,
                _LIMIT,
                _SSO_ONLY,
            ),
            **REFUSED,
        },
        openapi_extra=json_body(WebAuthnRegistrationConfirmBody),
    )
    async def confirm_registration(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            principal = await principal_or_none(request)
            enrolled = await identity.finish_webauthn_registration(
                body.get("credential"),
                nickname=body.get("nickname"),
                challenge=body.get("challenge"),
                principal=principal,
                source_ip=source(request),
            )
        except AuthenticationRefused:
            return refusal()
        except (WebAuthnError, WebAuthnUnavailable) as exc:
            return _registration_error(exc)
        credential = _credential(enrolled.credential)
        if enrolled.tokens is None:
            return json_response(
                {"credential": credential, "recovery_codes": enrolled.recovery_codes}
            )
        return json_response(
            token_body(
                enrolled.tokens, recovery_codes=enrolled.recovery_codes, credential=credential
            )
        )

    # The signed-in user's own credentials.

    @router.get(
        "/webauthn/credentials",
        summary="List the signed-in user's security keys and passkeys",
        description="Needs an access token as the bearer token. Never shows a public key.",
        responses={
            200: {"model": WardenWebAuthnCredentialList, "description": "Oldest first."},
            **REFUSED,
        },
    )
    async def list_credentials(request: Request) -> Response:
        principal = await signed_in(request)
        if principal is None:
            return refusal()
        keys = await identity.list_webauthn(principal)
        return json_response({"credentials": [_credential(k) for k in keys]})

    @router.patch(
        "/webauthn/credentials/{credential_id}",
        summary="Rename one of the signed-in user's security keys or passkeys",
        description=(
            "Needs an access token as the bearer token. `nickname` null clears it. Another "
            "user's credential, or anything but a UUID, is a 404."
        ),
        responses={
            200: {"model": WardenWebAuthnCredentialEnvelope, "description": "Renamed."},
            400: detail("The nickname is not valid.", _NICKNAME),
            404: detail("The user holds no such credential.", _NOT_FOUND),
            **REFUSED,
        },
        openapi_extra=json_body(WebAuthnRenameBody),
    )
    async def rename_credential(credential_id: str, request: Request) -> Response:
        principal = await signed_in(request)
        if principal is None:
            return refusal()
        body = await read_object(request)
        cid = _id(credential_id)
        if cid is None:
            return json_response({"detail": _NOT_FOUND}, 404)
        if body is None or "nickname" not in body:
            return json_response({"detail": _NICKNAME}, 400)
        try:
            renamed = await identity.rename_webauthn(
                principal, cid, body["nickname"], source_ip=source(request)
            )
        except WebAuthnError:
            return json_response({"detail": _NICKNAME}, 400)
        if renamed is None:
            return json_response({"detail": _NOT_FOUND}, 404)
        return json_response({"credential": _credential(renamed)})

    @router.delete(
        "/webauthn/credentials/{credential_id}",
        status_code=204,
        summary="Remove one of the signed-in user's security keys or passkeys",
        description=(
            "Needs an access token as the bearer token. Refused with a 409 when it is the "
            "user's last second factor and the session policy requires one; where none is "
            "required, removing the last factor removes the recovery codes too. Another "
            "user's credential, or anything but a UUID, is a 404."
        ),
        responses={
            204: {"description": "Removed.", "headers": no_store()},
            404: detail("The user holds no such credential.", _NOT_FOUND),
            409: detail("It is the user's last second factor.", _LAST_FACTOR),
            **REFUSED,
        },
    )
    async def remove_credential(credential_id: str, request: Request) -> Response:
        principal = await signed_in(request)
        if principal is None:
            return refusal()
        cid = _id(credential_id)
        if cid is None:
            return json_response({"detail": _NOT_FOUND}, 404)
        try:
            removed = await identity.remove_webauthn(principal, cid, source_ip=source(request))
        except LastSecondFactorError:
            return json_response({"detail": _LAST_FACTOR}, 409)
        if not removed:
            return json_response({"detail": _NOT_FOUND}, 404)
        return Response(status_code=204, headers={"cache-control": "no-store"})

    return router
