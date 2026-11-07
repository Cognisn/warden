"""Public lifecycle routes. The product mounts them under ``config.http.auth_prefix``.

| Route | Body | Success |
|---|---|---|
| ``POST /invitations/accept`` | ``token``, ``password`` | 200 ``{"status": "accepted", "email"}`` |
| ``POST /invitations/accept/passkey/options`` | ``token`` | options |
| ``POST /invitations/accept/passkey`` | ``token``, ``credential`` (+) | 200 (*) |
| ``POST /password-reset`` | ``email`` | 202 ``{"status": "requested"}``, always |
| ``POST /password-reset/complete`` | ``token``, ``new_password`` | 204 |
| ``POST /passkey-registration/options`` | ``token`` | options |
| ``POST /passkey-registration`` | ``token``, ``credential`` (+) | 200 (**) |

Options are ``{"public_key", "expires_at"}``. (+) And an optional
``nickname``. (*) ``{"status": "accepted", "email", "credential",
"recovery_codes"}``. (**) ``{"status": "registered", "credential",
"recovery_codes"}``. Neither signs the user in.

A bad, used or expired token gets the uniform 401 refusal, and the reason
goes to the audit trail. An unacceptable password is a 400 and leaves the
link usable; so is an answer that is not a passkey. An invitation accepted
the wrong way (a password for single sign-on or a passkey, a passkey for
a password) is a 409 and stays usable. A reset request is answered before
any of its work is done, identically for every address, so neither the
response nor its timing reveals whether an account exists.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import Response

from warden.identity.errors import AuthenticationRefused
from warden.identity.http import SourceIp, client_ip, json_response, read_object, refusal
from warden.identity.invitations import InvitationMismatch
from warden.identity.routers.contract import (
    REFUSED,
    InvitationAcceptBody,
    PasskeyRegistrationBody,
    PasskeyTokenBody,
    ResetCompleteBody,
    ResetRequestBody,
    WardenInvitationAccepted,
    WardenPasskeyInvitationAccepted,
    WardenPasskeyRegistered,
    WardenResetRequested,
    WardenWebAuthnOptions,
    detail,
    json_body,
    no_store,
)
from warden.identity.users import SignInMethod, UserError
from warden.identity.webauthn import WebAuthnCredential, WebAuthnError, WebAuthnOptions
from warden.identity.webauthn import WebAuthnRefusal as R

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_lifecycle_router"]

logger = logging.getLogger(__name__)

_USE_SSO = "use single sign-on to accept this invitation"
_USE_PASSKEY = "use a passkey to accept this invitation"
_USE_PASSWORD = "accept this invitation with a password"  # noqa: S105 - a message
_HOW = {
    SignInMethod.SSO_ONLY: _USE_SSO,
    SignInMethod.PASSKEY_ONLY: _USE_PASSKEY,
    SignInMethod.PASSWORD_AND_SSO: _USE_PASSWORD,
}
_NOT_ACCEPTED = "credential not accepted"
_NICKNAME = "the nickname is not valid"
_LIMIT = "the credential limit is reached"


def _mismatch(exc: InvitationMismatch) -> Response:
    message = _HOW.get(exc.sign_in_method, _USE_SSO) if exc.sign_in_method else _USE_SSO
    return json_response({"detail": message}, 409)


def _options(options: WebAuthnOptions) -> Response:
    return json_response(
        {"public_key": options.public_key, "expires_at": options.expires_at.isoformat()}
    )


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
        "passkey": key.passkey,
    }


def _ceremony_error(exc: WebAuthnError) -> Response:
    """An answer that was not accepted, as a fixed message; the link stays usable."""
    if exc.reason is R.LIMIT_REACHED:
        return json_response({"detail": _LIMIT}, 409)
    if exc.reason is R.NICKNAME:
        return json_response({"detail": _NICKNAME}, 400)
    return json_response({"detail": _NOT_ACCEPTED}, 400)


def build_lifecycle_router(identity: Identity) -> APIRouter:
    router = APIRouter(tags=["warden: invitations and password reset"])
    trusted_proxies = tuple(identity.config.audit.trusted_proxies)
    minimum = identity.config.identity.password_min_length

    def source(request: Request) -> SourceIp:
        return client_ip(request, trusted_proxies)

    def weak() -> Response:
        return json_response({"detail": f"the password must be at least {minimum} characters"}, 400)

    @router.post(
        "/invitations/accept",
        summary="Accept an invitation with a password",
        description=(
            "Sets the password, activates the user and applies the staged roles, using the "
            "link up. It does not sign the user in: sign in next. A bad, used or expired token, "
            "or a user who is no longer invited (which uses the link up), gets the uniform "
            "refusal. A password that is too short is a 400, and an invitation that must be "
            "accepted through single sign-on or with a passkey is a 409; both leave the link "
            "usable."
        ),
        responses={
            200: {"model": WardenInvitationAccepted, "description": "Accepted."},
            400: detail(
                "The password is too short.", "the password must be at least 12 characters"
            ),
            409: detail(
                "This invitation is accepted through single sign-on (`POST /sso/start`) or with "
                "a passkey (`POST /invitations/accept/passkey/options`).",
                _USE_SSO,
                _USE_PASSKEY,
            ),
            **REFUSED,
        },
        openapi_extra=json_body(InvitationAcceptBody),
    )
    async def accept_invitation(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            accepted = await identity.invitations.accept_with_password(
                body.get("token"), body.get("password"), source_ip=source(request)
            )
        except UserError:
            return weak()
        except InvitationMismatch as exc:
            return _mismatch(exc)
        except AuthenticationRefused:
            return refusal()
        return json_response({"status": "accepted", "email": accepted.email})

    @router.post(
        "/invitations/accept/passkey/options",
        summary="Begin accepting an invitation with a passkey",
        description=(
            "For a `passkey_only` invitation. Answers with the options for "
            "`navigator.credentials.create()`: resident key and user verification required. "
            "The link stays usable. A bad, used or expired token, or a user who is no longer "
            "invited, gets the uniform refusal; an invitation accepted with a password or "
            "through single sign-on is a 409."
        ),
        responses={
            200: {"model": WardenWebAuthnOptions, "description": "The browser's options."},
            409: detail("This invitation is accepted another way.", _USE_PASSWORD, _USE_SSO),
            **REFUSED,
        },
        openapi_extra=json_body(PasskeyTokenBody),
    )
    async def passkey_invitation_options(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            options = await identity.begin_passkey_invitation(
                body.get("token"), source_ip=source(request)
            )
        except InvitationMismatch as exc:
            return _mismatch(exc)
        except AuthenticationRefused:
            return refusal()
        except WebAuthnError as exc:
            return _ceremony_error(exc)
        return _options(options)

    @router.post(
        "/invitations/accept/passkey",
        summary="Accept an invitation by registering a passkey",
        description=(
            "Sends the browser's answer to `navigator.credentials.create()` for options from "
            "`/invitations/accept/passkey/options`, and an optional nickname. Registers the "
            "passkey, activates the user, applies the staged roles and uses the link up, in one "
            "transaction. Answers with the passkey and fresh recovery codes, shown once. It "
            "does not sign the user in: sign in with the passkey next "
            "(`POST /passkey/options`). An answer that is not a passkey is a 400 and leaves the "
            "link usable; so is an invitation accepted another way (409). A bad, used or "
            "expired token, or a user who is no longer invited (which uses the link up), gets "
            "the uniform refusal."
        ),
        responses={
            200: {"model": WardenPasskeyInvitationAccepted, "description": "Accepted."},
            400: detail("The answer or the nickname was not accepted.", _NOT_ACCEPTED, _NICKNAME),
            409: detail("This invitation is accepted another way.", _USE_PASSWORD, _USE_SSO),
            **REFUSED,
        },
        openapi_extra=json_body(PasskeyRegistrationBody),
    )
    async def passkey_invitation_accept(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            accepted = await identity.accept_invitation_with_passkey(
                body.get("token"),
                body.get("credential"),
                nickname=body.get("nickname"),
                source_ip=source(request),
            )
        except InvitationMismatch as exc:
            return _mismatch(exc)
        except AuthenticationRefused:
            return refusal()
        except WebAuthnError as exc:
            return _ceremony_error(exc)
        return json_response(
            {
                "status": "accepted",
                "email": accepted.invitation.email,
                "credential": _credential(accepted.credential),
                "recovery_codes": accepted.recovery_codes,
            }
        )

    @router.post(
        "/passkey-registration/options",
        summary="Begin registering a passkey from an administrator's link",
        description=(
            "Sends the token from the link an administrator mailed "
            "(`POST /users/{user_id}/passkey-registration` under the admin prefix). Answers "
            "with the options for `navigator.credentials.create()`: resident key and user "
            "verification required. The link stays usable. A bad, used or expired token, or a "
            "user who is no longer active or is now `sso_only`, gets the uniform refusal."
        ),
        responses={
            200: {"model": WardenWebAuthnOptions, "description": "The browser's options."},
            409: detail("The user holds as many credentials as allowed.", _LIMIT),
            **REFUSED,
        },
        openapi_extra=json_body(PasskeyTokenBody),
    )
    async def passkey_registration_options(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            options = await identity.begin_passkey_registration(
                body.get("token"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        except WebAuthnError as exc:
            return _ceremony_error(exc)
        return _options(options)

    @router.post(
        "/passkey-registration",
        summary="Register a passkey from an administrator's link",
        description=(
            "Sends the browser's answer to `navigator.credentials.create()` for options from "
            "`/passkey-registration/options`, and an optional nickname. Registers the passkey "
            "and uses the link up, in one transaction, and answers with it and, when the user "
            "held no recovery codes, fresh ones, shown once (otherwise an empty list). It does "
            "not sign the user in: sign in with the passkey next (`POST /passkey/options`). An "
            "answer that is not a passkey is a 400 and leaves the link usable. A bad, used or "
            "expired token, or a user who is no longer active or is now `sso_only` (which "
            "uses the link up), gets the uniform refusal."
        ),
        responses={
            200: {"model": WardenPasskeyRegistered, "description": "Registered."},
            400: detail("The answer or the nickname was not accepted.", _NOT_ACCEPTED, _NICKNAME),
            409: detail("The user holds as many credentials as allowed.", _LIMIT),
            **REFUSED,
        },
        openapi_extra=json_body(PasskeyRegistrationBody),
    )
    async def passkey_registration(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            enrolled = await identity.finish_passkey_registration(
                body.get("token"),
                body.get("credential"),
                nickname=body.get("nickname"),
                source_ip=source(request),
            )
        except AuthenticationRefused:
            return refusal()
        except WebAuthnError as exc:
            return _ceremony_error(exc)
        return json_response(
            {
                "status": "registered",
                "credential": _credential(enrolled.credential),
                "recovery_codes": enrolled.recovery_codes,
            }
        )

    @router.post(
        "/password-reset",
        status_code=202,
        summary="Request a password reset link",
        description=(
            "Always 202, answered before any work is done, identically for every address, so "
            "neither the answer nor its timing reveals whether an account exists. A link is "
            "mailed only to an active user who signs in with a password; earlier links stop "
            "working."
        ),
        responses={
            202: {
                "model": WardenResetRequested,
                "description": "Accepted for processing.",
                "headers": no_store(),
            },
        },
        openapi_extra=json_body(ResetRequestBody),
    )
    async def request_reset(request: Request, background: BackgroundTasks) -> Response:
        body = await read_object(request) or {}
        email, address = body.get("email"), source(request)

        async def work() -> None:
            try:
                await identity.resets.request(email, source_ip=address)
            except Exception as exc:
                # The type only; the outcome is already in the audit trail.
                logger.warning("password reset request failed (%s)", type(exc).__name__)

        background.add_task(work)
        return json_response({"status": "requested"}, 202)

    @router.post(
        "/password-reset/complete",
        status_code=204,
        summary="Set a new password from a reset link",
        description=(
            "Uses the link up and ends every session of the user. A bad, used or expired "
            "token, or a user who has since become inactive or `sso_only` (which uses the link "
            "up), gets the uniform refusal. A password that is too short is a 400 and leaves "
            "the link usable."
        ),
        responses={
            204: {"description": "The password is set.", "headers": no_store()},
            400: detail(
                "The password is too short.", "the password must be at least 12 characters"
            ),
            **REFUSED,
        },
        openapi_extra=json_body(ResetCompleteBody),
    )
    async def complete_reset(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            await identity.resets.complete(
                body.get("token"), body.get("new_password"), source_ip=source(request)
            )
        except UserError:
            return weak()
        except AuthenticationRefused:
            return refusal()
        return Response(status_code=204, headers={"cache-control": "no-store"})

    return router
