"""Public sign-in routes. The product mounts them under ``config.http.auth_prefix``.

| Route | Body | Success |
|---|---|---|
| ``POST /sign-in`` | ``email``, ``password`` | tokens, or a challenge |
| ``POST /totp/verify`` | ``challenge``, ``code`` | tokens |
| ``POST /recovery-code`` | ``challenge``, ``code`` | tokens |
| ``POST /refresh`` | ``refresh_token`` | tokens |
| ``POST /sign-out`` | bearer token | 204 |
| ``POST /password`` | bearer token; ``current_password``, ``new_password`` | 204 |
| ``POST /totp/enrolment`` | bearer token, or ``challenge`` | ``secret``, ``uri`` |
| ``POST /totp/enrolment/confirm`` | bearer or ``challenge``; ``code`` | ``recovery_codes`` (*) |

(*) Under a challenge, the tokens as well.

Tokens are ``{"status": "signed_in", "access_token", "token_type": "Bearer",
"expires_in", "refresh_token", "refresh_expires_in"}``. A challenge is
``{"status": "mfa_required" | "mfa_enrolment_required", "challenge",
"expires_in"}``; ``mfa_required`` also carries ``methods``, the kinds of
second factor the user holds. Every authentication failure is the same 401
response. The security key and passkey routes (``/webauthn/...``) are in
``warden.identity.routers.webauthn`` and included here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import Response

from warden.identity.dependencies import Principal, bearer_token
from warden.identity.errors import AuthenticationRefused, MfaError
from warden.identity.http import SourceIp, client_ip, json_response, read_object, refusal
from warden.identity.routers.contract import (
    REFUSED,
    ChallengeBody,
    ChangePasswordBody,
    CodeBody,
    EnrolmentBody,
    EnrolmentConfirmBody,
    RefreshBody,
    SignInBody,
    WardenEnrolmentConfirmed,
    WardenSignedIn,
    WardenSignInAnswer,
    WardenTotpEnrolment,
    detail,
    json_body,
    no_store,
)
from warden.identity.routers.tokens import token_body
from warden.identity.routers.webauthn import build_webauthn_router

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_auth_router"]

_CHALLENGE_STATUS = {"verify": "mfa_required", "enrol": "mfa_enrolment_required"}


def build_auth_router(identity: Identity) -> APIRouter:
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

    @router.post(
        "/sign-in",
        summary="Sign in with an email address and password",
        description=(
            "Answers with a new session (`status` `signed_in`), or with a challenge when a "
            "second factor is needed: `mfa_required` (send a TOTP code to `/totp/verify`, a "
            "security key's answer to `/webauthn/verify`, or a recovery code to "
            "`/recovery-code`; `methods` lists the kinds the user holds) or "
            "`mfa_enrolment_required` (enrol through `/totp/enrolment` or "
            "`/webauthn/registration` under the challenge). An unknown address, a wrong "
            "password, an `sso_only` user, a user who is not active and a throttled attempt all "
            "get the uniform refusal, in the same time."
        ),
        responses={
            200: {"model": WardenSignInAnswer, "description": "Signed in, or challenged."},
            **REFUSED,
        },
        openapi_extra=json_body(SignInBody),
    )
    async def sign_in(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            result = await identity.sign_in(
                body.get("email"), body.get("password"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        if result.challenge is not None:
            answer: dict[str, object] = {
                "status": _CHALLENGE_STATUS[result.challenge.purpose],
                "challenge": result.challenge.token,
                "expires_in": result.challenge.expires_in,
            }
            if result.challenge.purpose == "verify":
                answer["methods"] = list(result.challenge.methods)
            return json_response(answer)
        if result.tokens is None:
            raise RuntimeError("sign-in produced neither tokens nor a challenge")
        return json_response(token_body(result.tokens))

    @router.post(
        "/totp/verify",
        summary="Complete sign-in with a TOTP code",
        description=(
            "Sends the `mfa_required` challenge with a six-digit code. A code is accepted at "
            "most once per time step; too many wrong codes end the challenge."
        ),
        responses={200: {"model": WardenSignedIn, "description": "Signed in."}, **REFUSED},
        openapi_extra=json_body(ChallengeBody),
    )
    async def totp_verify(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.verify_totp(
                body.get("challenge"), body.get("code"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        return json_response(token_body(pair))

    @router.post(
        "/recovery-code",
        summary="Complete sign-in with a recovery code",
        description=(
            "Sends the `mfa_required` challenge with one unused recovery code, which is used "
            "up, even under concurrent requests."
        ),
        responses={200: {"model": WardenSignedIn, "description": "Signed in."}, **REFUSED},
        openapi_extra=json_body(CodeBody),
    )
    async def recovery_code(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.use_recovery_code(
                body.get("challenge"), body.get("code"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        return json_response(token_body(pair))

    @router.post(
        "/refresh",
        summary="Exchange a refresh token for a new session pair",
        description=(
            "Refresh tokens rotate: each is single-use and the answer carries its replacement. "
            "Presenting a token that was already used ends its whole family (every token "
            "descended from the same sign-in), except that the immediate predecessor presented "
            "within the session policy's reuse grace window is refused without ending it. "
            "Refused for a user who is no longer active."
        ),
        responses={200: {"model": WardenSignedIn, "description": "A new pair."}, **REFUSED},
        openapi_extra=json_body(RefreshBody),
    )
    async def refresh(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.refresh(body.get("refresh_token"), source_ip=source(request))
        except AuthenticationRefused:
            return refusal()
        return json_response(token_body(pair))

    @router.post(
        "/sign-out",
        status_code=204,
        summary="End the current session",
        description="Needs an access token as the bearer token (not an API key).",
        responses={204: {"description": "Signed out.", "headers": no_store()}, **REFUSED},
    )
    async def sign_out(request: Request) -> Response:
        try:
            principal = await principal_or_none(request)
        except AuthenticationRefused:
            return refusal()
        if principal is None:
            return refusal()
        await identity.sign_out(principal, source_ip=source(request))
        return Response(status_code=204, headers={"cache-control": "no-store"})

    @router.post(
        "/password",
        status_code=204,
        summary="Change the signed-in user's password",
        description=(
            "Needs an access token as the bearer token. Ends the user's other sessions; the "
            "current one stays. A wrong current password, or a user without a password "
            "(`sso_only`), gets the fixed 400 message `password change refused`."
        ),
        responses={
            204: {"description": "Changed.", "headers": no_store()},
            400: detail(
                "Refused, or the new password is too short.",
                "password change refused",
                "the new password must be at least 12 characters",
            ),
            **REFUSED,
        },
        openapi_extra=json_body(ChangePasswordBody),
    )
    async def change_password(request: Request) -> Response:
        try:
            principal = await principal_or_none(request)
        except AuthenticationRefused:
            return refusal()
        if principal is None:
            return refusal()
        body = await read_object(request) or {}
        reason = await identity.change_password(
            principal,
            body.get("current_password"),
            body.get("new_password"),
            source_ip=source(request),
        )
        if reason == "weak_password":
            minimum = identity.config.identity.password_min_length
            return json_response(
                {"detail": f"the new password must be at least {minimum} characters"}, 400
            )
        if reason is not None:
            return json_response({"detail": "password change refused"}, 400)
        return Response(status_code=204, headers={"cache-control": "no-store"})

    @router.post(
        "/totp/enrolment",
        summary="Begin TOTP enrolment",
        description=(
            "Under an access token (bearer) for a signed-in user, or under an "
            "`mfa_enrolment_required` challenge during a forced enrolment. The enrolment counts "
            "as a second factor only once confirmed."
        ),
        responses={
            200: {"model": WardenTotpEnrolment, "description": "The secret to enrol."},
            409: detail("TOTP is already enrolled.", "TOTP is already enrolled"),
            **REFUSED,
        },
        openapi_extra=json_body(EnrolmentBody, required=False),
    )
    async def begin_enrolment(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            principal = await principal_or_none(request)
            enrolment = await identity.begin_enrolment(
                challenge=body.get("challenge"),
                principal=principal,
                source_ip=source(request),
            )
        except AuthenticationRefused:
            return refusal()
        except MfaError:
            return json_response({"detail": "TOTP is already enrolled"}, 409)
        return json_response({"secret": enrolment.secret_base32, "uri": enrolment.uri})

    @router.post(
        "/totp/enrolment/confirm",
        summary="Confirm TOTP enrolment with a first code",
        description=(
            "Answers with the recovery codes, shown once. Under a challenge (a forced "
            "enrolment) the answer is also the new session. A wrong code from a signed-in user "
            "is a 400, so a client does not take it for a sign-out."
        ),
        responses={
            200: {
                "model": WardenEnrolmentConfirmed,
                "description": "Confirmed: the recovery codes, with a session under a challenge.",
            },
            400: detail("The code was not accepted.", "code not accepted"),
            **REFUSED,
        },
        openapi_extra=json_body(EnrolmentConfirmBody),
    )
    async def confirm_enrolment(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            principal = await principal_or_none(request)
            codes, pair = await identity.confirm_enrolment(
                body.get("code"),
                challenge=body.get("challenge"),
                principal=principal,
                source_ip=source(request),
            )
        except AuthenticationRefused:
            return refusal()
        except MfaError:
            return json_response({"detail": "code not accepted"}, 400)
        if pair is None:
            return json_response({"recovery_codes": codes})
        return json_response(token_body(pair, recovery_codes=codes))

    router.include_router(build_webauthn_router(identity))
    return router
