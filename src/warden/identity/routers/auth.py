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
"expires_in"}``. Every authentication failure is the same 401 response.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import Response

from warden.identity.dependencies import Principal, bearer_token
from warden.identity.errors import AuthenticationRefused, MfaError
from warden.identity.http import SourceIp, client_ip, json_response, read_object, refusal
from warden.identity.tokens import TokenPair

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_auth_router"]

_CHALLENGE_STATUS = {"verify": "mfa_required", "enrol": "mfa_enrolment_required"}


def _tokens(pair: TokenPair, **extra: Any) -> dict[str, Any]:
    return {
        "status": "signed_in",
        "access_token": pair.access_token,
        "token_type": "Bearer",
        "expires_in": pair.expires_in,
        "refresh_token": pair.refresh_token,
        "refresh_expires_in": pair.refresh_expires_in,
        **extra,
    }


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

    @router.post("/sign-in")
    async def sign_in(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            result = await identity.sign_in(
                body.get("email"), body.get("password"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        if result.challenge is not None:
            return json_response(
                {
                    "status": _CHALLENGE_STATUS[result.challenge.purpose],
                    "challenge": result.challenge.token,
                    "expires_in": result.challenge.expires_in,
                }
            )
        if result.tokens is None:
            raise RuntimeError("sign-in produced neither tokens nor a challenge")
        return json_response(_tokens(result.tokens))

    @router.post("/totp/verify")
    async def totp_verify(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.verify_totp(
                body.get("challenge"), body.get("code"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        return json_response(_tokens(pair))

    @router.post("/recovery-code")
    async def recovery_code(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.use_recovery_code(
                body.get("challenge"), body.get("code"), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        return json_response(_tokens(pair))

    @router.post("/refresh")
    async def refresh(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.refresh(body.get("refresh_token"), source_ip=source(request))
        except AuthenticationRefused:
            return refusal()
        return json_response(_tokens(pair))

    @router.post("/sign-out")
    async def sign_out(request: Request) -> Response:
        try:
            principal = await principal_or_none(request)
        except AuthenticationRefused:
            return refusal()
        if principal is None:
            return refusal()
        await identity.sign_out(principal, source_ip=source(request))
        return Response(status_code=204, headers={"cache-control": "no-store"})

    @router.post("/password")
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

    @router.post("/totp/enrolment")
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

    @router.post("/totp/enrolment/confirm")
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
        return json_response(_tokens(pair, recovery_codes=codes))

    return router
