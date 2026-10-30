"""Public lifecycle routes. The product mounts them under ``config.http.auth_prefix``.

| Route | Body | Success |
|---|---|---|
| ``POST /invitations/accept`` | ``token``, ``password`` | 200 ``{"status": "accepted", "email"}`` |
| ``POST /password-reset`` | ``email`` | 202 ``{"status": "requested"}``, always |
| ``POST /password-reset/complete`` | ``token``, ``new_password`` | 204 |

A bad, used or expired token gets the uniform 401 refusal, and the reason
goes to the audit trail. An unacceptable password is a 400 and leaves the
link usable; so is a password offered for an invitation that must be
accepted through single sign-on (409). A reset request is answered before
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
    ResetCompleteBody,
    ResetRequestBody,
    WardenInvitationAccepted,
    WardenResetRequested,
    detail,
    json_body,
    no_store,
)
from warden.identity.users import UserError

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_lifecycle_router"]

logger = logging.getLogger(__name__)


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
            "refusal. A password that is too short is a 400 and an invitation that must be "
            "accepted through single sign-on is a 409; both leave the link usable."
        ),
        responses={
            200: {"model": WardenInvitationAccepted, "description": "Accepted."},
            400: detail(
                "The password is too short.", "the password must be at least 12 characters"
            ),
            409: detail(
                "This invitation is accepted through single sign-on (`POST /sso/start`).",
                "use single sign-on to accept this invitation",
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
        except InvitationMismatch:
            return json_response({"detail": "use single sign-on to accept this invitation"}, 409)
        except AuthenticationRefused:
            return refusal()
        return json_response({"status": "accepted", "email": accepted.email})

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
