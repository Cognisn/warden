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

    @router.post("/invitations/accept")
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

    @router.post("/password-reset", status_code=202)
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

    @router.post("/password-reset/complete")
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
