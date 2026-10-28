"""Single sign-on routes. The product mounts them under ``config.http.auth_prefix``,
alongside the sign-in routes.

| Route | Answer |
|---|---|
| ``GET /sso/start`` | 302 to the provider, setting the login cookie |
| ``GET /sso/callback`` | 302 to ``http.sso_completion_link`` with ``?code=`` |
| ``POST /sso/handoff`` | body ``code``, with the cookie: the session's tokens |

Every failure in the browser leg lands on the completion link with
``?error=sso_failed`` and nothing else; the product shows
``SSO_FAILURE_MESSAGE``. A failed handoff gets the uniform 401 refusal. The
reason goes only to the audit trail, as ``warden.identity.sso.sign_in``.

The callback URI the provider must allow is derived:
``http.public_base_url`` + ``http.auth_prefix`` + ``/sso/callback``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import Response

from warden.identity.errors import AuthenticationRefused
from warden.identity.http import NO_STORE, SourceIp, client_ip, json_response, read_object, refusal

# The same token body as password sign-in, so a client handles both alike.
from warden.identity.routers.auth import _tokens as tokens_body
from warden.identity.sso.errors import SsoError
from warden.identity.sso.service import COOKIE_NAME, SSO_FAILURE_MESSAGE

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_sso_router"]

_REDIRECT_HEADERS = {**NO_STORE, "referrer-policy": "no-referrer"}


def build_sso_router(identity: Identity) -> APIRouter:
    router = APIRouter(tags=["warden: single sign-on"])
    config = identity.config
    trusted_proxies = tuple(config.audit.trusted_proxies)
    cookie_path = f"{config.http.auth_prefix}/sso"

    def source(request: Request) -> SourceIp:
        return client_ip(request, trusted_proxies)

    def land(**query: str) -> Response:
        target = config.http.render_link(config.http.sso_completion_link)
        separator = "&" if "?" in target else "?"
        return Response(
            status_code=302,
            headers={"location": f"{target}{separator}{urlencode(query)}", **_REDIRECT_HEADERS},
        )

    def failed() -> Response:
        if config.http.sso_completion_link is None:
            return Response(
                content=SSO_FAILURE_MESSAGE,
                status_code=400,
                media_type="text/plain",
                headers=_REDIRECT_HEADERS,
            )
        response = land(error="sso_failed")
        response.delete_cookie(COOKIE_NAME, path=cookie_path, secure=True, httponly=True)
        return response

    @router.get("/sso/start")
    async def start(request: Request) -> Response:
        try:
            begun = await identity.sso.begin(source_ip=source(request))
        except SsoError:
            return failed()
        response = Response(
            status_code=302, headers={"location": begun.redirect_url, **_REDIRECT_HEADERS}
        )
        response.set_cookie(
            COOKIE_NAME,
            begun.binding,
            max_age=begun.max_age,
            path=cookie_path,
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

    @router.get("/sso/callback")
    async def callback(request: Request) -> Response:
        params = request.query_params
        try:
            code = await identity.sso.complete(
                state=params.get("state"),
                code=params.get("code"),
                error=params.get("error"),
                binding=request.cookies.get(COOKIE_NAME),
                source_ip=source(request),
            )
        except SsoError:
            return failed()
        return land(code=code)

    @router.post("/sso/handoff")
    async def handoff(request: Request) -> Response:
        body = await read_object(request) or {}
        try:
            pair = await identity.sso.exchange(
                body.get("code"), request.cookies.get(COOKIE_NAME), source_ip=source(request)
            )
        except AuthenticationRefused:
            return refusal()
        response = json_response(tokens_body(pair))
        response.delete_cookie(COOKIE_NAME, path=cookie_path, secure=True, httponly=True)
        return response

    return router
