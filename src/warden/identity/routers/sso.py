"""Single sign-on routes. The product mounts them under ``config.http.auth_prefix``,
alongside the sign-in routes.

| Route | Answer |
|---|---|
| ``GET /sso/start`` | 302 to the provider, setting the login cookie |
| ``POST /sso/start`` | form ``invitation``: 303 to the provider, setting both cookies |
| ``GET /sso/callback`` | 302 to ``http.sso_completion_link`` with ``?code=`` |
| ``POST /sso/handoff`` | body ``code``, with the cookie: the session's tokens |

``POST /sso/start`` is how an invitation link completes through single
sign-on: the product's accept-invitation screen submits a form (a top-level
navigation, ``application/x-www-form-urlencoded``) carrying the link's
token, so the token never appears in a URL warden sends. The browser holds
it in an HttpOnly cookie until the callback, which accepts the invitation
with the verified identity and lands like any sign-in; the handoff then
issues the new user's session.

Every failure in the browser leg lands on the completion link with
``?error=sso_failed`` and nothing else; the product shows
``SSO_FAILURE_MESSAGE``. A failed handoff gets the uniform 401 refusal. The
reason goes only to the audit trail, as ``warden.identity.sso.sign_in``.

The callback URI the provider must allow is derived:
``http.public_base_url`` + ``http.auth_prefix`` + ``/sso/callback``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Request
from fastapi.responses import Response

from warden.identity.errors import AuthenticationRefused
from warden.identity.http import NO_STORE, SourceIp, client_ip, json_response, read_object, refusal

# The same token body as password sign-in, so a client handles both alike.
from warden.identity.routers.auth import _tokens as tokens_body
from warden.identity.sso.errors import SsoError
from warden.identity.sso.service import (
    COOKIE_NAME,
    INVITATION_COOKIE_NAME,
    SSO_FAILURE_MESSAGE,
    LoginStart,
)

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_sso_router"]

_REDIRECT_HEADERS = {**NO_STORE, "referrer-policy": "no-referrer"}
_MAX_FORM = 4096


async def _form_field(request: Request, name: str) -> str:
    """One field of a small urlencoded form, or "" if absent, repeated or unreadable."""
    body = await request.body()
    if len(body) > _MAX_FORM:
        return ""
    try:
        fields = parse_qs(body.decode("ascii"), max_num_fields=8)
    except (UnicodeDecodeError, ValueError):
        return ""
    values = fields.get(name, [])
    return values[0] if len(values) == 1 else ""


def build_sso_router(identity: Identity) -> APIRouter:
    router = APIRouter(tags=["warden: single sign-on"])
    config = identity.config
    trusted_proxies = tuple(config.audit.trusted_proxies)
    cookie_path = f"{config.http.auth_prefix}/sso"

    def source(request: Request) -> SourceIp:
        return client_ip(request, trusted_proxies)

    def set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
        response.set_cookie(
            name,
            value,
            max_age=max_age,
            path=cookie_path,
            secure=True,
            httponly=True,
            samesite="lax",
        )

    def clear_cookie(response: Response, name: str) -> None:
        response.delete_cookie(name, path=cookie_path, secure=True, httponly=True)

    def land(**query: str) -> Response:
        target = config.http.render_link(config.http.sso_completion_link)
        separator = "&" if "?" in target else "?"
        response = Response(
            status_code=302,
            headers={"location": f"{target}{separator}{urlencode(query)}", **_REDIRECT_HEADERS},
        )
        clear_cookie(response, INVITATION_COOKIE_NAME)
        return response

    def failed() -> Response:
        if config.http.sso_completion_link is None:
            response = Response(
                content=SSO_FAILURE_MESSAGE,
                status_code=400,
                media_type="text/plain",
                headers=_REDIRECT_HEADERS,
            )
            clear_cookie(response, INVITATION_COOKIE_NAME)
            return response
        response = land(error="sso_failed")
        clear_cookie(response, COOKIE_NAME)
        return response

    def to_provider(begun: LoginStart, status_code: int) -> Response:
        response = Response(
            status_code=status_code,
            headers={"location": begun.redirect_url, **_REDIRECT_HEADERS},
        )
        set_cookie(response, COOKIE_NAME, begun.binding, begun.max_age)
        return response

    @router.get("/sso/start")
    async def start(request: Request) -> Response:
        try:
            begun = await identity.sso.begin(source_ip=source(request))
        except SsoError:
            return failed()
        response = to_provider(begun, 302)
        # A sign-in, not an acceptance: no earlier invitation rides along.
        clear_cookie(response, INVITATION_COOKIE_NAME)
        return response

    @router.post("/sso/start")
    async def start_with_invitation(request: Request) -> Response:
        token = await _form_field(request, "invitation")
        try:
            begun = await identity.sso.begin(source_ip=source(request), invitation=token)
        except SsoError:
            return failed()
        # 303: the browser follows a form post to the provider with a GET.
        response = to_provider(begun, 303)
        set_cookie(response, INVITATION_COOKIE_NAME, token, begun.max_age)
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
                invitation=request.cookies.get(INVITATION_COOKIE_NAME),
                invitations=identity.invitations,
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
        clear_cookie(response, COOKIE_NAME)
        return response

    return router
