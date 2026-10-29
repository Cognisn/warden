"""Single sign-on routes. The product mounts them under ``config.http.auth_prefix``,
alongside the sign-in routes.

| Route | Answer |
|---|---|
| ``GET /sso/start`` | 302 to the provider, setting the login cookie |
| ``POST /sso/start`` | body ``invitation``: 303 to the provider, setting the login cookie |
| ``GET /sso/callback`` | 302 to ``http.sso_completion_link`` with ``?code=`` |
| ``POST /sso/handoff`` | body ``code``, with the cookie: the session's tokens |

``POST /sso/start`` is how an invitation link completes through single
sign-on: the product's accept-invitation screen posts the link's token in
the field ``invitation``, as a urlencoded form
(``application/x-www-form-urlencoded``, for example a top-level form
submission) or a JSON object (``application/json``), chosen by
``Content-Type``. Any other type, or a missing, repeated or malformed
``invitation``, lands on the fixed failure (``invitation_malformed``). The
token never appears in a URL warden sends. It is sealed into the login
transaction to the login cookie, so only this browser's callback can open
it; the callback then accepts the invitation with the verified identity and
lands like any sign-in, and the handoff issues the new user's session.

Every failure in the browser leg lands on the completion link with
``?error=sso_failed`` and nothing else; the product shows
``SSO_FAILURE_MESSAGE``. A failed handoff gets the uniform 401 refusal. The
reason goes only to the audit trail, as ``warden.identity.sso.sign_in``.

The callback URI the provider must allow is derived:
``http.public_base_url`` + ``http.auth_prefix`` + ``/sso/callback``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Request
from fastapi.responses import Response

from warden.identity.errors import AuthenticationRefused
from warden.identity.http import NO_STORE, SourceIp, client_ip, json_response, read_object, refusal

# The same token body as password sign-in, so a client handles both alike.
from warden.identity.routers.tokens import token_body
from warden.identity.sso.errors import SsoError
from warden.identity.sso.service import COOKIE_NAME, SSO_FAILURE_MESSAGE, LoginStart

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_sso_router"]

_REDIRECT_HEADERS = {**NO_STORE, "referrer-policy": "no-referrer"}
_MAX_BODY = 4096
_FORM = "application/x-www-form-urlencoded"
_JSON = "application/json"


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise ValueError("a repeated member")
    return dict(pairs)


async def _body_field(request: Request, name: str) -> str:
    """One field of a small urlencoded form or JSON object, chosen by ``Content-Type``.

    "" if the type is neither, or the field is absent, repeated, not a
    string, or the body cannot be read.
    """
    media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media_type not in (_FORM, _JSON):
        return ""
    body = await request.body()
    if len(body) > _MAX_BODY:
        return ""
    if media_type == _JSON:
        try:
            document = json.loads(body, object_pairs_hook=_unique_members)
        except (ValueError, RecursionError):
            return ""
        value = document.get(name) if isinstance(document, dict) else None
        return value if isinstance(value, str) else ""
    try:
        fields = parse_qs(
            body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=8
        )
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
        return to_provider(begun, 302)

    @router.post("/sso/start")
    async def start_with_invitation(request: Request) -> Response:
        token = await _body_field(request, "invitation")
        try:
            begun = await identity.sso.begin(source_ip=source(request), invitation=token)
        except SsoError:
            return failed()
        # 303: the browser follows a post to the provider with a GET.
        return to_provider(begun, 303)

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
        response = json_response(token_body(pair))
        clear_cookie(response, COOKIE_NAME)
        return response

    return router
