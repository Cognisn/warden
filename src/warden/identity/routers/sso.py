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
from warden.identity.routers.contract import (
    REFUSED,
    HandoffBody,
    SsoInvitationBody,
    WardenSignedIn,
    json_body,
    no_store,
)

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


_STRING = {"type": "string"}
_LOCATION = {"description": "Where the browser goes next.", "schema": _STRING}
_SET_COOKIE = {
    "description": (
        f"`{COOKIE_NAME}`, the login binding: HttpOnly, Secure, SameSite=Lax, path "
        "`<auth prefix>/sso`, for `sso.login_transaction_ttl_seconds`."
    ),
    "schema": _STRING,
}
_REFERRER = {"description": "`no-referrer`.", "schema": _STRING}
_TO_PROVIDER = {
    "location": {"description": "The provider's authorisation endpoint.", "schema": _STRING},
    "set-cookie": _SET_COOKIE,
    "referrer-policy": _REFERRER,
    **no_store(),
}
_LANDING = {"location": _LOCATION, "referrer-policy": _REFERRER, **no_store()}
_NO_LANDING = {
    "description": (
        "A failure while `http.sso_completion_link` is not configured: the fixed failure "
        "message as plain text."
    ),
    "content": {"text/plain": {"schema": _STRING, "example": SSO_FAILURE_MESSAGE}},
}
_FAILURE = (
    " Every failure lands the browser on `http.sso_completion_link` with `?error=sso_failed` "
    "and nothing else, clearing the cookie; show `SSO_FAILURE_MESSAGE`. The reason is "
    "recorded only in the audit trail (`warden.identity.sso.sign_in`)."
)
_COOKIE_PARAMETER = {
    "name": COOKIE_NAME,
    "in": "cookie",
    "required": True,
    "description": "The login binding set by `/sso/start`; the browser sends it.",
    "schema": _STRING,
}


def _query(name: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "in": "query",
        "required": False,
        "description": description,
        "schema": _STRING,
    }


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

    @router.get(
        "/sso/start",
        status_code=302,
        response_class=Response,
        summary="Begin single sign-on",
        description=(
            "A top-level browser navigation. Stores a login transaction (PKCE S256, state and "
            "nonce), sets the login binding cookie and redirects to the identity provider."
            + _FAILURE
        ),
        responses={
            302: {
                "description": "To the provider; on failure, to the completion link.",
                "headers": _TO_PROVIDER,
            },
            400: _NO_LANDING,
        },
    )
    async def start(request: Request) -> Response:
        try:
            begun = await identity.sso.begin(source_ip=source(request))
        except SsoError:
            return failed()
        return to_provider(begun, 302)

    @router.post(
        "/sso/start",
        status_code=303,
        response_class=Response,
        summary="Accept an invitation through single sign-on",
        description=(
            "The product's accept-invitation screen submits the link's token as `invitation`, "
            "a urlencoded form (a top-level form submission) or a JSON object, chosen by "
            "`Content-Type`, so the token appears in no URL. The token is sealed into the "
            "login transaction to this browser's binding. At the callback the verified "
            "identity accepts the invitation (it must be the invited address), and the browser "
            "lands like any sign-in. Any other content type, or a missing, repeated or "
            "malformed `invitation`, is a failure." + _FAILURE
        ),
        responses={
            303: {
                "description": (
                    "To the provider (the browser follows with GET); on failure, a 302 to "
                    "the completion link."
                ),
                "headers": _TO_PROVIDER,
            },
            400: _NO_LANDING,
        },
        openapi_extra=json_body(SsoInvitationBody, also=("application/x-www-form-urlencoded",)),
    )
    async def start_with_invitation(request: Request) -> Response:
        token = await _body_field(request, "invitation")
        try:
            begun = await identity.sso.begin(source_ip=source(request), invitation=token)
        except SsoError:
            return failed()
        # 303: the browser follows a post to the provider with a GET.
        return to_provider(begun, 303)

    @router.get(
        "/sso/callback",
        status_code=302,
        response_class=Response,
        summary="The identity provider's redirect back",
        description=(
            "The redirect URI registered with the provider: `http.public_base_url` + "
            "`http.auth_prefix` + `/sso/callback`. Uses the login transaction up, redeems the "
            "code with the PKCE verifier, validates the id_token and matches a pre-provisioned "
            "active user, then lands the browser on `http.sso_completion_link` with only a "
            "one-time handoff code (`?code=`)." + _FAILURE
        ),
        responses={
            302: {
                "description": (
                    "To the completion link: `?code=` on success, `?error=sso_failed` on failure."
                ),
                "headers": _LANDING,
            },
            400: _NO_LANDING,
        },
        openapi_extra={
            "parameters": [
                _query("state", "From the provider."),
                _query("code", "From the provider."),
                _query("error", "From the provider, when it refused."),
                {**_COOKIE_PARAMETER, "required": False},
            ]
        },
    )
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

    @router.post(
        "/sso/handoff",
        summary="Exchange the handoff code for a session",
        description=(
            "The product's completion screen posts the `code` from its URL, from the same "
            "browser, so the login binding cookie goes with it. The code is single-use and "
            "expires after `sso.handoff_code_ttl_seconds`. The answer is the same body as "
            "password sign-in, and clears the cookie."
        ),
        responses={200: {"model": WardenSignedIn, "description": "Signed in."}, **REFUSED},
        openapi_extra={**json_body(HandoffBody), "parameters": [_COOKIE_PARAMETER]},
    )
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
