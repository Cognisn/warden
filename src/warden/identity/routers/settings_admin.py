"""Administration routes for the instance sign-in settings and the session policy.

Included by ``build_admin_router`` and mounted with it under
``config.http.admin_prefix``. The instance settings and the session policy
are behind the product's ``settings`` permission (the user administration
permission unless the product names another); a user's method, its pending
change and the resend and cancel routes are behind the user administration
permission, as the route that sets a method is.

| Route | Body | Success |
|---|---|---|
| ``GET /sign-in-settings`` | | the default method and the allowed second factors |
| ``PUT /sign-in-settings`` | the default, the allowed factors | the settings, who moved |
| ``GET /users/{id}/sign-in-method`` | | ``{"user", "sign_in_method"}`` (+) |
| ``POST /users/{id}/sign-in-method/resend`` | | 202 |
| ``POST /users/{id}/sign-in-method/cancel`` | | ``{"user", "sign_in_method"}`` (+) |
| ``GET /session-policy`` | | ``{"policy", "defaults"}`` |
| ``PUT /session-policy`` | the four lifetimes | ``{"policy", "defaults"}`` |
| ``POST /session-policy/reset`` | | ``{"policy", "defaults"}`` |

(+) With ``has_passkey`` as well when the method is, or is moving to, ``passkey_only``.
Every refusal of a sign-in change answers ``{"detail", "reason"}``.
"""

# No ``from __future__ import annotations``: FastAPI must resolve the ``Annotated``
# dependency aliases at definition time.

import dataclasses
import uuid
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from warden.identity.dependencies import Principal, require_permission
from warden.identity.http import SourceIp, client_ip, json_response, read_object
from warden.identity.mail import MailDeliveryError
from warden.identity.policy import PolicyError, SessionPolicy
from warden.identity.routers.contract import (
    FORBIDDEN,
    REFUSED,
    SessionPolicyBody,
    SignInSettingsBody,
    WardenChangeRefused,
    WardenLinkResent,
    WardenSessionPolicy,
    WardenSignInMethodSet,
    WardenSignInSettings,
    WardenSignInSettingsChanged,
    detail,
    json_body,
    no_store,
)
from warden.identity.routers.views import iso, method_state, settings_body, user_body
from warden.identity.sign_in_settings import (
    SignInMethodChangeRefused,
    SignInMethodState,
    SignInSettingsError,
)
from warden.identity.users import SignInMethod, UserError

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_settings_admin_router"]

_SETTINGS_FIELDS = frozenset({"default_sign_in_method", "allowed_second_factors"})
_POLICY_FIELDS = frozenset(
    {
        "access_token_ttl_seconds",
        "refresh_token_ttl_seconds",
        "session_lifespan_seconds",
        "refresh_reuse_grace_seconds",
        "require_mfa",
    }
)
_INVALID = "the request is not valid"
_NOT_FOUND = "not found"
_UNDELIVERED = "the message could not be delivered"


def _detail(message: str, status_code: int) -> Response:
    return json_response({"detail": message}, status_code)


def _refused(exc: SignInMethodChangeRefused) -> Response:
    return json_response({"detail": str(exc), "reason": exc.reason}, 409)


def _id(text: object) -> uuid.UUID | None:
    if not isinstance(text, str) or len(text) != 36:
        return None
    try:
        return uuid.UUID(text)
    except ValueError:
        return None


def _policy_body(policy: SessionPolicy) -> dict[str, Any]:
    return dataclasses.asdict(policy)


def build_settings_admin_router(identity: "Identity", *, users: str, settings: str) -> APIRouter:
    """The routes; ``users`` guards the per-user ones and ``settings`` the instance-wide ones."""
    router = APIRouter(tags=["warden: administration"])
    trusted_proxies = tuple(identity.config.audit.trusted_proxies)

    def source(request: Request) -> SourceIp:
        return client_ip(request, trusted_proxies)

    users_admin = require_permission(users)
    settings_admin = require_permission(settings)

    async def method_answer(user_id: uuid.UUID, state: SignInMethodState) -> Response:
        user = await identity.users.get(user_id)
        if user is None:
            return _detail(_NOT_FOUND, 404)
        answer: dict[str, Any] = {"user": user_body(user), "sign_in_method": method_state(state)}
        target = state.effective if state.pending is None else state.pending.to_method
        if target is SignInMethod.PASSKEY_ONLY:
            answer["has_passkey"] = await identity.users.holds_passkey(user.id)
        return json_response(answer)

    # The instance sign-in settings

    @router.get(
        "/sign-in-settings",
        summary="Show the instance sign-in settings",
        description=(
            "The default sign-in method every user without one of their own follows, and the "
            "second factors the administrator allows (`totp`, `passkey` or both, never empty). "
            "Behind the settings permission."
        ),
        responses={
            200: {
                "model": WardenSignInSettings,
                "description": "The settings.",
                "headers": no_store(),
            },
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def get_sign_in_settings(
        principal: Annotated[Principal, Depends(settings_admin)],
    ) -> Response:
        return json_response(settings_body(await identity.sign_in_settings()))

    @router.put(
        "/sign-in-settings",
        summary="Change the instance sign-in settings",
        description=(
            "Only the fields given change. A new `default_sign_in_method` moves every user who "
            "follows it: at once for those holding its credential, otherwise as a pending "
            "change with a set-up link mailed (`changed`, `pending` and `links_failed` list "
            "the users, so each failed delivery can be resent with `POST "
            "/users/{user_id}/sign-in-method/resend`). `allowed_second_factors` may not be "
            "emptied. Refused (409) with a `reason`: `sso_not_configured` for `sso_only` while "
            "single sign-on is not set up, `webauthn` for passkeys alone without WebAuthn, or "
            "the set-up link that cannot be sent (`mail_sender`, `passkey_registration_link`, "
            "`reset_password_link`). Nothing changes when refused. Every change is audited "
            "with the client address. Behind the settings permission."
        ),
        responses={
            200: {
                "model": WardenSignInSettingsChanged,
                "description": "The new settings and who the change reached.",
                "headers": no_store(),
            },
            400: detail(
                "Not a JSON object with a known field, or a value that is not valid.",
                _INVALID,
                "invalid settings: allowed_second_factors",
            ),
            409: {
                "model": WardenChangeRefused,
                "description": "The change cannot be made now; `reason` says why.",
                "headers": no_store(),
            },
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(SignInSettingsBody),
    )
    async def put_sign_in_settings(
        request: Request, principal: Annotated[Principal, Depends(settings_admin)]
    ) -> Response:
        body = await read_object(request)
        if body is None or not body or not set(body) <= _SETTINGS_FIELDS:
            return _detail(_INVALID, 400)
        try:
            change = await identity.update_sign_in_settings(
                actor=str(principal.user_id), source_ip=source(request), **body
            )
        except SignInSettingsError as exc:
            return _detail(str(exc), 400)
        except SignInMethodChangeRefused as exc:
            return _refused(exc)
        return json_response(
            {
                "settings": settings_body(change.settings),
                "changed": [str(u) for u in change.changed],
                "pending": [str(u) for u in change.pending],
                "links_failed": [str(u) for u in change.links_failed],
            }
        )

    # A user's method and its pending change

    @router.get(
        "/users/{user_id}/sign-in-method",
        summary="Show a user's sign-in method",
        description=(
            "The user's own setting (null when they follow the instance default), the "
            "method in force and any pending change, with the set-up link that completes "
            "it and when it was mailed. `has_passkey` as well when the method is, or is "
            "moving to, `passkey_only`."
        ),
        responses={
            200: {
                "model": WardenSignInMethodSet,
                "description": "The user and their method.",
                "headers": no_store(),
            },
            404: detail("No such user.", _NOT_FOUND),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def get_user_method(
        user_id: str, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _detail(_NOT_FOUND, 404)
        try:
            state = await identity.sign_in_method(uid)
        except UserError:
            return _detail(_NOT_FOUND, 404)
        return await method_answer(uid, state)

    @router.post(
        "/users/{user_id}/sign-in-method/resend",
        status_code=202,
        summary="Send a pending change's set-up link again",
        description=(
            "Mails a fresh link at once and stops the earlier one working. Refused (409) "
            "with a `reason`: `not_pending`, `no_link` (a move to `sso_only` completes at "
            "the first single sign-on and has no link), `user_inactive`, or the link that "
            "cannot be sent (`mail_sender`, `passkey_registration_link`, "
            "`reset_password_link`, `webauthn`). Audited with the client address."
        ),
        responses={
            202: {
                "model": WardenLinkResent,
                "description": "Sent.",
                "headers": no_store(),
            },
            404: detail("No such user.", _NOT_FOUND),
            409: {
                "model": WardenChangeRefused,
                "description": "A link cannot be sent; `reason` says why.",
                "headers": no_store(),
            },
            502: detail("The mail sender refused the message.", _UNDELIVERED),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def resend_link(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _detail(_NOT_FOUND, 404)
        try:
            expires_at = await identity.resend_sign_in_method_link(
                uid, actor=str(principal.user_id), source_ip=source(request)
            )
        except SignInMethodChangeRefused as exc:
            # Before UserError: a refusal is a kind of user error.
            return _refused(exc)
        except UserError:
            return _detail(_NOT_FOUND, 404)
        except MailDeliveryError:
            return _detail(_UNDELIVERED, 502)
        return json_response({"status": "sent", "expires_at": iso(expires_at)}, 202)

    @router.post(
        "/users/{user_id}/sign-in-method/cancel",
        summary="Cancel a pending sign-in method change",
        description=(
            "The user stays on the method in force, their own setting goes back to what "
            "it was before the change, and the set-up link stops working. Refused (409, "
            "`reason` `not_pending`) when no change is pending. Audited with the client "
            "address."
        ),
        responses={
            200: {
                "model": WardenSignInMethodSet,
                "description": "The user and their method.",
                "headers": no_store(),
            },
            404: detail("No such user.", _NOT_FOUND),
            409: {
                "model": WardenChangeRefused,
                "description": "No change is pending; `reason` is `not_pending`.",
                "headers": no_store(),
            },
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def cancel_change(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _detail(_NOT_FOUND, 404)
        try:
            state = await identity.cancel_sign_in_method_change(
                uid, actor=str(principal.user_id), source_ip=source(request)
            )
        except SignInMethodChangeRefused as exc:
            # Before UserError: a refusal is a kind of user error.
            return _refused(exc)
        except UserError:
            return _detail(_NOT_FOUND, 404)
        return await method_answer(uid, state)

    # The session policy (backlog item 2)

    async def policy_answer() -> Response:
        return json_response(
            {
                "policy": _policy_body(await identity.policy.current()),
                "defaults": _policy_body(identity.policy.defaults),
            }
        )

    @router.get(
        "/session-policy",
        summary="Show the session policy",
        description=(
            "The effective session policy (token lifetimes, the session lifespan and the "
            "refresh reuse grace, in seconds), and the configuration's own, which a reset "
            "returns to. `require_mfa` is deprecated and always true. Behind the settings "
            "permission."
        ),
        responses={
            200: {
                "model": WardenSessionPolicy,
                "description": "The policy and the defaults.",
                "headers": no_store(),
            },
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def get_session_policy(
        principal: Annotated[Principal, Depends(settings_admin)],
    ) -> Response:
        return await policy_answer()

    @router.put(
        "/session-policy",
        summary="Change the session policy",
        description=(
            "Only the fields given change, each an integer number of seconds, validated as a "
            "whole by the rules the configuration applies at start-up. Shortening the session "
            "lifespan applies to existing sessions too. `require_mfa` is not changeable: "
            "`false` is refused. Every replica sees the change as soon as it commits. Audited "
            "with the client address. Behind the settings permission."
        ),
        responses={
            200: {
                "model": WardenSessionPolicy,
                "description": "The new policy and the defaults.",
                "headers": no_store(),
            },
            400: detail(
                "Not a JSON object with a known field, or a value the rules refuse.",
                _INVALID,
                "access_token_ttl_seconds must be between 60 and 3600",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(SessionPolicyBody),
    )
    async def put_session_policy(
        request: Request, principal: Annotated[Principal, Depends(settings_admin)]
    ) -> Response:
        body = await read_object(request)
        if body is None or not body or not set(body) <= _POLICY_FIELDS:
            return _detail(_INVALID, 400)
        try:
            await identity.policy.update(
                actor=str(principal.user_id), source_ip=source(request), **body
            )
        except PolicyError as exc:
            return _detail(str(exc), 400)
        return await policy_answer()

    @router.post(
        "/session-policy/reset",
        summary="Drop the session policy overrides",
        description="Back to the configuration's policy. Audited with the client address.",
        responses={
            200: {
                "model": WardenSessionPolicy,
                "description": "The policy, now the defaults.",
                "headers": no_store(),
            },
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def reset_session_policy(
        request: Request, principal: Annotated[Principal, Depends(settings_admin)]
    ) -> Response:
        await identity.policy.reset(actor=str(principal.user_id), source_ip=source(request))
        return await policy_answer()

    return router
