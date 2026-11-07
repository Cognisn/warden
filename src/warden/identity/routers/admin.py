"""Administration routes. The product mounts them under ``config.http.admin_prefix``.

Every route requires a permission the product names when it builds the
router (``identity.admin_router(permission=..., roles=..., invitations=...,
api_keys=...)``); warden hardcodes none. Every change is made through the
identity services, which audit it under ``warden.identity.*`` with the
administrator as actor. Request bodies are parsed here, never echoed back,
and every error is a fixed message.

| Route | Body | Success |
|---|---|---|
| ``GET /users[?status=&limit=&after=]`` | | ``{"users": [...]}`` (*) |
| ``GET /users/{id}`` | | ``{"user", "roles", "webauthn_credentials"}`` |
| ``POST /users/{id}/status`` | ``status`` | ``{"user"}`` |
| ``POST /users/{id}/sign-in-method`` | ``sign_in_method`` | ``{"user"}`` (+) |
| ``POST /users/{id}/password-reset`` | | 202 |
| ``POST /users/{id}/passkey-registration`` | | 202 |
| ``DELETE /users/{id}/totp`` | | 204 |
| ``DELETE /users/{id}/mfa`` | | 204 |
| ``GET /roles`` | | ``{"roles", "permissions"}`` |
| ``PUT /users/{id}/roles/{role}`` | ``expires_at`` (optional) | 204 |
| ``DELETE /users/{id}/roles/{role}`` | | 204 |
| ``GET /invitations`` | | ``{"invitations": [...]}`` |
| ``POST /invitations`` | ``email``, ``display_name``, ``sign_in_method``, ``roles`` (*) | 201 |
| ``POST /invitations/{id}/resend`` | | 200 |
| ``DELETE /invitations/{id}`` | | 204 |
| ``GET /api-keys[?user_id=]`` | | ``{"api_keys": [...]}`` |
| ``POST /api-keys`` | ``user_id``, ``name``, ``scopes``, ``expires_at`` (*) | 201, with the key |
| ``DELETE /api-keys/{id}`` | | 204 |

(*) ``display_name``, ``sign_in_method``, ``roles`` and ``expires_at`` are optional.
(+) With ``has_passkey`` as well when the method set is ``passkey_only``.
A user list paged with ``limit`` or ``after`` also carries ``next``.
Times are ISO 8601 with a zone offset. A new API key is returned once, never again.
"""

import re
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from warden.identity.apikeys import ApiKey, ApiKeyError
from warden.identity.dependencies import Principal, require_permission
from warden.identity.http import NO_STORE, SourceIp, client_ip, json_response, read_object
from warden.identity.invitations import InvitationError, PendingInvitation, StagedGrant
from warden.identity.mail import MailDeliveryError, MailError
from warden.identity.mfa import WebAuthnUnavailable
from warden.identity.roles import LastAdministratorError, RoleAssignment, RoleError
from warden.identity.routers.contract import (
    FORBIDDEN,
    REFUSED,
    InvitationCreateBody,
    NewApiKeyBody,
    RoleAssignBody,
    SignInMethodBody,
    StatusBody,
    WardenApiKeyList,
    WardenInvitationIssued,
    WardenInvitationList,
    WardenNewApiKeyIssued,
    WardenPasskeyLinkSent,
    WardenResetSent,
    WardenRoleList,
    WardenSignInMethodSet,
    WardenUserDetail,
    WardenUserEnvelope,
    WardenUserList,
    detail,
    json_body,
    no_store,
)
from warden.identity.service import PasskeyLinkNotConfigured, PasskeyLinkRefused
from warden.identity.users import (
    SignInMethod,
    SignInMethodConflict,
    User,
    UserError,
    UserStatus,
)

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_admin_router"]

_MAX_USER_PAGE = 1000
_PAGE_SIZE = re.compile(r"[1-9][0-9]{0,3}")


class _BadRequest(Exception):
    pass


_HOLDS_KEYS = "the user holds security keys or passkeys; reset their second factors first"
_NO_LINK = "a passkey registration link cannot be sent to this user"
_LINK_NOT_CONFIGURED = "the passkey registration link is not configured"
_UNAVAILABLE = "WebAuthn is not configured"


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat()


def _user(user: User) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "status": user.status.value,
        "sign_in_method": user.sign_in_method.value,
        "has_password": user.has_password,
        "created_at": _iso(user.created_at),
        "updated_at": _iso(user.updated_at),
    }


def _assignment(assignment: RoleAssignment) -> dict[str, Any]:
    return {
        "role": assignment.role,
        "granted_at": _iso(assignment.granted_at),
        "granted_by": assignment.granted_by,
        "expires_at": _iso(assignment.expires_at),
    }


def _grants(grants: tuple[StagedGrant, ...]) -> list[dict[str, Any]]:
    return [{"role": g.role, "expires_at": _iso(g.expires_at)} for g in grants]


def _invitation(pending: PendingInvitation) -> dict[str, Any]:
    return {
        "user": _user(pending.user),
        "expires_at": _iso(pending.expires_at),
        "roles": _grants(pending.grants),
    }


def _api_key(key: ApiKey) -> dict[str, Any]:
    return {
        "id": str(key.id),
        "user_id": str(key.user_id),
        "name": key.name,
        "hint": key.hint,
        "scopes": sorted(key.scopes),
        "created_at": _iso(key.created_at),
        "created_by": key.created_by,
        "expires_at": _iso(key.expires_at),
        "revoked_at": _iso(key.revoked_at),
        "last_used_at": _iso(key.last_used_at),
    }


def _id(text: object) -> uuid.UUID | None:
    if not isinstance(text, str) or len(text) != 36:
        return None
    try:
        return uuid.UUID(text)
    except ValueError:
        return None


def _when(value: object) -> datetime | None:
    """An optional zoned ISO 8601 time from a request body."""
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise _BadRequest
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise _BadRequest from None
    if moment.tzinfo is None:
        raise _BadRequest
    return moment


def _detail(message: str, status_code: int) -> Response:
    return json_response({"detail": message}, status_code)


def _not_found() -> Response:
    return _detail("not found", 404)


def _invalid() -> Response:
    return _detail("the request is not valid", 400)


def _no_content() -> Response:
    return Response(status_code=204, headers=NO_STORE)


def build_admin_router(
    identity: "Identity",
    *,
    users: str,
    roles: str | None = None,
    invitations: str | None = None,
    api_keys: str | None = None,
) -> APIRouter:
    """Routes for users, roles, invitations and API keys, each area behind one permission.

    ``roles``, ``invitations`` and ``api_keys`` default to ``users``. Each
    must be one of the product's registered permissions.
    """
    registered = identity.permissions.permissions()
    needed = {
        "users": users,
        "roles": roles or users,
        "invitations": invitations or users,
        "api_keys": api_keys or users,
    }
    for permission in needed.values():
        if permission not in registered:
            raise ValueError(f"admin permission {permission} is not registered")

    router = APIRouter(tags=["warden: administration"])
    trusted_proxies = tuple(identity.config.audit.trusted_proxies)

    def source(request: Request) -> SourceIp:
        return client_ip(request, trusted_proxies)

    users_admin = require_permission(needed["users"])
    roles_admin = require_permission(needed["roles"])
    invitations_admin = require_permission(needed["invitations"])
    keys_admin = require_permission(needed["api_keys"])

    # Users

    @router.get(
        "/users",
        summary="List users",
        description=(
            "Users oldest first (ties by id), optionally only those of one `status` "
            "(`invited`, `active`, `suspended` or `deactivated`). Without `limit` or "
            "`after` this is every user and the body is `users` alone. With either, the "
            "body also carries `next`: pass it as `after` for the following page, until it "
            "is null."
        ),
        responses={
            200: {"model": WardenUserList, "description": "The users."},
            400: detail(
                "`status` is not a user status, `limit` is not 1 to 1000, or `after` is "
                "not a cursor this route returned.",
                "the request is not valid",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def list_users(
        principal: Annotated[Principal, Depends(users_admin)],
        status: str | None = None,
        limit: Annotated[
            str | None, Query(description="Page size, a whole number from 1 to 1000.")
        ] = None,
        after: Annotated[
            str | None, Query(description="The `next` cursor from the previous page.")
        ] = None,
    ) -> Response:
        wanted: UserStatus | None = None
        if status is not None:
            try:
                wanted = UserStatus(status)
            except ValueError:
                return _invalid()
        if limit is None and after is None:
            found = await identity.users.list(status=wanted)
            return json_response({"users": [_user(u) for u in found]})
        size: int | None = None
        if limit is not None:
            if _PAGE_SIZE.fullmatch(limit) is None or int(limit) > _MAX_USER_PAGE:
                return _invalid()
            size = int(limit)
        try:
            found = await identity.users.list(
                status=wanted, limit=None if size is None else size + 1, after=after
            )
        except UserError:
            return _invalid()
        more = size is not None and len(found) > size
        page = found[:size] if more else found
        following = identity.users.cursor(page[-1]) if more else None
        return json_response({"users": [_user(u) for u in page], "next": following})

    @router.get(
        "/users/{user_id}",
        summary="Show a user and their roles",
        description=("`user_id` is the user's UUID; anything else is a 404."),
        responses={
            200: {"model": WardenUserDetail, "description": "The user."},
            404: detail("No such user.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def show_user(
        user_id: str, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        user = None if uid is None else await identity.users.get(uid)
        if user is None:
            return _not_found()
        assignments = await identity.roles.assignments_of(user.id)
        keys = await identity.webauthn_credentials.count(user.id)
        return json_response(
            {
                "user": _user(user),
                "roles": [_assignment(a) for a in assignments],
                "webauthn_credentials": keys,
            }
        )

    @router.post(
        "/users/{user_id}/status",
        summary="Set a user's status",
        description=(
            "While a user is not `active`, every credential check refuses them: their "
            "access tokens, refresh tokens and API keys stop being honoured at once. The "
            "last active administrator cannot be suspended or deactivated, even by "
            "concurrent requests."
        ),
        responses={
            200: {"model": WardenUserEnvelope, "description": "The updated user."},
            400: detail("The request is not valid.", "the request is not valid"),
            404: detail("No such user.", "not found"),
            409: detail(
                "This would leave no active administrator.",
                "this would leave no active administrator",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(StatusBody),
    )
    async def set_status(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        body = await read_object(request) or {}
        try:
            status = UserStatus(str(body.get("status")))
        except ValueError:
            return _invalid()
        try:
            user = await identity.users.set_status(uid, status, actor=str(principal.user_id))
        except LastAdministratorError:
            return _detail("this would leave no active administrator", 409)
        except UserError:
            return _not_found()
        return json_response({"user": _user(user)})

    @router.post(
        "/users/{user_id}/sign-in-method",
        summary="Set a user's sign-in method",
        description=(
            "`password_and_sso`, `sso_only` or `passkey_only`. An `sso_only` or "
            "`passkey_only` user cannot sign in with, reset or change a password; a "
            "`passkey_only` user signs in with a passkey alone (`POST /passkey/sign-in` under "
            "the auth prefix). Setting `passkey_only` also answers `has_passkey`: when false, "
            "the user cannot sign in until they register a passkey from a link "
            "(`POST /users/{user_id}/passkey-registration`). `sso_only` is refused (409) "
            "while the user holds security keys or passkeys: reset their second factors "
            "first (`DELETE /users/{user_id}/mfa`)."
        ),
        responses={
            200: {"model": WardenSignInMethodSet, "description": "The updated user."},
            400: detail("The request is not valid.", "the request is not valid"),
            404: detail("No such user.", "not found"),
            409: detail("The user holds security keys or passkeys.", _HOLDS_KEYS),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(SignInMethodBody),
    )
    async def set_method(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        body = await read_object(request) or {}
        try:
            method = SignInMethod(str(body.get("sign_in_method")))
        except ValueError:
            return _invalid()
        try:
            user = await identity.users.set_sign_in_method(
                uid, method, actor=str(principal.user_id)
            )
        except SignInMethodConflict:
            return _detail(_HOLDS_KEYS, 409)
        except UserError:
            return _not_found()
        if method is SignInMethod.PASSKEY_ONLY:
            has_passkey = await identity.users.holds_passkey(user.id)
            return json_response({"user": _user(user), "has_passkey": has_passkey})
        return json_response({"user": _user(user)})

    @router.post(
        "/users/{user_id}/password-reset",
        status_code=202,
        summary="Send a user a password reset link",
        description=(
            "Mails a reset link at once and reports the outcome, unlike the public reset "
            "request. Refused (409) for a user who is not active or is `sso_only`."
        ),
        responses={
            202: {"model": WardenResetSent, "description": "Sent.", "headers": no_store()},
            404: detail("No such user.", "not found"),
            409: detail(
                "A link cannot be sent to this user.", "a reset link cannot be sent to this user"
            ),
            502: detail(
                "The mail sender refused the message.", "the message could not be delivered"
            ),
            503: detail("No mail sender is configured.", "mail is not configured"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def send_reset(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        user = None if uid is None else await identity.users.get(uid)
        if user is None:
            return _not_found()
        try:
            reason = await identity.resets.request(
                user.email, actor=str(principal.user_id), source_ip=source(request)
            )
        except MailDeliveryError:
            return _detail("the message could not be delivered", 502)
        except MailError:
            return _detail("mail is not configured", 503)
        if reason is not None:
            return _detail("a reset link cannot be sent to this user", 409)
        return json_response({"status": "sent"}, 202)

    @router.post(
        "/users/{user_id}/passkey-registration",
        status_code=202,
        summary="Send a user a passkey registration link",
        description=(
            "Mails a single-use link (`http.passkey_registration_link`) with which the user "
            "registers a passkey without signing in (`POST /passkey-registration/options` "
            "under the auth prefix), and reports the outcome. Sending again stops the earlier "
            "link working. For a `passkey_only` user who has no passkey yet or has lost every "
            "one: reset their second factors first (`DELETE /users/{user_id}/mfa`), then send "
            "the link. There is no self-service request. Refused (409) for a user who is not "
            "active or is `sso_only`, and without WebAuthn configured."
        ),
        responses={
            202: {"model": WardenPasskeyLinkSent, "description": "Sent.", "headers": no_store()},
            404: detail("No such user.", "not found"),
            409: detail(
                "A link cannot be sent to this user, or WebAuthn is not configured.",
                _NO_LINK,
                _UNAVAILABLE,
            ),
            502: detail(
                "The mail sender refused the message.", "the message could not be delivered"
            ),
            503: detail(
                "No mail sender or no link template is configured.",
                "mail is not configured",
                _LINK_NOT_CONFIGURED,
            ),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def send_passkey_link(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        try:
            expires_at = await identity.send_passkey_registration(
                uid, actor=str(principal.user_id), source_ip=source(request)
            )
        except UserError:
            return _not_found()
        except PasskeyLinkRefused:
            return _detail(_NO_LINK, 409)
        except WebAuthnUnavailable:
            return _detail(_UNAVAILABLE, 409)
        except PasskeyLinkNotConfigured:
            return _detail(_LINK_NOT_CONFIGURED, 503)
        except MailDeliveryError:
            return _detail("the message could not be delivered", 502)
        except MailError:
            return _detail("mail is not configured", 503)
        return json_response({"status": "sent", "expires_at": _iso(expires_at)}, 202)

    @router.delete(
        "/users/{user_id}/totp",
        status_code=204,
        summary="Reset a user's TOTP enrolment",
        description=(
            "For a user who has lost their authenticator and their recovery codes. In one "
            "transaction it removes the TOTP enrolment (confirmed or not) and every recovery "
            "code, ends every session of the user, and records `warden.identity.mfa.reset`. "
            "The user's next password sign-in answers `mfa_enrolment_required` where the "
            "session policy requires a second factor, and they enrol again. A user with "
            "nothing enrolled is a 204 too, still audited."
        ),
        responses={
            204: {"description": "Reset.", "headers": no_store()},
            404: detail("No such user.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def reset_totp(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        try:
            await identity.reset_totp(uid, actor=str(principal.user_id), source_ip=source(request))
        except UserError:
            return _not_found()
        return _no_content()

    @router.delete(
        "/users/{user_id}/mfa",
        status_code=204,
        summary="Reset every second factor of a user",
        description=(
            "For a user who has lost their second factors. In one transaction it removes the "
            "TOTP enrolment (confirmed or not), every security key and passkey and every "
            "recovery code, ends every session of the user, and records "
            "`warden.identity.mfa.reset` with counts (`totp_removed`, `webauthn_removed`, "
            "`recovery_codes_removed`, `sessions_ended`). The user's next password sign-in "
            "answers `mfa_enrolment_required` where the session policy requires a second "
            "factor, and they enrol again. A user with nothing enrolled is a 204 too, still "
            "audited. `DELETE /users/{user_id}/totp` removes TOTP only and leaves keys."
        ),
        responses={
            204: {"description": "Reset.", "headers": no_store()},
            404: detail("No such user.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def reset_mfa(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        try:
            await identity.reset_mfa(uid, actor=str(principal.user_id), source_ip=source(request))
        except UserError:
            return _not_found()
        return _no_content()

    # Roles

    @router.get(
        "/roles",
        summary="List roles and permissions",
        description=("The roles and permissions the product registered."),
        responses={
            200: {"model": WardenRoleList, "description": "The registry."},
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def list_roles(principal: Annotated[Principal, Depends(roles_admin)]) -> Response:
        registry = identity.permissions
        return json_response(
            {
                "roles": [
                    {
                        "name": r.name,
                        "permissions": sorted(r.permissions),
                        "administrator": r.administrator,
                    }
                    for r in registry.roles()
                ],
                "permissions": registry.permissions(),
            }
        )

    @router.put(
        "/users/{user_id}/roles/{role}",
        status_code=204,
        summary="Assign a role",
        description=(
            "Assigns `role`, optionally until `expires_at`. Assigning a role the user "
            "already holds replaces its expiry. An administrator role cannot expire."
        ),
        responses={
            204: {"description": "Assigned.", "headers": no_store()},
            400: detail("Not a defined role, or a bad expiry.", "the request is not valid"),
            404: detail("No such user.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(RoleAssignBody, required=False),
    )
    async def assign_role(
        user_id: str,
        role: str,
        request: Request,
        principal: Annotated[Principal, Depends(roles_admin)],
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        body = await read_object(request) or {}
        try:
            expires_at = _when(body.get("expires_at"))
        except _BadRequest:
            return _invalid()
        if role not in identity.permissions:
            return _invalid()
        try:
            await identity.roles.assign(
                uid, role, actor=str(principal.user_id), expires_at=expires_at
            )
        except RoleError as exc:
            return _not_found() if "does not exist" in str(exc) else _invalid()
        return _no_content()

    @router.delete(
        "/users/{user_id}/roles/{role}",
        status_code=204,
        summary="Revoke a role",
        description=(
            "The last active administrator keeps their administrator role, even under "
            "concurrent requests."
        ),
        responses={
            204: {"description": "Revoked.", "headers": no_store()},
            404: detail("The user does not hold the role.", "not found"),
            409: detail(
                "This would leave no active administrator.",
                "this would leave no active administrator",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def revoke_role(
        user_id: str, role: str, principal: Annotated[Principal, Depends(roles_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        try:
            held = await identity.roles.revoke(uid, role, actor=str(principal.user_id))
        except LastAdministratorError:
            return _detail("this would leave no active administrator", 409)
        return _no_content() if held else _not_found()

    # Invitations

    @router.get(
        "/invitations",
        summary="List pending invitations",
        description=("Invited users, with their current link's expiry and staged roles."),
        responses={
            200: {"model": WardenInvitationList, "description": "The invitations."},
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def list_invitations(
        principal: Annotated[Principal, Depends(invitations_admin)],
    ) -> Response:
        pending = await identity.invitations.pending()
        return json_response({"invitations": [_invitation(p) for p in pending]})

    @router.post(
        "/invitations",
        status_code=201,
        summary="Invite a user",
        description=(
            "Creates the user in the `invited` status, stages the roles and mails the link "
            "in one transaction: if the mail fails, nothing is left behind."
        ),
        responses={
            201: {
                "model": WardenInvitationIssued,
                "description": "Invited.",
                "headers": no_store(),
            },
            400: detail("The request is not valid.", "the request is not valid"),
            409: detail(
                "A user with that address exists, or the invitation is `passkey_only` and "
                "WebAuthn is not configured.",
                "a user with that email address already exists",
                _UNAVAILABLE,
            ),
            502: detail(
                "The mail sender refused the message.", "the invitation could not be delivered"
            ),
            503: detail("No mail sender is configured.", "mail is not configured"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(InvitationCreateBody),
    )
    async def invite(
        request: Request, principal: Annotated[Principal, Depends(invitations_admin)]
    ) -> Response:
        body = await read_object(request) or {}
        email, display_name = body.get("email"), body.get("display_name")
        raw_roles = body.get("roles", [])
        try:
            method = SignInMethod(body.get("sign_in_method", SignInMethod.PASSWORD_AND_SSO))
            if not isinstance(email, str) or not (
                display_name is None or isinstance(display_name, str)
            ):
                raise _BadRequest
            if not isinstance(raw_roles, list) or not all(
                isinstance(g, dict) and isinstance(g.get("role"), str) for g in raw_roles
            ):
                raise _BadRequest
            grants = tuple(StagedGrant(g["role"], _when(g.get("expires_at"))) for g in raw_roles)
        except (_BadRequest, ValueError):
            return _invalid()
        if method is SignInMethod.PASSKEY_ONLY and identity.webauthn is None:
            return _detail(_UNAVAILABLE, 409)
        try:
            invitation = await identity.invitations.create(
                email,
                actor=str(principal.user_id),
                display_name=display_name,
                sign_in_method=method,
                grants=grants,
                source_ip=source(request),
            )
        except RoleError:
            return _invalid()
        except InvitationError as exc:
            if "already exists" in str(exc):
                return _detail("a user with that email address already exists", 409)
            return _invalid()
        except MailDeliveryError:
            return _detail("the invitation could not be delivered", 502)
        except MailError:
            return _detail("mail is not configured", 503)
        return json_response(
            {
                "user_id": str(invitation.user_id),
                "email": invitation.email,
                "expires_at": _iso(invitation.expires_at),
                "roles": _grants(invitation.grants),
            },
            201,
        )

    @router.post(
        "/invitations/{user_id}/resend",
        summary="Resend an invitation",
        description=(
            "Mails a new link and revokes the old one, keeping the staged roles. If the "
            "mail fails, the old link still works."
        ),
        responses={
            200: {"model": WardenInvitationIssued, "description": "Resent."},
            404: detail("No such user.", "not found"),
            409: detail("The user is not invited.", "the invitation is not pending"),
            502: detail(
                "The mail sender refused the message.", "the invitation could not be delivered"
            ),
            503: detail("No mail sender is configured.", "mail is not configured"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def resend(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(invitations_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        try:
            invitation = await identity.invitations.resend(
                uid, actor=str(principal.user_id), source_ip=source(request)
            )
        except InvitationError:
            return _detail("the invitation is not pending", 409)
        except MailDeliveryError:
            return _detail("the invitation could not be delivered", 502)
        except MailError:
            return _detail("mail is not configured", 503)
        return json_response(
            {
                "user_id": str(invitation.user_id),
                "email": invitation.email,
                "expires_at": _iso(invitation.expires_at),
                "roles": _grants(invitation.grants),
            }
        )

    @router.delete(
        "/invitations/{user_id}",
        status_code=204,
        summary="Revoke an invitation",
        description=(
            "Deletes the invited user. It never removes a user who accepted concurrently: "
            "that is a 409."
        ),
        responses={
            204: {"description": "Revoked.", "headers": no_store()},
            404: detail("No such user.", "not found"),
            409: detail("The user is not invited.", "the invitation is not pending"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def revoke_invitation(
        user_id: str, request: Request, principal: Annotated[Principal, Depends(invitations_admin)]
    ) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        try:
            await identity.invitations.revoke(
                uid, actor=str(principal.user_id), source_ip=source(request)
            )
        except InvitationError:
            return _detail("the invitation is not pending", 409)
        return _no_content()

    # API keys

    @router.get(
        "/api-keys",
        summary="List API keys",
        description=(
            "Every key, or only one user's (`user_id`, a UUID), revoked keys included. A "
            "key itself is never shown again; `hint` identifies it."
        ),
        responses={
            200: {"model": WardenApiKeyList, "description": "The keys."},
            400: detail("`user_id` is not a UUID.", "the request is not valid"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def list_keys(
        principal: Annotated[Principal, Depends(keys_admin)], user_id: str | None = None
    ) -> Response:
        uid = None if user_id is None else _id(user_id)
        if user_id is not None and uid is None:
            return _invalid()
        found = await identity.api_keys.list(user_id=uid)
        return json_response({"api_keys": [_api_key(k) for k in found]})

    @router.post(
        "/api-keys",
        status_code=201,
        summary="Create an API key",
        description=(
            "A key acts as its user, limited to `scopes`, which must be registered "
            "permissions the user holds now. It is refused once it expires or is revoked, "
            "or while its user is not active. The key is in this answer only."
        ),
        responses={
            201: {"model": WardenNewApiKeyIssued, "description": "Created.", "headers": no_store()},
            400: detail("The request is not valid.", "the request is not valid"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(NewApiKeyBody),
    )
    async def create_key(
        request: Request, principal: Annotated[Principal, Depends(keys_admin)]
    ) -> Response:
        body = await read_object(request) or {}
        uid = _id(body.get("user_id"))
        name, scopes = body.get("name"), body.get("scopes")
        try:
            expires_at = _when(body.get("expires_at"))
        except _BadRequest:
            return _invalid()
        if (
            uid is None
            or not isinstance(name, str)
            or not isinstance(scopes, list)
            or not all(isinstance(s, str) for s in scopes)
        ):
            return _invalid()
        try:
            new = await identity.api_keys.create(
                uid,
                name,
                scopes,
                actor=str(principal.user_id),
                expires_at=expires_at,
                source_ip=source(request),
            )
        except ApiKeyError:
            return _invalid()
        return json_response({"key": new.key, "api_key": _api_key(new.api_key)}, 201)

    @router.delete(
        "/api-keys/{key_id}",
        status_code=204,
        summary="Revoke an API key",
        description=("A revoked key stays listed, with `revoked_at`."),
        responses={
            204: {"description": "Revoked.", "headers": no_store()},
            404: detail("No such key, or already revoked.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def revoke_key(
        key_id: str, request: Request, principal: Annotated[Principal, Depends(keys_admin)]
    ) -> Response:
        kid = _id(key_id)
        if kid is None or not await identity.api_keys.revoke(
            kid, actor=str(principal.user_id), source_ip=source(request)
        ):
            return _not_found()
        return _no_content()

    return router
