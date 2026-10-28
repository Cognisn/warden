"""Administration routes. The product mounts them under ``config.http.admin_prefix``.

Every route requires a permission the product names when it builds the
router (``identity.admin_router(permission=..., roles=..., invitations=...,
api_keys=...)``); warden hardcodes none. Every change is made through the
identity services, which audit it under ``warden.identity.*`` with the
administrator as actor. Request bodies are parsed here, never echoed back,
and every error is a fixed message.

| Route | Body | Success |
|---|---|---|
| ``GET /users[?status=]`` | | ``{"users": [...]}`` |
| ``GET /users/{id}`` | | ``{"user", "roles"}`` |
| ``POST /users/{id}/status`` | ``status`` | ``{"user"}`` |
| ``POST /users/{id}/sign-in-method`` | ``sign_in_method`` | ``{"user"}`` |
| ``POST /users/{id}/password-reset`` | | 202 |
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
Times are ISO 8601 with a zone offset. A new API key is returned once, never again.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from psycopg import sql

from warden.db import schema, table
from warden.identity.apikeys import ApiKey, ApiKeyError
from warden.identity.dependencies import Principal, require_permission
from warden.identity.http import NO_STORE, SourceIp, client_ip, json_response, read_object
from warden.identity.invitations import InvitationError, PendingInvitation, StagedGrant
from warden.identity.mail import MailDeliveryError, MailError
from warden.identity.roles import LastAdministratorError, RoleAssignment, RoleError
from warden.identity.users import SignInMethod, User, UserError, UserStatus

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_admin_router"]


class _BadRequest(Exception):
    pass


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


async def _list_users(identity: "Identity", status: UserStatus | None) -> list[User]:
    """Every user, oldest first, optionally of one status."""
    async with identity.db.transaction() as tx:
        cur = await tx.execute(
            sql.SQL(
                "SELECT id FROM {} WHERE %(status)s::text IS NULL OR status = %(status)s"
                " ORDER BY created_at, id"
            ).format(table(schema.USERS)),
            {"status": None if status is None else status.value},
        )
        found = [await identity.users.get(row[0], conn=tx) for row in await cur.fetchall()]
    return [user for user in found if user is not None]


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

    @router.get("/users")
    async def list_users(
        principal: Annotated[Principal, Depends(users_admin)], status: str | None = None
    ) -> Response:
        wanted: UserStatus | None = None
        if status is not None:
            try:
                wanted = UserStatus(status)
            except ValueError:
                return _invalid()
        found = await _list_users(identity, wanted)
        return json_response({"users": [_user(u) for u in found]})

    @router.get("/users/{user_id}")
    async def show_user(
        user_id: str, principal: Annotated[Principal, Depends(users_admin)]
    ) -> Response:
        uid = _id(user_id)
        user = None if uid is None else await identity.users.get(uid)
        if user is None:
            return _not_found()
        assignments = await identity.roles.assignments_of(user.id)
        return json_response({"user": _user(user), "roles": [_assignment(a) for a in assignments]})

    @router.post("/users/{user_id}/status")
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

    @router.post("/users/{user_id}/sign-in-method")
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
        except UserError:
            return _not_found()
        return json_response({"user": _user(user)})

    @router.post("/users/{user_id}/password-reset")
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

    # Roles

    @router.get("/roles")
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

    @router.put("/users/{user_id}/roles/{role}")
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

    @router.delete("/users/{user_id}/roles/{role}")
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

    @router.get("/invitations")
    async def list_invitations(
        principal: Annotated[Principal, Depends(invitations_admin)],
    ) -> Response:
        pending = await identity.invitations.pending()
        return json_response({"invitations": [_invitation(p) for p in pending]})

    @router.post("/invitations")
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

    @router.post("/invitations/{user_id}/resend")
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

    @router.delete("/invitations/{user_id}")
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

    @router.get("/api-keys")
    async def list_keys(
        principal: Annotated[Principal, Depends(keys_admin)], user_id: str | None = None
    ) -> Response:
        uid = None if user_id is None else _id(user_id)
        if user_id is not None and uid is None:
            return _invalid()
        found = await identity.api_keys.list(user_id=uid)
        return json_response({"api_keys": [_api_key(k) for k in found]})

    @router.post("/api-keys")
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

    @router.delete("/api-keys/{key_id}")
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
