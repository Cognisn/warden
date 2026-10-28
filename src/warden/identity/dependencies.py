"""FastAPI dependencies: ``require_user``, ``require_permission`` and the resource-scope hook.

They find the ``Identity`` that ``Identity.install(app)`` placed on the
application, so a product can declare them on its routes before warden is
constructed::

    @app.get("/cases")
    async def cases(principal: Annotated[Principal, Depends(require_permission("cases.read"))]):
        ...

A missing, malformed or refused bearer token gets the uniform 401 refusal;
a valid user without the permission gets 403.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from fastapi import HTTPException, Request

from warden.identity.errors import AuthenticationRefused
from warden.identity.http import Refused, client_ip

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = [
    "APP_STATE_KEY",
    "Principal",
    "ResourceScopeHook",
    "bearer_token",
    "require_permission",
    "require_user",
]

APP_STATE_KEY = "warden_identity"


@dataclass(frozen=True, slots=True)
class Principal:
    """The signed-in user behind a request.

    For a request made with an API key, ``api_key_id`` names the key,
    ``session_id`` holds the same id (a key has no session), ``amr`` is
    ``("api_key",)``, and ``permissions`` are the key's scopes intersected
    with the user's current permissions.
    """

    user_id: uuid.UUID
    session_id: uuid.UUID
    email: str
    roles: frozenset[str]
    permissions: frozenset[str]
    amr: tuple[str, ...]
    api_key_id: uuid.UUID | None = None


class ResourceScopeHook(Protocol):
    """The product's resource-level check, consulted by ``require_permission(..., scoped=True)``.

    Called only after the user is known to hold ``permission``; it can narrow
    a permission to particular resources, never grant one.
    """

    async def __call__(self, principal: Principal, permission: str, request: Request) -> bool: ...


class Forbidden(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=403, detail="forbidden", headers={"cache-control": "no-store"})


def installed_identity(request: Request) -> Identity:
    identity: Identity | None = getattr(request.app.state, APP_STATE_KEY, None)
    if identity is None:
        raise RuntimeError("no warden Identity is installed; call identity.install(app)")
    return identity


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


async def require_user(request: Request) -> Principal:
    """The signed-in user (by access token or API key), or the uniform 401 refusal."""
    identity = installed_identity(request)
    token = bearer_token(request)
    if token is None:
        raise Refused()
    try:
        if identity.api_keys.looks_like_key(token):
            source = client_ip(request, identity.config.audit.trusted_proxies)
            return await identity.api_keys.authenticate(token, source_ip=source)
        return await identity.authenticate(token)
    except AuthenticationRefused:
        raise Refused() from None


def require_permission(
    permission: str, *, scoped: bool = False
) -> Callable[[Request], Awaitable[Principal]]:
    """A dependency requiring ``permission``; with ``scoped``, also the product's hook.

    A scoped check with no hook installed refuses: it fails closed.
    """

    async def dependency(request: Request) -> Principal:
        principal = await require_user(request)
        if permission not in principal.permissions:
            raise Forbidden()
        if scoped:
            hook = installed_identity(request).resource_scope
            if hook is None or not await hook(principal, permission, request):
                raise Forbidden()
        return principal

    return dependency
