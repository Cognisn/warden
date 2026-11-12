"""require_user, require_permission and the product's resource-scope hook."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from identity_support import FAST_HASHER, PASSWORD, MemorySecrets, UserFactory

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import (
    Identity,
    PermissionRegistry,
    Principal,
    UserStatus,
    require_permission,
    require_user,
)
from warden.keys import KeyStore

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'


class CaseScope:
    """A product hook: analysts may touch only cases they are assigned."""

    def __init__(self) -> None:
        self.assigned: dict[str, set[str]] = {}

    async def __call__(self, principal: Principal, permission: str, request: Request) -> bool:
        case = request.path_params.get("case_id")
        return case in self.assigned.get(str(principal.user_id), set())


@pytest.fixture
def scope() -> CaseScope:
    return CaseScope()


def _app(identity: Identity) -> FastAPI:
    app = FastAPI()
    identity.install(app)
    app.include_router(identity.auth_router(), prefix="/auth")

    @app.get("/me")
    async def me(principal: Annotated[Principal, Depends(require_user)]) -> dict[str, object]:
        return {"user": str(principal.user_id), "permissions": sorted(principal.permissions)}

    @app.get("/cases")
    async def cases(
        principal: Annotated[Principal, Depends(require_permission("cases.read"))],
    ) -> dict[str, str]:
        return {"ok": "yes"}

    @app.put("/cases/{case_id}")
    async def edit(
        case_id: str,
        principal: Annotated[Principal, Depends(require_permission("cases.write", scoped=True))],
    ) -> dict[str, str]:
        return {"edited": case_id}

    return app


@pytest.fixture
async def scoped_client(
    config: WardenConfig,
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    scope: CaseScope,
    secrets: MemorySecrets,
) -> AsyncIterator[tuple[Identity, httpx.AsyncClient]]:
    identity = Identity(
        config,
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        resource_scope=scope,
    )
    transport = httpx.ASGITransport(app=_app(identity))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield identity, c


async def _bearer(identity: Identity, email: str) -> dict[str, str]:
    result = await identity.sign_in(email, PASSWORD)
    assert result.tokens is not None
    return {"authorization": f"Bearer {result.tokens.access_token}"}


async def _user(identity: Identity, *roles: str) -> tuple[str, dict[str, str]]:
    import uuid

    email = f"dep-{uuid.uuid4().hex[:8]}@example.com"
    user = await identity.users.create(email, actor="t", password=PASSWORD)
    for role in roles:
        await identity.roles.assign(user.id, role, actor="t")
    return str(user.id), await _bearer(identity, email)


async def test_require_user(scoped_client: tuple[Identity, httpx.AsyncClient]) -> None:
    identity, client = scoped_client
    user_id, auth = await _user(identity, "viewer")
    response = await client.get("/me", headers=auth)
    assert response.status_code == 200
    assert response.json() == {"user": user_id, "permissions": ["cases.read"]}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"authorization": "Bearer"},
        {"authorization": "Bearer not.a.token"},
        {"authorization": "Basic dXNlcjpwYXNz"},
        {"authorization": "bearer"},
    ],
)
async def test_require_user_refuses_uniformly(
    scoped_client: tuple[Identity, httpx.AsyncClient], headers: dict[str, str]
) -> None:
    _, client = scoped_client
    response = await client.get("/me", headers=headers)
    assert response.status_code == 401
    assert response.content == REFUSAL
    assert response.headers["www-authenticate"] == "Bearer"


async def test_require_user_refuses_an_inactive_user(
    scoped_client: tuple[Identity, httpx.AsyncClient],
) -> None:
    import uuid

    identity, client = scoped_client
    user_id, auth = await _user(identity, "viewer")
    await identity.users.set_status(uuid.UUID(user_id), UserStatus.SUSPENDED, actor="t")
    response = await client.get("/me", headers=auth)
    assert response.status_code == 401 and response.content == REFUSAL


async def test_require_permission(scoped_client: tuple[Identity, httpx.AsyncClient]) -> None:
    identity, client = scoped_client
    _, viewer = await _user(identity, "viewer")
    _, nobody = await _user(identity)
    assert (await client.get("/cases", headers=viewer)).status_code == 200
    denied = await client.get("/cases", headers=nobody)
    assert denied.status_code == 403
    assert denied.content == b'{"detail":"forbidden"}'
    assert (await client.get("/cases")).status_code == 401


async def test_role_changes_apply_to_the_next_request(
    scoped_client: tuple[Identity, httpx.AsyncClient],
) -> None:
    import uuid

    identity, client = scoped_client
    user_id, auth = await _user(identity, "viewer")
    await identity.roles.revoke(uuid.UUID(user_id), "viewer", actor="t")
    assert (await client.get("/cases", headers=auth)).status_code == 403


async def test_scoped_permission_consults_the_product_hook(
    scoped_client: tuple[Identity, httpx.AsyncClient], scope: CaseScope
) -> None:
    identity, client = scoped_client
    analyst_id, analyst = await _user(identity, "analyst")
    _, viewer = await _user(identity, "viewer")
    scope.assigned[analyst_id] = {"case-1"}
    assert (await client.put("/cases/case-1", headers=analyst)).status_code == 200
    assert (await client.put("/cases/case-2", headers=analyst)).status_code == 403
    # The hook narrows a permission; it never grants one the user lacks.
    scope.assigned[analyst_id] = set()
    assert (await client.put("/cases/case-1", headers=viewer)).status_code == 403


async def test_a_scoped_permission_without_a_hook_fails_closed(
    identity: Identity, make_user: UserFactory
) -> None:
    transport = httpx.ASGITransport(app=_app(identity))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        user = await make_user(roles=("analyst",))
        auth = await _bearer(identity, user.email)
        assert (await c.put("/cases/case-1", headers=auth)).status_code == 403
        assert (await c.get("/cases", headers=auth)).status_code == 200


async def test_dependencies_need_an_installed_identity() -> None:
    app = FastAPI()

    @app.get("/me")
    async def me(principal: Annotated[Principal, Depends(require_user)]) -> str:
        return "unreachable"

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        with pytest.raises(RuntimeError, match="install"):
            await c.get("/me", headers={"authorization": "Bearer x.y.z"})
