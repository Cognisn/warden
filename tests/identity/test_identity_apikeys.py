"""API keys: prefixed, hashed, expiring, revocable, scoped, refused for inactive users (#132).

A key's effective permissions are its scopes intersected with its user's
current permissions, so a key can never exceed its user.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from identity_support import (
    FAST_HASHER,
    PASSWORD,
    MemorySecrets,
    UserFactory,
    audit_rows,
    make_config,
)

from warden.db import Database
from warden.identity import (
    Identity,
    PermissionRegistry,
    Principal,
    UserStatus,
    require_permission,
    require_user,
)
from warden.identity.apikeys import ApiKeyError
from warden.keys import KeyStore

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'


def _app(identity: Identity) -> FastAPI:
    app = FastAPI()
    identity.install(app)
    app.include_router(identity.auth_router(), prefix="/auth")

    @app.get("/me")
    async def me(principal: Annotated[Principal, Depends(require_user)]) -> dict[str, object]:
        return {
            "user": str(principal.user_id),
            "permissions": sorted(principal.permissions),
            "amr": list(principal.amr),
            "api_key": None if principal.api_key_id is None else str(principal.api_key_id),
        }

    @app.get("/cases")
    async def read(
        principal: Annotated[Principal, Depends(require_permission("cases.read"))],
    ) -> str:
        return "read"

    @app.put("/cases")
    async def write(
        principal: Annotated[Principal, Depends(require_permission("cases.write"))],
    ) -> str:
        return "written"

    return app


@pytest.fixture
async def client(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_app(identity), client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


def _bearer(key: str) -> dict[str, str]:
    return {"authorization": f"Bearer {key}"}


async def _reasons(db: Database) -> list[str]:
    return [
        r["details"]["reason"]
        for r in await audit_rows(db, "warden.identity.api_key.authenticate")
        if r["outcome"] == "failure"
    ]


# Creation


async def test_a_key_is_prefixed_and_stored_only_as_its_hash(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user(roles=("analyst",))
    new = await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="admin-1")
    assert new.key.startswith("wdn_")
    assert new.api_key.hint == new.key[: len(new.api_key.hint)]
    assert len(new.api_key.hint) < len(new.key) // 2
    assert new.api_key.scopes == frozenset({"cases.read"})
    async with db.connection() as conn:
        cur = await conn.execute("SELECT key_hash FROM warden.api_keys")
        rows = await cur.fetchall()
        cur = await conn.execute("SELECT count(*) FROM warden.api_keys WHERE hint = %s", (new.key,))
        assert await cur.fetchone() == (0,)
    assert [bytes(r[0]) for r in rows] == [hashlib.sha256(new.key.encode()).digest()]
    created = await audit_rows(db, "warden.identity.api_key.created")
    assert [(r["actor"], r["resource_id"]) for r in created] == [("admin-1", str(user.id))]
    assert new.key not in str(created[0]["details"])


async def test_the_configured_prefix_is_used(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    identity = Identity(
        make_config(api_key_prefix="acme_"),
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
    )
    user = await identity.users.create("p@example.com", actor="t", password=PASSWORD)
    await identity.roles.assign(user.id, "viewer", actor="t")
    new = await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="t")
    assert new.key.startswith("acme_")


async def test_a_key_expires_within_the_configured_maximum(
    identity: Identity, make_user: UserFactory
) -> None:
    user = await make_user(roles=("viewer",))
    before = datetime.now(UTC)
    default = await identity.api_keys.create(user.id, "default", {"cases.read"}, actor="t")
    assert default.api_key.expires_at is not None
    assert (
        before + timedelta(days=365)
        <= default.api_key.expires_at
        <= datetime.now(UTC) + timedelta(days=365, seconds=5)
    )
    short = before + timedelta(days=7)
    chosen = await identity.api_keys.create(
        user.id, "short", {"cases.read"}, actor="t", expires_at=short
    )
    assert chosen.api_key.expires_at == short
    for bad in (before + timedelta(days=366), before - timedelta(seconds=1)):
        with pytest.raises(ApiKeyError, match="expiry"):
            await identity.api_keys.create(
                user.id, "bad", {"cases.read"}, actor="t", expires_at=bad
            )


async def test_keys_may_be_unexpiring_when_no_maximum_is_set(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
) -> None:
    identity = Identity(
        make_config(api_key_max_lifetime_days=None),
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
    )
    user = await identity.users.create("forever@example.com", actor="t", password=PASSWORD)
    await identity.roles.assign(user.id, "viewer", actor="t")
    new = await identity.api_keys.create(user.id, "forever", {"cases.read"}, actor="t")
    assert new.api_key.expires_at is None


@pytest.mark.parametrize(
    ("name", "scopes", "match"),
    [
        ("ci", set(), "scope"),
        ("ci", {"no.such"}, "scope"),
        ("ci", {"cases.write"}, "exceed"),  # a viewer cannot hold cases.write
        ("", {"cases.read"}, "name"),
        ("x" * 101, {"cases.read"}, "name"),
        ("bad\nname", {"cases.read"}, "name"),
    ],
)
async def test_creation_is_checked(
    identity: Identity, make_user: UserFactory, name: str, scopes: set[str], match: str
) -> None:
    user = await make_user(roles=("viewer",))
    with pytest.raises(ApiKeyError, match=match):
        await identity.api_keys.create(user.id, name, scopes, actor="t")


async def test_an_inactive_user_gets_no_new_key(identity: Identity, make_user: UserFactory) -> None:
    user = await make_user(roles=("viewer",))
    await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="t")
    with pytest.raises(ApiKeyError, match="active"):
        await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="t")


# Authentication


async def test_a_key_is_accepted_by_require_user_and_require_permission(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user(roles=("analyst",))
    new = await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="t")
    me = await client.get("/me", headers=_bearer(new.key))
    assert me.status_code == 200
    assert me.json() == {
        "user": str(user.id),
        "permissions": ["cases.read"],
        "amr": ["api_key"],
        "api_key": str(new.api_key.id),
    }
    assert (await client.get("/cases", headers=_bearer(new.key))).status_code == 200
    # The user may write cases; the key was not given that scope.
    denied = await client.put("/cases", headers=_bearer(new.key))
    assert denied.status_code == 403


async def test_a_key_never_exceeds_its_user_s_current_permissions(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user(roles=("analyst",))
    new = await identity.api_keys.create(user.id, "ci", {"cases.read", "cases.write"}, actor="t")
    assert (await client.put("/cases", headers=_bearer(new.key))).status_code == 200
    await identity.roles.revoke(user.id, "analyst", actor="t")
    await identity.roles.assign(user.id, "viewer", actor="t")
    assert (await client.put("/cases", headers=_bearer(new.key))).status_code == 403
    me = await client.get("/me", headers=_bearer(new.key))
    assert me.json()["permissions"] == ["cases.read"]


async def test_a_key_is_refused_once_its_user_is_inactive(
    identity: Identity, db: Database, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    """#132 for API keys."""
    user = await make_user(roles=("viewer",))
    new = await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="t")
    for status in (UserStatus.SUSPENDED, UserStatus.DEACTIVATED):
        await identity.users.set_status(user.id, status, actor="t")
        refused = await client.get("/me", headers=_bearer(new.key))
        assert refused.status_code == 401 and refused.content == REFUSAL
    assert await _reasons(db) == ["user_inactive", "user_inactive"]
    await identity.users.set_status(user.id, UserStatus.ACTIVE, actor="t")
    assert (await client.get("/me", headers=_bearer(new.key))).status_code == 200


async def test_every_refusal_is_the_same_response(
    identity: Identity, db: Database, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user(roles=("viewer",))
    revoked = await identity.api_keys.create(user.id, "revoked", {"cases.read"}, actor="t")
    assert await identity.api_keys.revoke(revoked.api_key.id, actor="admin-1")
    expired = await identity.api_keys.create(user.id, "expired", {"cases.read"}, actor="t")
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.api_keys SET created_at = now() - interval '2 days',"
            " expires_at = now() - interval '1 second' WHERE id = %s",
            (expired.api_key.id,),
        )
    unknown = "wdn_" + "A" * 43
    responses = [
        await client.get("/me", headers=_bearer(key))
        for key in (revoked.key, expired.key, unknown, "wdn_short", "not-a-jwt-either")
    ]
    assert {(r.status_code, r.content, r.headers["www-authenticate"]) for r in responses} == {
        (401, REFUSAL, "Bearer")
    }
    assert await _reasons(db) == ["key_revoked", "key_expired", "unknown_key"]


async def test_revoking_a_key(identity: Identity, db: Database, make_user: UserFactory) -> None:
    user = await make_user(roles=("viewer",))
    new = await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="t")
    assert await identity.api_keys.revoke(new.api_key.id, actor="admin-1")
    assert not await identity.api_keys.revoke(new.api_key.id, actor="admin-1")
    listed = await identity.api_keys.list(user_id=user.id)
    assert [k.revoked_at is not None for k in listed] == [True]
    revoked = await audit_rows(db, "warden.identity.api_key.revoked")
    assert [(r["outcome"], r["actor"]) for r in revoked] == [("success", "admin-1")]


async def test_use_is_recorded_on_the_key(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user(roles=("viewer",))
    new = await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="t")
    assert new.api_key.last_used_at is None
    await client.get("/me", headers=_bearer(new.key))
    [listed] = await identity.api_keys.list(user_id=user.id)
    assert listed.last_used_at is not None


async def test_a_key_cannot_sign_out_or_change_a_password(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    """Session routes take access tokens only."""
    user = await make_user(roles=("viewer",))
    new = await identity.api_keys.create(user.id, "ci", {"cases.read"}, actor="t")
    for path in ("/auth/sign-out", "/auth/password"):
        response = await client.post(path, headers=_bearer(new.key), json={})
        assert response.status_code == 401 and response.content == REFUSAL


async def test_access_tokens_still_work(
    identity: Identity, client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user(roles=("viewer",))
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is not None
    me = await client.get("/me", headers=_bearer(result.tokens.access_token))
    assert me.status_code == 200 and me.json()["api_key"] is None
