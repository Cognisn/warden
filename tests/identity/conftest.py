"""Fixtures for identity tests that need a database, keys, an audit recorder and an app."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import FAST_HASHER, PASSWORD, MemorySecrets, UserFactory, make_config

from warden.audit import ActionRegistry, AuditRecorder, set_recorder
from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity, PermissionRegistry, User
from warden.keys import KeyStore


@pytest.fixture
def permissions() -> PermissionRegistry:
    registry = PermissionRegistry()
    registry.register_permission("cases.read", "Read cases")
    registry.register_permission("cases.write", "Edit cases")
    registry.register_permission("users.manage", "Manage users")
    registry.define_role("viewer", {"cases.read"})
    registry.define_role("analyst", {"cases.read", "cases.write"})
    registry.define_role("admin", {"users.manage", "cases.read"}, administrator=True)
    return registry


@pytest.fixture
def audit_registry() -> ActionRegistry:
    return ActionRegistry()


@pytest.fixture
async def db(pool: Any, audit_registry: ActionRegistry) -> AsyncIterator[Database]:
    database = Database(pool)
    previous = set_recorder(AuditRecorder(database, audit_registry))
    try:
        yield database
    finally:
        set_recorder(previous)


@pytest.fixture
async def keys(db: Database) -> KeyStore:
    store = KeyStore(db, MemorySecrets())
    await store.rotate()
    return store


@pytest.fixture
def config() -> WardenConfig:
    return make_config()


@pytest.fixture
def identity(
    config: WardenConfig, db: Database, keys: KeyStore, permissions: PermissionRegistry
) -> Identity:
    return Identity(config, db, keys, permissions, hasher=FAST_HASHER)


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


@pytest.fixture
def make_user(identity: Identity) -> UserFactory:
    async def factory(
        email: str | None = None,
        *,
        password: str | None = PASSWORD,
        roles: tuple[str, ...] = (),
        **kw: Any,
    ) -> User:
        user = await identity.users.create(
            email or f"user-{uuid.uuid4().hex[:8]}@example.com",
            actor="test",
            password=password,
            **kw,
        )
        for role in roles:
            await identity.roles.assign(user.id, role, actor="test")
        return user

    return factory
