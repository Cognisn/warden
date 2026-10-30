"""The sample console's application: how a product wires warden into FastAPI.

Read top to bottom, ``build_console`` is the integration a product writes:

1. hand warden the product's own connection pool (``Database``);
2. install one audit recorder, with the product's audit actions registered;
3. open the key store over konfig's secrets;
4. construct ``Identity`` with the product's permissions, roles,
   resource-scope hook and mail sender;
5. run the syslog forwarder, when syslog is configured;
6. mount warden's routers under the prefixes the configuration names, each
   administration and audit router guarded by a permission the product chose;
7. mount the product's own routes and pages.
"""

from __future__ import annotations

import mimetypes
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from examples.console import product
from examples.console.console_routes import console_router
from examples.console.notes import Notes, NoteScope, notes_router
from examples.console.outbox import Outbox
from examples.console.security import SecurityHeaders, content_security_policy
from warden.audit import ActionRegistry, AuditRecorder, set_recorder
from warden.audit.router import audit_router
from warden.audit.syslog import (
    SyslogForwarder,
    SyslogSettings,
    register_syslog_actions,
    syslog_router,
)
from warden.config import WardenConfig
from warden.db import ConnectionSource, Database
from warden.identity import Identity, PasswordHasher, require_permission
from warden.jwks import keys_router
from warden.keys import KeyStore, SecretStore
from warden.proxy import TrustedProxyMiddleware

__all__ = ["PAGES", "STATIC", "Console", "build_console"]

STATIC = Path(__file__).resolve().parent / "static"
# Paths that answer with the console's single page. The link templates in the
# example configuration point at the first three.
PAGES = ("/accept", "/reset", "/signed-in", "/")

# Windows can map .js to text/plain, which a browser refuses for a module
# script under ``nosniff``.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")


@dataclass(frozen=True)
class Console:
    """The built console: the app and the warden objects behind it."""

    app: FastAPI
    identity: Identity
    keys: KeyStore
    recorder: AuditRecorder
    outbox: Outbox
    notes: Notes
    forwarder: SyslogForwarder | None


def actor(permission: str) -> Callable[[Request], Awaitable[str]]:
    """A FastAPI dependency for warden's audit, syslog and SSO routes.

    Those routes know nothing of users (audit is independent of identity,
    design D11): the product supplies a dependency that refuses the caller
    or returns the actor id to record. This one requires ``permission``.
    """
    check = require_permission(permission)

    async def dependency(request: Request) -> str:
        principal = await check(request)
        return str(principal.user_id)

    return dependency


def build_console(
    config: WardenConfig,
    pool: ConnectionSource,
    secrets: SecretStore,
    *,
    hasher: PasswordHasher | None = None,
) -> Console:
    """Build the console over the product's open pool and konfig's secrets store."""
    db = Database(pool)

    registry = ActionRegistry()
    product.register_actions(registry)
    register_syslog_actions(registry)
    recorder = AuditRecorder(db, registry, details_max_bytes=config.audit.details_max_bytes)
    set_recorder(recorder)

    keys = KeyStore(db, secrets, config.keys)
    notes = Notes()
    outbox = Outbox()
    identity = Identity(
        config,
        db,
        keys,
        product.permissions(),
        secrets=secrets,
        hasher=hasher,
        resource_scope=NoteScope(notes),
        mail_sender=outbox,
    )

    forwarder: SyslogForwarder | None = None
    if config.syslog.enabled:
        settings = SyslogSettings.from_config(config.syslog, secrets=secrets.get)
        forwarder = SyslogForwarder(db, settings, registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(identity.running())
            await stack.enter_async_context(identity.pruning(every_seconds=3600))
            if forwarder is not None:
                await stack.enter_async_context(forwarder)
            yield

    # No interactive API documentation: its page needs inline script and a CDN,
    # which the Content Security Policy refuses. The schema stays at /openapi.json.
    app = FastAPI(title="warden sample console", lifespan=lifespan, docs_url=None, redoc_url=None)
    identity.install(app)

    http = config.http
    app.include_router(identity.auth_router(), prefix=http.auth_prefix)
    app.include_router(identity.sso_router(), prefix=http.auth_prefix)
    app.include_router(identity.lifecycle_router(), prefix=http.auth_prefix)
    app.include_router(
        identity.admin_router(permission=product.USERS_MANAGE, api_keys=product.KEYS_MANAGE),
        prefix=http.admin_prefix,
    )
    app.include_router(
        identity.sso_settings_router(authorise=actor(product.SSO_MANAGE)),
        prefix=http.admin_prefix,
    )
    app.include_router(
        audit_router(
            recorder=recorder,
            keys=keys,
            authorise=actor(product.AUDIT_READ),
            authorise_export=actor(product.AUDIT_EXPORT),
        ),
        prefix=http.audit_prefix,
    )
    if forwarder is not None:
        app.include_router(
            syslog_router(forwarder, authorise=actor(product.SYSLOG_MANAGE), recorder=recorder),
            prefix=http.audit_prefix,
        )
    app.include_router(keys_router(keys=keys), prefix=http.keys_prefix)

    app.include_router(notes_router(notes), prefix="/api")
    app.include_router(console_router(identity, outbox, recorder, keys, forwarder), prefix="/api")
    _mount_pages(app)

    app.add_middleware(SecurityHeaders, policy=content_security_policy(config.sso.issuer_url))
    app.add_middleware(TrustedProxyMiddleware, trusted_proxies=config.audit.trusted_proxies)
    return Console(
        app=app,
        identity=identity,
        keys=keys,
        recorder=recorder,
        outbox=outbox,
        notes=notes,
        forwarder=forwarder,
    )


def _mount_pages(app: FastAPI) -> None:
    index = STATIC / "index.html"

    async def page() -> FileResponse:
        return FileResponse(index, media_type="text/html", headers={"cache-control": "no-store"})

    async def no_icon() -> Response:
        # The console has no icon; answer browsers' automatic request quietly.
        return Response(status_code=204)

    for path in PAGES:
        app.add_api_route(path, page, methods=["GET"], include_in_schema=False)
    app.add_api_route("/favicon.ico", no_icon, methods=["GET"], include_in_schema=False)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
