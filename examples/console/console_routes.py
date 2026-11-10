"""The sample's own routes, built on warden's public Python API.

Where warden ships an HTTP route the console calls it directly. These routes
cover what the console needs that warden leaves to the product:

- ``GET /me``: who the bearer is (warden's routes have no such route; a
  product answers it from ``require_user``);
- ``GET /outbox``: the in-memory mail outbox (the sample's own mail sender);
- ``GET``/``PUT /policy``, ``POST /policy/reset``: the session policy, through
  ``Identity.policy`` (warden has no HTTP route for it);
- ``POST /audit/anchor``, ``POST /audit/anchors/verify``: audit anchors,
  through ``warden.audit.anchor`` and ``verify_anchors`` (warden has the CLI
  ``warden audit anchor`` and ``warden audit verify --anchors``, but no route);
- ``GET /syslog/settings``: the forwarder's effective settings (warden's
  syslog routes give status and a test send only);
- ``POST /passwords/recheck``: one run of the password recheck, through
  ``Identity.password_recheck`` (warden has the CLI ``warden passwords
  recheck`` and the Python call, but no route: the product schedules it);
- ``POST /watch-lists/{id}/import-sample``: imports the small synthetic file
  shipped with the sample into an imported watch list, through
  ``Identity.watch_lists.import_hibp`` (warden imports with the CLI ``warden
  passwords import``, not over HTTP);
- ``GET``/``PUT /dev/clock``: the development clock, present only when the
  console was started with ``serve --dev-clock``.

The sample mounts them under ``/api``. The outbox is unauthenticated so an
invitee can follow a link: acceptable only because the sample is for local
development.
"""

# No ``from __future__ import annotations``: FastAPI must resolve the route
# signatures, which use dependency aliases local to ``console_router``.

import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from examples.console.devclock import DevClock
from examples.console.outbox import Outbox
from examples.console.product import (
    AUDIT_EXPORT,
    AUDIT_READ,
    PASSWORDS_MANAGE,
    POLICY_MANAGE,
    SYSLOG_MANAGE,
)
from warden.audit import (
    AnchorError,
    AnchorReport,
    AuditRecorder,
    read_anchors,
    verify_anchors,
)
from warden.audit import anchor as write_anchor
from warden.audit.syslog import SyslogForwarder
from warden.identity import Identity, PolicyError, Principal, require_permission, require_user
from warden.identity.password_policy import WatchListError, WatchListNotFound
from warden.keys import KeyStore

__all__ = ["console_router"]

# The largest anchor export the verify route reads, in bytes.
MAX_ANCHOR_EXPORT = 2_000_000
# A small file of SHA-1 hashes of synthetic passwords, in the downloader's format.
SAMPLE_IMPORT = Path(__file__).resolve().parent / "data" / "synthetic-pwned.txt"


def _policy(policy: Any) -> dict[str, Any]:
    return {
        "access_token_ttl_seconds": policy.access_token_ttl_seconds,
        "refresh_token_ttl_seconds": policy.refresh_token_ttl_seconds,
        "session_lifespan_seconds": policy.session_lifespan_seconds,
        "refresh_reuse_grace_seconds": policy.refresh_reuse_grace_seconds,
        "require_mfa": policy.require_mfa,
    }


def _anchor_report(report: AnchorReport) -> dict[str, Any]:
    chain = report.chain
    return {
        "ok": report.ok,
        "chain": {
            "ok": chain.ok,
            "rows": chain.rows,
            "last_id": chain.last_id,
            "broken": None
            if chain.broken is None
            else {"row_id": chain.broken.row_id, "description": chain.broken.description},
        },
        "anchors": [
            {
                "line": check.line,
                "row_id": check.row_id,
                "head_id": check.head_id,
                "status": check.status,
                "ok": check.ok,
                "description": check.description,
            }
            for check in report.anchors
        ],
    }


def console_router(
    identity: Identity,
    outbox: Outbox,
    recorder: AuditRecorder,
    keys: KeyStore,
    forwarder: SyslogForwarder | None,
    dev_clock: DevClock | None = None,
) -> APIRouter:
    router = APIRouter(tags=["sample: console"])
    User = Annotated[Principal, Depends(require_user)]
    PolicyAdmin = Annotated[Principal, Depends(require_permission(POLICY_MANAGE))]
    AuditReader = Annotated[Principal, Depends(require_permission(AUDIT_READ))]
    AuditWriter = Annotated[Principal, Depends(require_permission(AUDIT_EXPORT))]
    SyslogAdmin = Annotated[Principal, Depends(require_permission(SYSLOG_MANAGE))]
    PasswordAdmin = Annotated[Principal, Depends(require_permission(PASSWORDS_MANAGE))]

    @router.get("/console")
    async def console_settings() -> dict[str, Any]:
        """Where warden's routers are mounted, so the pages need no copy of the configuration."""
        http = identity.config.http
        return {
            "prefixes": {
                "auth": http.auth_prefix,
                "admin": http.admin_prefix,
                "audit": http.audit_prefix,
                "keys": http.keys_prefix,
            },
            "syslog": forwarder is not None,
            # Whether a policy may enable the sealed fingerprint (ruling PW8).
            "fingerprint": identity.config.passwords.fingerprint_available,
            "dev_clock": dev_clock is not None,
        }

    @router.get("/me")
    async def me(principal: User) -> dict[str, Any]:
        return {
            "user_id": str(principal.user_id),
            "email": principal.email,
            "roles": sorted(principal.roles),
            "permissions": sorted(principal.permissions),
            "amr": list(principal.amr),
            "api_key_id": None if principal.api_key_id is None else str(principal.api_key_id),
        }

    @router.get("/outbox")
    async def show_outbox() -> dict[str, Any]:
        return {"messages": outbox.messages()}

    @router.get("/policy")
    async def show_policy(principal: PolicyAdmin) -> dict[str, Any]:
        return {
            "policy": _policy(await identity.policy.current()),
            "defaults": _policy(identity.policy.defaults),
        }

    @router.put("/policy")
    async def change_policy(request: Request, principal: PolicyAdmin) -> JSONResponse:
        body = await request.json()
        if not isinstance(body, dict):
            return JSONResponse({"detail": "the request is not valid"}, status_code=400)
        try:
            policy = await identity.policy.update(actor=str(principal.user_id), **body)
        except (PolicyError, TypeError, ValueError):
            return JSONResponse({"detail": "the policy is not valid"}, status_code=400)
        return JSONResponse({"policy": _policy(policy)})

    @router.post("/policy/reset")
    async def reset_policy(principal: PolicyAdmin) -> dict[str, Any]:
        return {"policy": _policy(await identity.policy.reset(actor=str(principal.user_id)))}

    @router.post("/audit/anchor")
    async def anchor_head(principal: AuditWriter) -> JSONResponse:
        try:
            written = await write_anchor(recorder, keys, actor=str(principal.user_id))
        except AnchorError:
            return JSONResponse({"detail": "the head could not be anchored"}, status_code=409)
        if written is None:
            return JSONResponse({"anchored": None})
        return JSONResponse(
            {
                "anchored": {
                    "row_id": written.row_id,
                    "head_id": written.anchor.head_id,
                    "key_id": written.anchor.key_id,
                    "anchored_at": written.anchor.anchored_at.isoformat(),
                }
            }
        )

    @router.post("/audit/anchors/verify")
    async def check_anchors(request: Request, principal: AuditReader) -> JSONResponse:
        body = await request.body()
        if len(body) > MAX_ANCHOR_EXPORT:
            return JSONResponse({"detail": "the export is too large"}, status_code=413)
        try:
            lines = body.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            return JSONResponse({"detail": "the export is not UTF-8 text"}, status_code=400)
        report = await verify_anchors(identity.db, keys, read_anchors(lines))
        return JSONResponse(_anchor_report(report))

    @router.get("/syslog/settings")
    async def syslog_settings(principal: SyslogAdmin) -> JSONResponse:
        if forwarder is None:
            return JSONResponse({"configured": False, "settings": None})
        return JSONResponse(
            {"configured": True, "settings": forwarder.settings.model_dump(mode="json")}
        )

    @router.post("/passwords/recheck")
    async def recheck_passwords(principal: PasswordAdmin) -> dict[str, int]:
        report = await identity.password_recheck.run(actor=str(principal.user_id))
        return {
            "checked": report.checked,
            "matched": report.matched,
            "flagged": report.flagged,
            "sessions_ended": report.sessions_ended,
            "resealed": report.resealed,
            "unopened": report.unopened,
            "hibp_unavailable": report.hibp_unavailable,
        }

    @router.post("/watch-lists/{list_id}/import-sample")
    async def import_sample(list_id: uuid.UUID, principal: PasswordAdmin) -> JSONResponse:
        lines = SAMPLE_IMPORT.read_text(encoding="utf-8").splitlines()
        try:
            result = await identity.watch_lists.import_hibp(
                list_id, lines, actor=str(principal.user_id)
            )
        except WatchListNotFound:
            return JSONResponse({"detail": "no such watch list"}, status_code=404)
        except WatchListError:
            return JSONResponse(
                {"detail": "only an imported watch list takes the sample file"}, status_code=409
            )
        return JSONResponse(
            {"imported": result.imported, "below_threshold": result.below_threshold}
        )

    if dev_clock is not None:
        # Unauthenticated on purpose: moving the clock forward expires the
        # administrator's own token, and the way back must not need it.
        clock = dev_clock

        @router.get("/dev/clock")
        async def show_clock() -> dict[str, int]:
            return {"offset_days": clock.offset_days}

        @router.put("/dev/clock")
        async def move_clock(request: Request) -> JSONResponse:
            body = await request.json()
            days = body.get("days") if isinstance(body, dict) else None
            try:
                clock.set_days(days)
            except ValueError:
                return JSONResponse({"detail": "the offset is not valid"}, status_code=400)
            return JSONResponse({"offset_days": clock.offset_days})

    return router
