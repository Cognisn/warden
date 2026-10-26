"""FastAPI routes for the audit trail: list, export and verify.

warden's audit subsystem knows nothing of users (design D11), so the product
supplies the authorisation as an ordinary FastAPI dependency. It refuses by
raising (typically ``HTTPException(403)``) and otherwise returns the actor
identifier recorded against exports, or ``None``. Exports may need a
stronger dependency than reading; verification defaults to the reading one.

    app.include_router(
        audit_router(recorder=recorder, keys=key_store, authorise=require_auditor),
        prefix=config.http.audit_prefix,
    )

Routes, relative to the mount prefix:

- ``GET /events``: matching events, newest first, a page at a time.
- ``GET /export?format=csv|ndjson``: every matching event, streamed in chain
  order; the export itself is audited first, with the caller's address.
- ``GET /verify``: the chain verification report.
"""

# No `from __future__ import annotations`: FastAPI resolves the routes' annotations
# at definition time, and they refer to dependencies local to audit_router.

from collections.abc import Callable
from ipaddress import ip_address
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import AwareDatetime, ValidationError

from warden.audit.checkpoint import HistoricalVerifier
from warden.audit.events import Outcome
from warden.audit.export import ExportFormat, export, row_to_json
from warden.audit.query import MAX_PAGE_SIZE, AuditQuery, list_events
from warden.audit.recorder import AuditRecorder
from warden.audit.verify import verify_chain

__all__ = ["audit_router"]

_MEDIA_TYPES: dict[str, str] = {"csv": "text/csv; charset=utf-8", "ndjson": "application/x-ndjson"}


def _query(
    since: Annotated[AwareDatetime | None, Query()] = None,
    until: Annotated[AwareDatetime | None, Query()] = None,
    action: Annotated[list[str] | None, Query(max_length=50)] = None,
    actor: Annotated[str | None, Query(max_length=512)] = None,
    resource_type: Annotated[str | None, Query(max_length=512)] = None,
    resource_id: Annotated[str | None, Query(max_length=512)] = None,
    outcome: Annotated[Outcome | None, Query()] = None,
) -> AuditQuery:
    try:
        return AuditQuery(
            since=since,
            until=until,
            actions=tuple(action or ()),
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
        )
    except ValidationError:
        raise HTTPException(status_code=422, detail="invalid audit filter") from None


def audit_router(
    *,
    recorder: AuditRecorder,
    keys: HistoricalVerifier,
    authorise: Callable[..., Any],
    authorise_export: Callable[..., Any] | None = None,
    authorise_verify: Callable[..., Any] | None = None,
) -> APIRouter:
    """The audit routes, each guarded by the product's authorisation dependency."""
    router = APIRouter()
    can_read = Depends(authorise)
    can_export = Depends(authorise_export or authorise)
    can_verify = Depends(authorise_verify or authorise)
    filters = Depends(_query)

    @router.get("/events")
    async def list_audit_events(
        query: Annotated[AuditQuery, filters],
        _actor: Annotated[Any, can_read],
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 100,
        before_id: Annotated[int | None, Query(ge=1)] = None,
    ) -> dict[str, Any]:
        page = await list_events(recorder.db, query, limit=limit, before_id=before_id)
        return {
            "events": [row_to_json(row) for row in page.rows],
            "next_before_id": page.next_before_id,
        }

    @router.get("/export")
    async def export_audit_events(
        request: Request,
        format: Annotated[ExportFormat, Query()],
        query: Annotated[AuditQuery, filters],
        actor: Annotated[Any, can_export],
    ) -> StreamingResponse:
        client = request.client.host if request.client else None
        lines = await export(
            recorder,
            query,
            format,
            actor=actor if isinstance(actor, str) else None,
            source_ip=_address_or_none(client),
        )
        return StreamingResponse(
            lines,
            media_type=_MEDIA_TYPES[format],
            headers={"content-disposition": f'attachment; filename="audit-export.{format}"'},
        )

    @router.get("/verify")
    async def verify_audit_chain(_actor: Annotated[Any, can_verify]) -> dict[str, Any]:
        report = await verify_chain(recorder.db, keys)
        broken = report.broken
        return {
            "ok": report.ok,
            "rows": report.rows,
            "first_id": report.first_id,
            "last_id": report.last_id,
            "head_hash": None if report.head_hash is None else report.head_hash.hex(),
            "checkpoints": report.checkpoints,
            "broken": None
            if broken is None
            else {
                "row_id": broken.row_id,
                "reason": broken.reason,
                "description": broken.description,
            },
        }

    return router


def _address_or_none(host: str | None) -> str | None:
    """The peer as an address, or ``None`` for a non-address peer (a test client, a socket)."""
    if host is None:
        return None
    try:
        return str(ip_address(host))
    except ValueError:
        return None
