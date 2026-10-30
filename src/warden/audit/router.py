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
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from warden.audit.checkpoint import HistoricalVerifier
from warden.audit.events import Outcome
from warden.audit.export import ExportFormat, export, row_to_json
from warden.audit.query import MAX_PAGE_SIZE, AuditQuery, list_events
from warden.audit.recorder import AuditRecorder
from warden.audit.verify import verify_chain

__all__ = ["audit_router"]

_MEDIA_TYPES: dict[str, str] = {"csv": "text/csv; charset=utf-8", "ndjson": "application/x-ndjson"}


_PRODUCT_REFUSAL = "Refused by the product's `authorise` dependency; the body is the product's."
_REFUSED: dict[int | str, dict[str, Any]] = {
    401: {"description": _PRODUCT_REFUSAL},
    403: {"description": _PRODUCT_REFUSAL},
}
_BAD_FILTER: dict[int | str, dict[str, Any]] = {
    422: {
        "description": (
            "A filter is not valid: FastAPI's validation error (`detail` a list of errors), or "
            '`{"detail": "invalid audit filter"}` (for example `since` not before `until`).'
        ),
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {"detail": {"anyOf": [{"type": "string"}, {"type": "array"}]}},
                    "required": ["detail"],
                },
                "example": {"detail": "invalid audit filter"},
            }
        },
    }
}


class AuditEventView(BaseModel):
    """One audit row, as listed and as exported in NDJSON (documentation only)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    recorded_at: str = Field(description="Server time, ISO 8601 UTC; chain order follows it.")
    occurred_at: str = Field(description="When the event happened, ISO 8601 UTC.")
    action: str
    outcome: Outcome
    actor: str | None
    resource_type: str | None
    resource_id: str | None
    source_ip: str | None
    details: dict[str, Any]
    key_id: str | None = Field(description="The signing key of a checkpoint or anchor row.")
    prev_hash: str = Field(description="Hex SHA-256 of the previous row.")
    row_hash: str = Field(description="Hex SHA-256 of this row.")


class AuditEventPage(BaseModel):
    """A page of events, newest first (documentation only)."""

    model_config = ConfigDict(extra="forbid")

    events: list[AuditEventView]
    next_before_id: int | None = Field(
        description="Pass as `before_id` for the next page; null on the last page."
    )


class BrokenLinkView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    row_id: int
    reason: str = Field(description="A `BreakReason`.")
    description: str


class ChainVerification(BaseModel):
    """The verification report (documentation only)."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    rows: int
    first_id: int | None
    last_id: int | None
    head_hash: str | None = Field(description="Hex SHA-256 of the last row.")
    checkpoints: int
    broken: BrokenLinkView | None = Field(description="The first broken link; null when intact.")


def _query(
    since: Annotated[
        AwareDatetime | None,
        Query(description="`occurred_at` on or after, ISO 8601 with a zone offset."),
    ] = None,
    until: Annotated[
        AwareDatetime | None,
        Query(description="`occurred_at` before, ISO 8601 with a zone offset."),
    ] = None,
    action: Annotated[
        list[str] | None, Query(max_length=50, description="Any of these actions; repeatable.")
    ] = None,
    actor: Annotated[str | None, Query(max_length=512, description="Exactly this actor.")] = None,
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
    router = APIRouter(tags=["warden: audit"])
    can_read = Depends(authorise)
    can_export = Depends(authorise_export or authorise)
    can_verify = Depends(authorise_verify or authorise)
    filters = Depends(_query)

    @router.get(
        "/events",
        summary="List audit events",
        description=(
            "Matching events, newest first, `limit` at a time (1 to 1000, default 100). Pass a "
            "page's `next_before_id` as `before_id` for the next one."
        ),
        responses={
            200: {"model": AuditEventPage, "description": "A page."},
            **_REFUSED,
            **_BAD_FILTER,
        },
    )
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

    @router.get(
        "/export",
        response_class=StreamingResponse,
        summary="Export audit events",
        description=(
            "Every matching event, streamed in chain order from one snapshot. The export is "
            "itself recorded (`warden.audit.export`, with the filter, the caller's actor and "
            "address) before the first line. CSV cells that begin with `=`, `+`, `-`, `@`, a "
            "tab or a carriage return are prefixed with `'`; NDJSON is ASCII-escaped, one row "
            "per line, in the shape of `AuditEventView`."
        ),
        responses={
            200: {
                "description": "An attachment, `audit-export.csv` or `audit-export.ndjson`.",
                "headers": {
                    "content-disposition": {
                        "description": "`attachment`, with the file name.",
                        "schema": {"type": "string"},
                    }
                },
                "content": {
                    "text/csv": {"schema": {"type": "string"}},
                    "application/x-ndjson": {"schema": {"type": "string"}},
                },
            },
            **_REFUSED,
            **_BAD_FILTER,
        },
    )
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

    @router.get(
        "/verify",
        summary="Verify the audit chain",
        description=(
            "Verifies every row's hash and link, and every retention checkpoint's signature, "
            "from one consistent snapshot, and reports the first broken link by row id and "
            "reason, never by row contents."
        ),
        responses={200: {"model": ChainVerification, "description": "The report."}, **_REFUSED},
    )
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
