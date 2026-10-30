"""The sample product's own resource: notes, gated by warden's permissions.

It shows the three things a product does with warden's authorisation:

- ``require_permission`` on each route, with permissions the product declared;
- a resource-scope hook that narrows ``notes.write`` to the note's owner
  (unless the caller also holds ``notes.admin``); the hook can narrow a
  permission, never grant one;
- a product audit event for every change, recorded through ``record_audit``.

Notes are kept in memory: the sample has no tables of its own.
"""

# No ``from __future__ import annotations``: FastAPI must resolve the route
# signatures, which use dependency aliases local to ``notes_router``.

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from examples.console.product import (
    NOTE_CREATED,
    NOTE_DELETED,
    NOTE_UPDATED,
    NOTES_ADMIN,
    NOTES_READ,
    NOTES_WRITE,
)
from warden.audit import AuditEvent, record_audit
from warden.identity import Principal, require_permission

__all__ = ["Note", "NoteScope", "Notes", "notes_router"]


@dataclass
class Note:
    id: uuid.UUID
    owner: uuid.UUID
    title: str
    body: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None

    def view(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "owner": str(self.owner),
            "title": self.title,
            "body": self.body,
            "created_at": self.created_at.isoformat(),
            "updated_at": None if self.updated_at is None else self.updated_at.isoformat(),
        }


class Notes:
    """The in-memory note store."""

    def __init__(self) -> None:
        self._notes: dict[uuid.UUID, Note] = {}

    def all(self) -> list[Note]:
        return sorted(self._notes.values(), key=lambda n: n.created_at)

    def get(self, note_id: str) -> Note | None:
        try:
            return self._notes.get(uuid.UUID(note_id))
        except ValueError:
            return None

    def add(self, note: Note) -> None:
        self._notes[note.id] = note

    def remove(self, note: Note) -> None:
        self._notes.pop(note.id, None)


class NoteScope:
    """The product's resource-scope hook (warden's ``ResourceScopeHook``).

    warden calls it only after the user is known to hold ``permission``.
    Writing a particular note is allowed to its owner and to holders of
    ``notes.admin``; anything else the hook does not narrow.
    """

    def __init__(self, notes: Notes) -> None:
        self._notes = notes

    async def __call__(self, principal: Principal, permission: str, request: Request) -> bool:
        if permission != NOTES_WRITE:
            return True
        note_id = request.path_params.get("note_id")
        if note_id is None:
            return True
        note = self._notes.get(str(note_id))
        if note is None:
            # Unknown notes are reported as not found by the route itself.
            return True
        return note.owner == principal.user_id or NOTES_ADMIN in principal.permissions


class NoteBody(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=10_000)


def _source(request: Request) -> IPv4Address | IPv6Address | None:
    """The client address (already resolved by the trusted-proxy middleware), if it is one."""
    host = request.client.host if request.client else None
    try:
        return None if host is None else ip_address(host)
    except ValueError:
        return None


async def _audit(action: str, principal: Principal, note: Note, request: Request) -> None:
    await record_audit(
        AuditEvent(
            action=action,
            outcome="success",
            actor=str(principal.user_id),
            resource_type="note",
            resource_id=str(note.id),
            source_ip=_source(request),
            details={"title": note.title},
        )
    )


def notes_router(notes: Notes) -> APIRouter:
    """``/notes`` routes; the sample mounts them under ``/api``."""
    router = APIRouter(tags=["sample: notes"])
    Reader = Annotated[Principal, Depends(require_permission(NOTES_READ))]
    Writer = Annotated[Principal, Depends(require_permission(NOTES_WRITE))]
    ScopedWriter = Annotated[Principal, Depends(require_permission(NOTES_WRITE, scoped=True))]

    def found(note_id: str) -> Note:
        note = notes.get(note_id)
        if note is None:
            raise HTTPException(status_code=404, detail="not found")
        return note

    @router.get("/notes")
    async def list_notes(principal: Reader) -> dict[str, Any]:
        return {"notes": [n.view() for n in notes.all()]}

    @router.post("/notes", status_code=201)
    async def create_note(body: NoteBody, request: Request, principal: Writer) -> JSONResponse:
        note = Note(id=uuid.uuid4(), owner=principal.user_id, title=body.title, body=body.body)
        notes.add(note)
        await _audit(NOTE_CREATED, principal, note, request)
        return JSONResponse(note.view(), status_code=201)

    @router.put("/notes/{note_id}")
    async def update_note(
        note_id: str, body: NoteBody, request: Request, principal: ScopedWriter
    ) -> dict[str, Any]:
        note = found(note_id)
        note.title, note.body, note.updated_at = body.title, body.body, datetime.now(UTC)
        await _audit(NOTE_UPDATED, principal, note, request)
        return note.view()

    @router.delete("/notes/{note_id}", status_code=204)
    async def delete_note(note_id: str, request: Request, principal: ScopedWriter) -> Response:
        note = found(note_id)
        notes.remove(note)
        await _audit(NOTE_DELETED, principal, note, request)
        return Response(status_code=204)

    return router
