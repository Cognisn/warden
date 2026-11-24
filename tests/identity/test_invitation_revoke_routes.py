"""Revoking an invitation: 404 for no such user, 409 only for a user who is not invited (#4).

Revoking a pending invitation deletes the invited user, so an invitation
already revoked has no user left: that is the documented 404, not 409.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from identity_support import (
    PASSWORD,
    RecordingSender,
    UserFactory,
    audit_rows,
    complete_sign_in,
    race,
)

from warden.db import Database
from warden.identity import Identity, User

pytestmark = pytest.mark.db

ADDRESS = "198.51.100.20"
NEW_PASSWORD = "a brand new passphrase for this test"


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=(ADDRESS, 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


@pytest.fixture
async def headers(identity: Identity, make_user: UserFactory) -> dict[str, str]:
    admin = await make_user("admin@example.com", roles=("admin",))
    result = await complete_sign_in(identity, admin.email, PASSWORD)
    assert result.tokens is not None
    return {"authorization": f"Bearer {result.tokens.access_token}"}


async def _invite(client: httpx.AsyncClient, headers: dict[str, str], email: str) -> str:
    created = await client.post("/admin/invitations", json={"email": email}, headers=headers)
    assert created.status_code == 201, created.text
    user_id: str = created.json()["user_id"]
    return user_id


async def test_an_unknown_user_is_a_404(client: httpx.AsyncClient, headers: dict[str, str]) -> None:
    answer = await client.delete(f"/admin/invitations/{uuid.uuid4()}", headers=headers)
    assert answer.status_code == 404
    assert answer.json() == {"detail": "not found"}


async def test_an_invitation_already_revoked_is_a_404(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    user_id = await _invite(client, headers, "guest@example.com")
    first = await client.delete(f"/admin/invitations/{user_id}", headers=headers)
    assert first.status_code == 204
    again = await client.delete(f"/admin/invitations/{user_id}", headers=headers)
    assert again.status_code == 404
    assert again.json() == {"detail": "not found"}
    rows = await audit_rows(db, "warden.identity.invitation.revoked")
    assert [(r["outcome"], r["details"].get("reason")) for r in rows] == [
        ("success", None),
        ("failure", "no_such_user"),
    ]


async def test_an_accepted_invitation_is_a_409(
    client: httpx.AsyncClient, headers: dict[str, str], identity: Identity, mail: RecordingSender
) -> None:
    user_id = await _invite(client, headers, "guest@example.com")
    await identity.invitations.accept_with_password(mail.token(), NEW_PASSWORD)
    answer = await client.delete(f"/admin/invitations/{user_id}", headers=headers)
    assert answer.status_code == 409
    assert answer.json() == {"detail": "the invitation is not pending"}
    assert await identity.users.get(uuid.UUID(user_id)) is not None


async def test_a_user_who_was_never_invited_is_a_409(
    client: httpx.AsyncClient, headers: dict[str, str], make_user: UserFactory, db: Database
) -> None:
    user: User = await make_user("member@example.com")
    answer = await client.delete(f"/admin/invitations/{user.id}", headers=headers)
    assert answer.status_code == 409
    rows = await audit_rows(db, "warden.identity.invitation.revoked")
    assert [(r["outcome"], r["details"]["reason"]) for r in rows] == [("failure", "not_pending")]


async def test_two_concurrent_revocations_revoke_once(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    for n in range(6):
        user_id = await _invite(client, headers, f"guest-{n}@example.com")
        url = f"/admin/invitations/{user_id}"
        answers = await race(
            lambda url=url: client.delete(url, headers=headers),
            lambda url=url: client.delete(url, headers=headers),
        )
        assert sorted(a.status_code for a in answers) == [204, 404], answers
        rows = [
            r
            for r in await audit_rows(db, "warden.identity.invitation.revoked")
            if r["resource_id"] == user_id
        ]
        assert [r["outcome"] for r in rows if r["outcome"] == "success"] == ["success"]
        assert [r["details"]["reason"] for r in rows if r["outcome"] == "failure"] == [
            "no_such_user"
        ]
