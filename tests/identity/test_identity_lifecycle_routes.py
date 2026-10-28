"""Public lifecycle routes: accept an invitation, request and complete a password reset."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows

from warden.db import Database
from warden.identity import Identity, SignInMethod

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'
NEW_PASSWORD = "a brand new passphrase"


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.lifecycle_router(), prefix="/auth")
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


async def test_accept_an_invitation(
    identity: Identity, client: httpx.AsyncClient, db: Database, mail: RecordingSender
) -> None:
    invitation = await identity.invitations.create("new@example.com", actor="admin-1")
    response = await client.post(
        "/auth/invitations/accept", json={"token": mail.token(), "password": NEW_PASSWORD}
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted", "email": "new@example.com"}
    assert response.headers["cache-control"] == "no-store"
    signed_in = await client.post(
        "/auth/sign-in", json={"email": "new@example.com", "password": NEW_PASSWORD}
    )
    assert signed_in.status_code == 200
    rows = await audit_rows(db, "warden.identity.invitation.accepted")
    assert rows[-1]["outcome"] == "success"
    assert rows[-1]["resource_id"] == str(invitation.user_id)


@pytest.mark.parametrize(
    "body",
    [
        {"token": "A" * 43, "password": NEW_PASSWORD},
        {"token": None, "password": NEW_PASSWORD},
        {"password": NEW_PASSWORD},
        {},
    ],
)
async def test_a_bad_invitation_gets_the_uniform_refusal(
    client: httpx.AsyncClient, body: dict[str, object]
) -> None:
    response = await client.post("/auth/invitations/accept", json=body)
    assert (response.status_code, response.content) == (401, REFUSAL)


async def test_a_non_json_body_gets_the_uniform_refusal(client: httpx.AsyncClient) -> None:
    response = await client.post("/auth/invitations/accept", content=b"\xff not json")
    assert (response.status_code, response.content) == (401, REFUSAL)


async def test_a_weak_password_is_a_400_and_the_invitation_stays(
    identity: Identity, client: httpx.AsyncClient, mail: RecordingSender
) -> None:
    await identity.invitations.create("weak@example.com", actor="admin-1")
    weak = await client.post(
        "/auth/invitations/accept", json={"token": mail.token(), "password": "short"}
    )
    assert weak.status_code == 400
    assert weak.json() == {"detail": "the password must be at least 12 characters"}
    ok = await client.post(
        "/auth/invitations/accept", json={"token": mail.token(), "password": NEW_PASSWORD}
    )
    assert ok.status_code == 200


async def test_a_password_for_an_sso_only_invitation_is_a_409(
    identity: Identity, client: httpx.AsyncClient, mail: RecordingSender
) -> None:
    await identity.invitations.create(
        "sso@example.com", actor="admin-1", sign_in_method=SignInMethod.SSO_ONLY
    )
    response = await client.post(
        "/auth/invitations/accept", json={"token": mail.token(), "password": NEW_PASSWORD}
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "use single sign-on to accept this invitation"}


async def test_a_reset_request_looks_the_same_whoever_asks(
    client: httpx.AsyncClient, mail: RecordingSender, make_user: UserFactory, db: Database
) -> None:
    known = await make_user("known@example.com")
    sso = await make_user("sso-user@example.com", sign_in_method=SignInMethod.SSO_ONLY)
    responses = [
        await client.post("/auth/password-reset", json={"email": email})
        for email in (known.email, sso.email, "nobody@example.com", "garbage")
    ]
    responses.append(await client.post("/auth/password-reset", content=b"[]"))
    assert {(r.status_code, r.content) for r in responses} == {(202, b'{"status":"requested"}')}
    assert [m.to for m in mail.sent] == ["known@example.com"]
    rows = await audit_rows(db, "warden.identity.password.reset_requested")
    assert [str(r["details"].get("reason")) for r in rows] == [
        "None",
        "sso_only",
        "unknown_user",
        "malformed",
        "malformed",
    ]


async def test_a_failed_send_still_answers_the_same(
    client: httpx.AsyncClient, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    mail.fail = True
    response = await client.post("/auth/password-reset", json={"email": user.email})
    assert (response.status_code, response.content) == (202, b'{"status":"requested"}')


async def test_complete_a_reset(
    client: httpx.AsyncClient, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    await client.post("/auth/password-reset", json={"email": user.email})
    done = await client.post(
        "/auth/password-reset/complete",
        json={"token": mail.token(), "new_password": NEW_PASSWORD},
    )
    assert done.status_code == 204
    again = await client.post(
        "/auth/password-reset/complete",
        json={"token": mail.token(), "new_password": NEW_PASSWORD},
    )
    assert (again.status_code, again.content) == (401, REFUSAL)
    old = await client.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    assert old.status_code == 401


async def test_a_reset_with_a_weak_password_is_a_400(
    client: httpx.AsyncClient, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    await client.post("/auth/password-reset", json={"email": user.email})
    response = await client.post(
        "/auth/password-reset/complete", json={"token": mail.token(), "new_password": "x"}
    )
    assert response.status_code == 400


async def test_a_bad_reset_token_gets_the_uniform_refusal(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/password-reset/complete", json={"token": "B" * 43, "new_password": NEW_PASSWORD}
    )
    assert (response.status_code, response.content) == (401, REFUSAL)
