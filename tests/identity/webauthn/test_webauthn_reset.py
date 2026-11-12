"""The administrator's reset of every second factor (ruling P4, Skuld question 21, answer a).

``DELETE <admin>/users/{user_id}/mfa`` removes TOTP, every security key and
passkey and every recovery code, and ends every session, in one
transaction. ``DELETE <admin>/users/{user_id}/totp`` keeps exactly its
0.1.0b8 behaviour.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import PASSWORD, UserFactory, audit_rows, enrol_totp, race
from soft_authenticator import SoftwareAuthenticator

from warden.db import Database
from warden.identity import Identity, User, UserError

pytestmark = pytest.mark.db

ACTION = "warden.identity.mfa.reset"


@pytest.fixture
async def http(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    transport = httpx.ASGITransport(app=application, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


async def _bearer(http: httpx.AsyncClient, user: User) -> dict[str, str]:
    answer = await http.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    assert answer.json()["status"] == "signed_in", answer.json()
    return {"authorization": f"Bearer {answer.json()['access_token']}"}


async def _register(http: httpx.AsyncClient, headers: dict[str, str]) -> httpx.Response:
    begun = await http.post("/auth/webauthn/registration", json={}, headers=headers)
    assert begun.status_code == 200, begun.text
    response = SoftwareAuthenticator().register(begun.json()["public_key"])
    return await http.post(
        "/auth/webauthn/registration/confirm", json={"credential": response}, headers=headers
    )


async def _admin(http: httpx.AsyncClient, make_user: UserFactory) -> dict[str, str]:
    return await _bearer(http, await make_user(roles=("admin",)))


async def _state(db: Database, user_id: uuid.UUID) -> dict[str, Any]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT"
            " (SELECT count(*) FROM warden.totp_credentials WHERE user_id = %(u)s),"
            " (SELECT count(*) FROM warden.webauthn_credentials WHERE user_id = %(u)s),"
            " (SELECT count(*) FROM warden.recovery_codes WHERE user_id = %(u)s),"
            " (SELECT count(*) FROM warden.sessions WHERE user_id = %(u)s"
            "  AND revoked_at IS NULL)",
            {"u": user_id},
        )
        row = await cur.fetchone()
    assert row is not None
    return dict(zip(("totp", "keys", "codes", "sessions"), row, strict=True))


async def test_the_reset_removes_every_second_factor_and_ends_every_session(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    admin = await _admin(http, make_user)
    user = await make_user()
    headers = await _bearer(http, user)
    await enrol_totp(identity, user)
    for _ in range(2):
        assert (await _register(http, headers)).status_code == 200
    assert await _state(db, user.id) == {"totp": 1, "keys": 2, "codes": 10, "sessions": 1}

    answer = await http.delete(f"/admin/users/{user.id}/mfa", headers=admin)
    assert answer.status_code == 204
    assert answer.content == b""
    assert answer.headers["cache-control"] == "no-store"
    assert await _state(db, user.id) == {"totp": 0, "keys": 0, "codes": 0, "sessions": 0}
    (event,) = await audit_rows(db, ACTION)
    admin_id = (await identity.authenticate(admin["authorization"][7:])).user_id
    assert (event["outcome"], event["actor"], event["resource_id"]) == (
        "success",
        str(admin_id),
        str(user.id),
    )
    assert event["details"] == {
        "totp_removed": True,
        "webauthn_removed": 2,
        "recovery_codes_removed": 10,
        "sessions_ended": 1,
    }
    # The user signs in with the password alone again (the policy requires nothing).
    signed_in = await http.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    assert signed_in.json()["status"] == "signed_in"


async def test_after_a_reset_a_required_second_factor_is_enrolled_again(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    admin = await _admin(http, make_user)  # signed in before a second factor is required
    await identity.policy.update(actor="test", require_mfa=True)
    user = await make_user()
    answer = await http.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    challenge = answer.json()["challenge"]
    begun = await http.post("/auth/webauthn/registration", json={"challenge": challenge})
    response = SoftwareAuthenticator().register(begun.json()["public_key"])
    enrolled = await http.post(
        "/auth/webauthn/registration/confirm", json={"challenge": challenge, "credential": response}
    )
    assert enrolled.status_code == 200
    assert (await http.delete(f"/admin/users/{user.id}/mfa", headers=admin)).status_code == 204
    again = await http.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    assert again.json()["status"] == "mfa_enrolment_required"


async def test_a_reset_is_idempotent_and_still_audited(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    admin = await _admin(http, make_user)
    user = await make_user()
    for _ in range(2):
        assert (await http.delete(f"/admin/users/{user.id}/mfa", headers=admin)).status_code == 204
    events = await audit_rows(db, ACTION)
    assert [e["details"] for e in events] == [
        {
            "totp_removed": False,
            "webauthn_removed": 0,
            "recovery_codes_removed": 0,
            "sessions_ended": 0,
        }
    ] * 2


async def test_no_such_user_is_a_404(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    admin = await _admin(http, make_user)
    for user_id in (str(uuid.uuid4()), "not-a-uuid"):
        answer = await http.delete(f"/admin/users/{user_id}/mfa", headers=admin)
        assert (answer.status_code, answer.json()) == (404, {"detail": "not found"})
    assert await audit_rows(db, ACTION) == []
    with pytest.raises(UserError):
        await identity.reset_mfa(uuid.uuid4(), actor="test")


async def test_the_reset_needs_the_users_permission(
    http: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    headers = await _bearer(http, await make_user(roles=("viewer",)))
    answer = await http.delete(f"/admin/users/{user.id}/mfa", headers=headers)
    assert answer.status_code == 403
    assert (await http.delete(f"/admin/users/{user.id}/mfa")).status_code == 401


async def test_the_totp_reset_keeps_its_published_behaviour(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """DELETE .../totp removes TOTP and the codes, ends sessions, and leaves keys alone."""
    admin = await _admin(http, make_user)
    user = await make_user()
    headers = await _bearer(http, user)
    await enrol_totp(identity, user)
    assert (await _register(http, headers)).status_code == 200
    assert (await http.delete(f"/admin/users/{user.id}/totp", headers=admin)).status_code == 204
    assert await _state(db, user.id) == {"totp": 0, "keys": 1, "codes": 0, "sessions": 0}
    (event,) = await audit_rows(db, ACTION)
    assert event["details"] == {
        "totp_removed": True,
        "recovery_codes_removed": 10,
        "sessions_ended": 1,
    }


async def test_a_reset_between_storing_a_key_and_its_codes_leaves_neither(
    http: httpx.AsyncClient,
    identity: Identity,
    db: Database,
    make_user: UserFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The window the race above can only sometimes hit, opened on purpose."""
    user = await make_user()
    headers = await _bearer(http, user)
    assert identity.webauthn is not None
    finish = identity.webauthn.finish_registration

    async def reset_meanwhile(*args: Any, **kwargs: Any) -> Any:
        registration = await finish(*args, **kwargs)
        await identity.reset_mfa(user.id, actor="test")
        return registration

    monkeypatch.setattr(identity.webauthn, "finish_registration", reset_meanwhile)
    answer = await _register(http, headers)
    assert (answer.status_code, answer.json()) == (400, {"detail": "credential not accepted"})
    state = await _state(db, user.id)
    assert (state["keys"], state["codes"]) == (0, 0)


async def test_a_reset_racing_a_registration_ends_consistent(
    http: httpx.AsyncClient, identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """Either the key (with fresh codes) survives the reset, or neither does."""
    seen: set[tuple[int, int]] = set()
    for _ in range(12):
        user = await make_user()
        headers = await _bearer(http, user)
        begun = await http.post("/auth/webauthn/registration", json={}, headers=headers)
        response = SoftwareAuthenticator().register(begun.json()["public_key"])

        async def confirm(response: Any = response, headers: dict[str, str] = headers) -> Any:
            return await http.post(
                "/auth/webauthn/registration/confirm",
                json={"credential": response},
                headers=headers,
            )

        async def reset(user_id: uuid.UUID = user.id) -> None:
            await identity.reset_mfa(user_id, actor="test")

        outcomes = await race(confirm, reset)
        assert not any(isinstance(o, BaseException) for o in outcomes), outcomes
        state = await _state(db, user.id)
        assert (state["keys"], state["codes"]) in {(0, 0), (1, 10)}, state
        seen.add((state["keys"], state["codes"]))
    assert seen  # every round ended in one of the two consistent states
