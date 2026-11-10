"""Watch list administration (ruling PW7) and the exposure report (PW8).

No route returns a list's entries, terms or hashes. An exact entry is
accepted as plaintext, hashed to SHA-1 at once, and never stored, logged,
echoed or audited: the leak test scans every response, the captured logs,
the audit rows and the stored rows for the plaintext and its SHA-1.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from identity_support import UserFactory, audit_rows
from password_admin_support import bearer, create_policy

from warden.db import Database
from warden.identity import Identity, SignInMethod
from warden.identity.password_policy import (
    ChangeReason,
    WatchListMatch,
    WatchListSource,
)

pytestmark = pytest.mark.db

PLAINTEXT = "Synthetic-Leak-Canary-7731"
OTHER = "Synthetic-Other-Canary-8842"


def _forms(text: str) -> list[str]:
    digest = hashlib.sha1(text.encode()).digest()  # noqa: S324
    return [text, digest.hex(), digest.hex().upper(), digest.hex()[:5], digest.hex().upper()[:5]]


@pytest.fixture
def app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com") as c:
        yield c


@pytest.fixture
async def headers(identity: Identity, make_user: UserFactory) -> dict[str, str]:
    admin = await make_user("admin@example.com", roles=("admin",))
    return await bearer(identity, admin)


async def create_list(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    name: str = "Local",
    kind: str = "manual",
    reason: str = "This password is banned here",
) -> dict[str, Any]:
    response = await client.post(
        "/admin/watch-lists", json={"name": name, "reason": reason, "kind": kind}, headers=headers
    )
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()["watch_list"]
    return created


async def test_create_read_rename_and_set_the_reason(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    created = await create_list(client, headers)
    assert set(created) == {
        "id",
        "name",
        "reason",
        "kind",
        "entry_count",
        "term_count",
        "import_threshold",
        "last_imported_at",
        "policy_ids",
        "created_at",
        "updated_at",
    }
    assert created["kind"] == "manual" and created["entry_count"] == 0
    url = f"/admin/watch-lists/{created['id']}"
    renamed = await client.put(url, json={"name": "Banned here"}, headers=headers)
    assert renamed.status_code == 200 and renamed.json()["watch_list"]["name"] == "Banned here"
    reasoned = await client.put(
        url, json={"reason": "Not allowed at this company"}, headers=headers
    )
    assert reasoned.json()["watch_list"]["reason"] == "Not allowed at this company"
    assert reasoned.json()["watch_list"]["name"] == "Banned here"
    assert (await client.put(url, json={}, headers=headers)).status_code == 400
    assert (await client.put(url, json={"name": ""}, headers=headers)).status_code == 400
    listed = await client.get("/admin/watch-lists", headers=headers)
    assert [w["name"] for w in listed.json()["watch_lists"]] == ["Banned here"]
    assert (await client.get(url, headers=headers)).json()["watch_list"]["id"] == created["id"]
    updated = await audit_rows(db, "warden.identity.watch_list.updated")
    assert [r["details"] for r in updated] == [{"fields": ["name"]}, {"fields": ["reason"]}]


async def test_create_refuses_a_bad_body_and_a_duplicate_name(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await create_list(client, headers)
    for body in (
        {"name": "Local", "reason": "r", "kind": "manual"},
        {"name": "Other", "reason": "r", "kind": "remote"},
        {"name": "Other", "kind": "manual"},
        {"name": "Other\n", "reason": "r", "kind": "manual"},
    ):
        response = await client.post("/admin/watch-lists", json=body, headers=headers)
        assert response.status_code in (400, 409), body
    duplicate = await client.post(
        "/admin/watch-lists",
        json={"name": "Local", "reason": "r", "kind": "manual"},
        headers=headers,
    )
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "a watch list with that name already exists"}


async def test_entries_and_terms_are_counted_never_returned(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    db: Database,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    created = await create_list(client, headers)
    url = f"/admin/watch-lists/{created['id']}"
    texts: list[str] = []

    async def call(method: str, path: str, **kw: Any) -> httpx.Response:
        response = await client.request(method, path, headers=headers, **kw)
        texts.append(response.text)
        return response

    added = await call("POST", f"{url}/entries", json={"passwords": [PLAINTEXT, OTHER, PLAINTEXT]})
    assert added.status_code == 200 and added.json() == {"added": 2}
    again = await call("POST", f"{url}/entries", json={"passwords": [PLAINTEXT]})
    assert again.json() == {"added": 0}
    terms = await call("POST", f"{url}/terms", json={"terms": ["Examplecorp", "canary"]})
    assert terms.json() == {"added": 2}
    shown = (await call("GET", url)).json()["watch_list"]
    assert shown["entry_count"] == 2 and shown["term_count"] == 2
    await call("GET", "/admin/watch-lists")
    removed = await call("POST", f"{url}/entries/removal", json={"passwords": [OTHER]})
    assert removed.json() == {"removed": 1}
    gone = await call("POST", f"{url}/terms/removal", json={"terms": ["CANARY"]})
    assert gone.json() == {"removed": 1}
    assert (await call("GET", url)).json()["watch_list"]["entry_count"] == 1

    # Nothing anywhere carries the plaintext or its SHA-1.
    rows = await audit_rows(db)
    async with db.connection() as conn:
        cur = await conn.execute("SELECT encode(hash, 'hex') FROM warden.watch_list_entries")
        stored = [r[0] for r in await cur.fetchall()]
    assert stored == [hashlib.sha1(PLAINTEXT.encode()).hexdigest()]  # noqa: S324
    haystacks = [*texts, caplog.text, repr(rows)]
    for secret in (*_forms(PLAINTEXT), *_forms(OTHER)):
        for haystack in haystacks:
            assert secret not in haystack
    changed = await audit_rows(db, "warden.identity.watch_list.entries_changed")
    assert [r["details"] for r in changed] == [
        {"entries_added": 2, "entries_removed": 0},
        {"entries_added": 0, "entries_removed": 0},
        {"terms_added": 2, "terms_removed": 0},
        {"entries_added": 0, "entries_removed": 1},
        {"terms_added": 0, "terms_removed": 1},
    ]


async def test_entry_bodies_are_checked_without_echo(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    created = await create_list(client, headers)
    url = f"/admin/watch-lists/{created['id']}/entries"
    for body in ({"passwords": PLAINTEXT}, {"passwords": [PLAINTEXT, 3]}, {"passwords": []}, {}):
        response = await client.post(url, json=body, headers=headers)
        assert response.status_code == 400
        assert PLAINTEXT not in response.text
    too_many = {"passwords": [f"{PLAINTEXT}-{n}" for n in range(101)]}
    assert (await client.post(url, json=too_many, headers=headers)).status_code == 400
    terms = f"/admin/watch-lists/{created['id']}/terms"
    short = await client.post(terms, json={"terms": ["ab"]}, headers=headers)
    assert short.status_code == 400 and "ab" not in short.json()["detail"].split()


async def test_an_imported_list_takes_no_manual_entries(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    imported = await create_list(client, headers, name="Breaches", kind="imported")
    response = await client.post(
        f"/admin/watch-lists/{imported['id']}/entries",
        json={"passwords": [PLAINTEXT]},
        headers=headers,
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "only a manual watch list takes entries and terms"}


async def test_delete_is_refused_while_attached(
    client: httpx.AsyncClient, headers: dict[str, str], db: Database
) -> None:
    created = await create_list(client, headers)
    policy = await create_policy(client, headers)
    attach = f"/admin/password-policies/{policy['id']}/watch-lists/{created['id']}"
    await client.put(attach, headers=headers)
    url = f"/admin/watch-lists/{created['id']}"
    shown = (await client.get(url, headers=headers)).json()["watch_list"]
    assert shown["policy_ids"] == [policy["id"]]
    refused = await client.delete(url, headers=headers)
    assert refused.status_code == 409
    assert refused.json() == {
        "detail": "the watch list is attached to 1 password policy; detach it first"
    }
    assert (await client.get(url, headers=headers)).status_code == 200
    await client.delete(attach, headers=headers)
    assert (await client.delete(url, headers=headers)).status_code == 204
    assert (await client.get(url, headers=headers)).status_code == 404
    assert (await client.delete(url, headers=headers)).status_code == 404
    (row,) = await audit_rows(db, "warden.identity.watch_list.deleted")
    assert row["resource_id"] == created["id"]


async def test_unknown_lists_are_404(client: httpx.AsyncClient, headers: dict[str, str]) -> None:
    for method, suffix, body in (
        ("GET", "", None),
        ("PUT", "", {"name": "x"}),
        ("POST", "/entries", {"passwords": [PLAINTEXT]}),
        ("POST", "/terms", {"terms": ["canary"]}),
    ):
        for list_id in (str(uuid.uuid4()), "nope"):
            response = await client.request(
                method, f"/admin/watch-lists/{list_id}{suffix}", json=body, headers=headers
            )
            assert response.status_code == 404, (method, suffix)


# The exposure report (PW8)


async def test_the_exposure_report_lists_flagged_users_by_list_and_policy(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    identity: Identity,
    make_user: UserFactory,
) -> None:
    listed = await create_list(client, headers)
    policy = await create_policy(client, headers)
    await client.put(
        "/admin/password-policy-roles/analyst", json={"policy_id": policy["id"]}, headers=headers
    )
    list_id = uuid.UUID(listed["id"])
    on_list = [await make_user(roles=("analyst",)) for _ in range(3)]
    breached = await make_user()
    expired = await make_user()
    clean = await make_user()
    match = WatchListMatch(WatchListSource.LIST, list_id, "r")
    for user in on_list:
        await identity.password_states.require_change(user.id, ChangeReason.WATCH_LIST, match=match)
    await identity.password_states.require_change(
        breached.id,
        ChangeReason.WATCH_LIST,
        match=WatchListMatch(WatchListSource.HIBP, None, "r"),
    )
    await identity.password_states.require_change(expired.id, ChangeReason.EXPIRED)

    everything = await client.get("/admin/password-exposures", headers=headers)
    assert everything.status_code == 200
    body = everything.json()
    assert set(body) == {"users", "by_list", "by_policy", "total"}
    assert body["total"] == 4
    flagged = {u["user_id"] for u in body["users"]}
    assert flagged == {str(u.id) for u in (*on_list, breached)}
    assert str(clean.id) not in flagged and str(expired.id) not in flagged
    entry = next(u for u in body["users"] if u["user_id"] == str(on_list[0].id))
    assert entry == {
        "user_id": str(on_list[0].id),
        "source": "list",
        "watch_list_id": listed["id"],
        "policy_id": policy["id"],
    }
    default_id = next(
        p["id"]
        for p in (await client.get("/admin/password-policies", headers=headers)).json()["policies"]
        if p["is_default"]
    )
    assert sorted(body["by_list"], key=lambda r: r["users"]) == [
        {"source": "hibp", "watch_list_id": None, "users": 1},
        {"source": "list", "watch_list_id": listed["id"], "users": 3},
    ]
    assert sorted(body["by_policy"], key=lambda r: r["users"]) == [
        {"policy_id": default_id, "users": 1},
        {"policy_id": policy["id"], "users": 3},
    ]

    seen: list[dict[str, Any]] = []
    url = "/admin/password-exposures?limit=3"
    pages = 0
    while pages < 5:
        page = (await client.get(url, headers=headers)).json()
        seen.extend(page["users"])
        pages += 1
        if page["next"] is None:
            break
        url = f"/admin/password-exposures?limit=3&after={page['next']}"
    assert pages == 2 and seen == body["users"]
    for bad in ("limit=0", "limit=1001", "after=nope", "limit=x"):
        response = await client.get(f"/admin/password-exposures?{bad}", headers=headers)
        assert response.status_code == 400


async def test_the_exposure_report_shows_no_policy_for_a_user_without_a_password(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    identity: Identity,
    make_user: UserFactory,
) -> None:
    sso = await make_user(password=None, sign_in_method=SignInMethod.SSO_ONLY)
    await identity.password_states.require_change(
        sso.id, ChangeReason.WATCH_LIST, match=WatchListMatch(WatchListSource.HIBP, None, "r")
    )
    body = (await client.get("/admin/password-exposures", headers=headers)).json()
    assert body["users"] == [
        {"user_id": str(sso.id), "source": "hibp", "watch_list_id": None, "policy_id": None}
    ]
