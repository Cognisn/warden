"""The sample console's own routes pass the client address, as a product should (GitHub #3).

The session policy, the password recheck and the sample watch-list import go
through warden's Python API, not a warden route, so the console's routes
must hand the client address to warden themselves. Each test checks every
row the call wrote.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable
from typing import Any

import httpx
import pytest
from console_support import bearer, make_user, sign_in

pytestmark = pytest.mark.db

ADDRESS = "2001:db8::10"


@pytest.fixture
async def client(console: Any) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=console.app, client=(ADDRESS, 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8040") as c:
        yield c


@pytest.fixture
async def headers(console: Any, client: httpx.AsyncClient) -> dict[str, str]:
    await make_user(console, "admin@example.com", "administrator")
    return bearer(await sign_in(client, "admin@example.com"))


async def _recorded(
    console: Any, call: Awaitable[httpx.Response], *expected: str, status: int = 200
) -> httpx.Response:
    db = console.identity.db
    async with db.connection() as conn:
        cur = await conn.execute("SELECT coalesce(max(id), 0) FROM warden.audit_events")
        row = await cur.fetchone()
    response = await call
    assert response.status_code == status, response.text
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT action, host(source_ip) FROM warden.audit_events WHERE id > %s ORDER BY id",
            (row[0],),
        )
        rows = [(r[0], r[1]) for r in await cur.fetchall()]
    for action in expected:
        assert action in [a for a, _ in rows], (action, rows)
    assert all(address == ADDRESS for _, address in rows), rows
    return response


async def test_changing_and_resetting_the_session_policy_record_the_address(
    console: Any, client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await _recorded(
        console,
        client.put(
            "/admin/session-policy", json={"refresh_reuse_grace_seconds": 5}, headers=headers
        ),
        "warden.identity.policy.changed",
    )
    await _recorded(
        console,
        client.post("/admin/session-policy/reset", headers=headers),
        "warden.identity.policy.changed",
    )


async def test_a_body_naming_source_ip_is_refused(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.put(
        "/admin/session-policy", json={"source_ip": "198.51.100.1"}, headers=headers
    )
    assert response.status_code == 400


async def test_a_recheck_records_the_address(
    console: Any, client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    await _recorded(
        console,
        client.post("/api/passwords/recheck", headers=headers),
        "warden.identity.password.recheck_completed",
    )


async def test_importing_the_sample_file_records_the_address(
    console: Any, client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    created = await client.post(
        "/admin/watch-lists",
        json={"name": "Imported", "reason": "breached", "kind": "imported"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    list_id = created.json()["watch_list"]["id"]
    await _recorded(
        console,
        client.post(f"/api/watch-lists/{list_id}/import-sample", headers=headers),
        "warden.identity.watch_list.imported",
    )


async def test_anchoring_the_head_records_the_address(
    console: Any, client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    answer = await _recorded(
        console, client.post("/api/audit/anchor", headers=headers), "warden.audit.anchor"
    )
    assert answer.json()["anchored"] is not None
