"""The passkey options route is throttled by source address.

``POST <auth>/passkey/options`` takes one attempt from its address's own
budget (``identity.sign_in_attempt_limit`` per ``sign_in_window_seconds``)
before it issues a challenge. Once the budget is spent it gives the
uniform refusal, issues no challenge, and records the reason in the audit
trail only. The budget is its own: it spends neither the passkey sign-in
budgets nor the password one, and a passkey sign-in that issues a session
clears it for its address.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from identity_support import (
    FAST_HASHER,
    PASSWORD,
    MemorySecrets,
    RecordingSender,
    audit_rows,
    race,
)
from passkey_support import (
    assert_refused,
    give_passkey,
    http_client,
    passkey_assertion,
    passkey_config,
    passkey_options,
    passkey_sign_in,
)
from soft_authenticator import other_key

from warden.db import Database
from warden.identity import Identity, PermissionRegistry, User
from warden.keys import KeyStore

pytestmark = pytest.mark.db

LIMIT = 3
HERE = ("198.51.100.40", 41000)
ELSEWHERE = ("203.0.113.40", 41000)


@pytest.fixture
async def throttled(
    db: Database,
    keys: KeyStore,
    permissions: PermissionRegistry,
    secrets: MemorySecrets,
    mail: RecordingSender,
) -> Identity:
    return Identity(
        passkey_config(sign_in_attempt_limit=LIMIT),
        db,
        keys,
        permissions,
        secrets=secrets,
        hasher=FAST_HASHER,
        mail_sender=mail,
    )


@pytest.fixture
async def here(throttled: Identity) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(throttled, HERE) as client:
        yield client


@pytest.fixture
async def elsewhere(throttled: Identity) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(throttled, ELSEWHERE) as client:
        yield client


async def _challenges(db: Database) -> int:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.webauthn_challenges")
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def _passkey_failures(db: Database) -> list[dict[str, Any]]:
    return [
        r
        for r in await audit_rows(db, "warden.identity.sign_in")
        if r["outcome"] == "failure" and r["details"].get("method") == "passkey"
    ]


async def _user_with_passkey(identity: Identity) -> tuple[User, Any]:
    user = await identity.users.create(
        f"options-{uuid.uuid4().hex[:8]}@example.com", actor="test", password=PASSWORD
    )
    key, _ = await give_passkey(identity, user)
    return user, key


async def _spend(http: httpx.AsyncClient, count: int = LIMIT) -> None:
    for _ in range(count):
        answer = await passkey_options(http)
        assert answer.status_code == 200, answer.text


# The limit.


async def test_the_options_route_refuses_once_its_address_has_spent_its_budget(
    here: httpx.AsyncClient, db: Database
) -> None:
    await _spend(here)
    before = await _challenges(db)
    assert_refused(await passkey_options(here))
    assert await _challenges(db) == before, "a refused options call issued a challenge"


async def test_a_refused_options_call_is_audited_with_its_reason_only(
    here: httpx.AsyncClient, db: Database
) -> None:
    await _spend(here)
    assert await _passkey_failures(db) == []
    assert_refused(await passkey_options(here))
    failures = await _passkey_failures(db)
    assert len(failures) == 1
    assert failures[0]["details"] == {"reason": "options_throttled", "method": "passkey"}
    assert failures[0]["actor"] is None


async def test_concurrent_options_calls_from_one_address_never_exceed_the_limit(
    throttled: Identity, db: Database
) -> None:
    """Barriered concurrent requests: exactly the limit get a challenge, each round."""
    for round_number in range(3):
        async with http_client(throttled, (f"192.0.2.{50 + round_number}", 1)) as http:
            before = await _challenges(db)
            answers = await race(*(lambda: passkey_options(http) for _ in range(8)))
            statuses = sorted(a.status_code for a in answers)
            assert statuses == [200] * LIMIT + [401] * (8 - LIMIT), answers
            for answer in answers:
                if answer.status_code == 401:
                    assert_refused(answer)
            assert await _challenges(db) == before + LIMIT


async def test_another_address_is_unaffected(
    here: httpx.AsyncClient, elsewhere: httpx.AsyncClient
) -> None:
    await _spend(here)
    assert_refused(await passkey_options(here))
    await _spend(elsewhere)


# The refusal is the one passkey sign-in already gives.


async def test_the_refusal_is_byte_identical_to_a_throttled_passkey_sign_in(
    throttled: Identity, here: httpx.AsyncClient, elsewhere: httpx.AsyncClient, db: Database
) -> None:
    _, key = await _user_with_passkey(throttled)
    await _spend(here)
    refused_options = await passkey_options(here)
    # Spend the other address's passkey sign-in budget, with options from fresh
    # addresses, so that only sign-in is throttled there.
    for attempt in range(LIMIT + 1):
        async with http_client(throttled, (f"192.0.2.{70 + attempt}", 1)) as fetcher:
            tamper = {"signing_key": other_key()} if attempt < LIMIT else {}
            credential = await passkey_assertion(fetcher, key, **tamper)
        answer = await passkey_sign_in(elsewhere, credential)
        assert_refused(answer)
    refused_sign_in = answer
    assert (await _passkey_failures(db))[-1]["details"]["reason"] == "throttled"
    assert_refused(refused_options)
    assert_refused(refused_sign_in)
    assert refused_options.status_code == refused_sign_in.status_code
    assert refused_options.content == refused_sign_in.content
    assert sorted(refused_options.headers.items()) == sorted(refused_sign_in.headers.items())


# The budget is the options route's own.


async def test_a_spent_options_budget_leaves_passkey_and_password_sign_in_alone(
    throttled: Identity, here: httpx.AsyncClient, elsewhere: httpx.AsyncClient
) -> None:
    user, key = await _user_with_passkey(throttled)
    await _spend(here)
    assert_refused(await passkey_options(here))
    # A passkey sign-in from the throttled address, with options fetched elsewhere.
    answer = await passkey_sign_in(here, await passkey_assertion(elsewhere, key))
    assert answer.status_code == 200, answer.text
    await _spend(here, LIMIT - 1)  # the sign-in cleared this address's options count
    # Password sign-in from the same address.
    signed_in = await here.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    assert signed_in.status_code == 200, signed_in.text


async def test_failed_passkey_sign_ins_do_not_spend_the_options_budget(
    throttled: Identity, here: httpx.AsyncClient, elsewhere: httpx.AsyncClient
) -> None:
    _, key = await _user_with_passkey(throttled)
    for _ in range(LIMIT):
        bad = await passkey_assertion(elsewhere, key, signing_key=other_key())
        assert_refused(await passkey_sign_in(here, bad))
    await _spend(here)


async def test_failed_password_sign_ins_do_not_spend_the_options_budget(
    throttled: Identity, here: httpx.AsyncClient
) -> None:
    user, _ = await _user_with_passkey(throttled)
    for _ in range(LIMIT + 1):
        assert_refused(
            await here.post("/auth/sign-in", json={"email": user.email, "password": "x"})
        )
    await _spend(here)


async def test_a_passkey_sign_in_clears_the_options_count_for_its_address(
    throttled: Identity, here: httpx.AsyncClient
) -> None:
    _, key = await _user_with_passkey(throttled)
    await _spend(here, LIMIT - 1)
    answer = await passkey_sign_in(here, await passkey_assertion(here, key))  # the last one
    assert answer.status_code == 200, answer.text
    await _spend(here)
    assert_refused(await passkey_options(here))


async def test_a_refused_passkey_sign_in_does_not_clear_the_options_count(
    throttled: Identity, here: httpx.AsyncClient
) -> None:
    _, key = await _user_with_passkey(throttled)
    await _spend(here, LIMIT - 1)
    bad = await passkey_assertion(here, key, signing_key=other_key())  # the last one
    assert_refused(await passkey_sign_in(here, bad))
    assert_refused(await passkey_options(here))
