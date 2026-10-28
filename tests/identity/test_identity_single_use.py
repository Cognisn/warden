"""Single-use tokens: hashed, expiring, consumed once by one guarded write (#127)."""

from __future__ import annotations

import asyncio
import hashlib
import uuid

import pytest
from identity_support import UserFactory, race

from warden.db import Database
from warden.identity.single_use import Purpose, SingleUseTokens

pytestmark = pytest.mark.db


@pytest.fixture
def tokens(db: Database) -> SingleUseTokens:
    return SingleUseTokens(db)


async def _issue(
    db: Database, tokens: SingleUseTokens, user_id: uuid.UUID, purpose: Purpose, ttl: int = 3600
) -> str:
    async with db.transaction() as tx:
        issued = await tokens.issue(tx, user_id, purpose, ttl_seconds=ttl, created_by="test")
    return issued.token


async def _consume(db: Database, tokens: SingleUseTokens, token: object, purpose: Purpose) -> bool:
    async with db.transaction() as tx:
        return await tokens.consume(tx, token, purpose) is not None


async def test_a_token_is_consumed_once(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    user = await make_user()
    token = await _issue(db, tokens, user.id, Purpose.PASSWORD_RESET)
    async with db.transaction() as tx:
        consumed = await tokens.consume(tx, token, Purpose.PASSWORD_RESET)
    assert consumed is not None and consumed.user_id == user.id
    assert not await _consume(db, tokens, token, Purpose.PASSWORD_RESET)


async def test_a_token_is_stored_only_as_its_hash(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    user = await make_user()
    async with db.transaction() as tx:
        issued = await tokens.issue(
            tx, user.id, Purpose.INVITATION, ttl_seconds=600, created_by="test"
        )
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT token_hash, expires_at, created_by FROM warden.single_use_tokens WHERE id = %s",
            (issued.id,),
        )
        row = await cur.fetchone()
    assert row is not None
    assert bytes(row[0]) == hashlib.sha256(issued.token.encode("ascii")).digest()
    # The expiry handed back is the row's own, not a second clock reading.
    assert row[1] == issued.expires_at
    assert row[2] == "test"


async def test_a_token_serves_only_its_own_purpose(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    user = await make_user()
    token = await _issue(db, tokens, user.id, Purpose.INVITATION)
    assert not await _consume(db, tokens, token, Purpose.PASSWORD_RESET)
    assert await _consume(db, tokens, token, Purpose.INVITATION)


async def test_an_expired_token_is_refused(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    user = await make_user()
    token = await _issue(db, tokens, user.id, Purpose.PASSWORD_RESET)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.single_use_tokens SET created_at = now() - interval '2 hours',"
            " expires_at = now() - interval '1 second'"
        )
    assert not await _consume(db, tokens, token, Purpose.PASSWORD_RESET)
    async with db.transaction() as tx:
        assert await tokens.lock_live(tx, token, Purpose.PASSWORD_RESET) is None


async def test_revoking_a_users_tokens(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    user = await make_user()
    first = await _issue(db, tokens, user.id, Purpose.PASSWORD_RESET)
    second = await _issue(db, tokens, user.id, Purpose.PASSWORD_RESET)
    invitation = await _issue(db, tokens, user.id, Purpose.INVITATION)
    async with db.transaction() as tx:
        assert await tokens.revoke_live(tx, user.id, Purpose.PASSWORD_RESET) == 2
    assert not await _consume(db, tokens, first, Purpose.PASSWORD_RESET)
    assert not await _consume(db, tokens, second, Purpose.PASSWORD_RESET)
    assert await _consume(db, tokens, invitation, Purpose.INVITATION)


@pytest.mark.parametrize(
    "token",
    [None, 7, "", "short", "a" * 43 + "\n", chr(0x0661) * 43, "a" * 44, "a" * 42, "!" * 43],
)
async def test_malformed_tokens_are_refused_cleanly(
    db: Database, tokens: SingleUseTokens, token: object
) -> None:
    async with db.transaction() as tx:
        assert await tokens.consume(tx, token, Purpose.INVITATION) is None
        assert await tokens.lock_live(tx, token, Purpose.INVITATION) is None
        assert await tokens.owner(tx, token, Purpose.INVITATION) is None


async def test_concurrent_consumes_use_a_token_once(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    """#127: concurrent submits of one token: exactly one wins, every time."""
    user = await make_user()
    for _ in range(5):
        token = await _issue(db, tokens, user.id, Purpose.INVITATION)
        results = await race(
            *[lambda token=token: _consume(db, tokens, token, Purpose.INVITATION) for _ in range(5)]
        )
        assert sorted(results) == [False, False, False, False, True]


async def test_lock_live_holds_the_token_until_the_holder_ends(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    """A pre-consume decision under lock_live cannot be overtaken by another request."""
    user = await make_user()
    token = await _issue(db, tokens, user.id, Purpose.INVITATION)
    holder_locked = asyncio.Event()
    release = asyncio.Event()

    async def holder() -> None:
        async with db.transaction() as tx:
            assert await tokens.lock_live(tx, token, Purpose.INVITATION) is not None
            holder_locked.set()
            await release.wait()
            assert await tokens.consume(tx, token, Purpose.INVITATION) is not None

    async def contender() -> object:
        await holder_locked.wait()
        async with db.transaction() as tx:
            return await tokens.lock_live(tx, token, Purpose.INVITATION)

    holding = asyncio.create_task(holder())
    contending = asyncio.create_task(contender())
    await holder_locked.wait()
    await asyncio.sleep(0.3)
    assert not contending.done(), "lock_live did not wait for the holder"
    release.set()
    await holding
    # Once the holder consumed and committed, the contender sees no live token.
    assert await contending is None


async def test_owner_names_the_user_whatever_the_tokens_state(
    db: Database, tokens: SingleUseTokens, make_user: UserFactory
) -> None:
    user = await make_user()
    token = await _issue(db, tokens, user.id, Purpose.INVITATION)
    assert await _consume(db, tokens, token, Purpose.INVITATION)
    async with db.transaction() as tx:
        assert await tokens.owner(tx, token, Purpose.INVITATION) == user.id
        assert await tokens.owner(tx, token, Purpose.PASSWORD_RESET) is None
