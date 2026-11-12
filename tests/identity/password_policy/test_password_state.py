"""Per-user password state (rulings PW5, PW8 and PW9) and forced-change challenges."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from identity_support import race

from warden.db import Database
from warden.identity import User
from warden.identity.crypto import SecretBox
from warden.identity.password_policy.challenges import PasswordChangeChallenges
from warden.identity.password_policy.fingerprint import Fingerprints
from warden.identity.password_policy.state import ChangeReason, PasswordStates
from warden.identity.password_policy.watchlists import WatchListMatch, WatchListSource

pytestmark = pytest.mark.db

SET_AT = datetime(2026, 11, 10, 9, 0, tzinfo=UTC)


@pytest.fixture
def states(db: Database) -> PasswordStates:
    return PasswordStates(db)


async def test_a_set_password_records_tier_and_expiry_only(
    states: PasswordStates, make_user: Any
) -> None:
    # Without a password: setting one records its state too.
    user: User = await make_user(password=None)
    assert await states.get(user.id) is None
    await states.record_set(
        user.id,
        tier="standard",
        set_at=SET_AT,
        expires_at=SET_AT + timedelta(days=90),
        fingerprint=None,
    )
    state = await states.get(user.id)
    assert state is not None
    assert state.tier == "standard"
    assert state.password_set_at == SET_AT
    assert state.expires_at == SET_AT + timedelta(days=90)
    assert state.change_reason is None
    assert not state.has_fingerprint


async def test_a_required_change_carries_its_reason_and_list(
    states: PasswordStates, make_user: Any
) -> None:
    user: User = await make_user()
    listed = uuid.uuid4()
    match = WatchListMatch(source=WatchListSource.HIBP, list_id=None, reason="Breached")
    assert await states.require_change(user.id, ChangeReason.WATCH_LIST, match=match)
    state = await states.get(user.id)
    assert state is not None
    assert state.change_reason == ChangeReason.WATCH_LIST
    assert state.watch_list_source == WatchListSource.HIBP
    assert state.watch_list_id is None
    # A second flag while one stands keeps the first.
    assert not await states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    assert (await states.get(user.id)).change_reason == ChangeReason.WATCH_LIST  # type: ignore[union-attr]
    await states.clear_change(user.id)
    assert (await states.get(user.id)).change_reason is None  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="watch list"):
        await states.require_change(user.id, ChangeReason.EXPIRED, match=match)
    del listed


async def test_setting_a_password_clears_a_required_change(
    states: PasswordStates, make_user: Any
) -> None:
    user: User = await make_user()
    await states.require_change(user.id, ChangeReason.ADMINISTRATOR)
    await states.record_set(user.id, tier=None, set_at=SET_AT, expires_at=None, fingerprint=None)
    assert (await states.get(user.id)).change_reason is None  # type: ignore[union-attr]


async def test_the_fingerprint_is_stored_sealed_and_read_back(
    states: PasswordStates, make_user: Any
) -> None:
    import base64

    from warden.identity.crypto import new_totp_key

    box = Fingerprints(SecretBox(base64.urlsafe_b64decode(new_totp_key() + "=")))
    user: User = await make_user()
    sealed = box.seal(user.id, "a synthetic password")
    await states.store_fingerprint(user.id, sealed)
    assert (await states.get(user.id)).has_fingerprint  # type: ignore[union-attr]
    assert await states.fingerprint(user.id) == sealed
    await states.store_fingerprint(user.id, None)
    assert await states.fingerprint(user.id) is None


@pytest.fixture
def challenges(db: Database) -> PasswordChangeChallenges:
    return PasswordChangeChallenges(db, ttl_seconds=300, max_failures=3)


async def test_a_challenge_opens_once_and_is_used_up_once(
    challenges: PasswordChangeChallenges, db: Database, make_user: Any
) -> None:
    user: User = await make_user()
    async with db.transaction() as tx:
        token = await challenges.create(tx, user.id, ChangeReason.EXPIRED)
    async with db.connection() as conn:
        challenge = await challenges.open(conn, token)
    assert challenge is not None
    assert challenge.user_id == user.id and challenge.reason == ChangeReason.EXPIRED

    async def consume() -> bool:
        async with db.transaction() as tx:
            return await challenges.consume(tx, challenge)

    outcomes = await race(consume, consume, consume)
    assert sorted(outcomes) == [False, False, True]
    async with db.connection() as conn:
        assert await challenges.open(conn, token) is None


async def test_a_challenge_is_held_as_a_hash(
    challenges: PasswordChangeChallenges, db: Database, make_user: Any
) -> None:
    user: User = await make_user()
    async with db.transaction() as tx:
        token = await challenges.create(tx, user.id, ChangeReason.POLICY)
    async with db.connection() as conn:
        cur = await conn.execute("SELECT token_hash FROM warden.password_change_challenges")
        (stored,) = await cur.fetchone()  # type: ignore[misc]
    assert token.encode() not in bytes(stored)
    assert len(bytes(stored)) == 32


async def test_failures_use_a_challenge_up(
    challenges: PasswordChangeChallenges, db: Database, make_user: Any
) -> None:
    user: User = await make_user()
    async with db.transaction() as tx:
        token = await challenges.create(tx, user.id, ChangeReason.ADMINISTRATOR)
    async with db.connection() as conn:
        challenge = await challenges.open(conn, token)
    assert challenge is not None
    for _ in range(3):
        await challenges.record_failure(challenge)
    async with db.connection() as conn:
        assert await challenges.open(conn, token) is None


@pytest.mark.parametrize("token", ["", "short", "x" * 500, "bad token!", 42, None])
async def test_a_malformed_token_opens_nothing(
    challenges: PasswordChangeChallenges, db: Database, token: object
) -> None:
    async with db.connection() as conn:
        assert await challenges.open(conn, token) is None


async def test_an_expired_challenge_opens_nothing_and_is_pruned(
    db: Database, make_user: Any
) -> None:
    short = PasswordChangeChallenges(db, ttl_seconds=300, max_failures=3)
    user: User = await make_user()
    async with db.transaction() as tx:
        token = await short.create(tx, user.id, ChangeReason.EXPIRED)
        await tx.execute(
            "UPDATE warden.password_change_challenges"
            " SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'"
        )
    async with db.connection() as conn:
        assert await short.open(conn, token) is None
    assert await short.prune() == 1


async def test_a_watch_list_challenge_keeps_the_match(
    challenges: PasswordChangeChallenges, db: Database, make_user: Any
) -> None:
    user: User = await make_user()
    match = WatchListMatch(source=WatchListSource.BUILTIN, list_id=None, reason="Too common")
    async with db.transaction() as tx:
        token = await challenges.create(tx, user.id, ChangeReason.WATCH_LIST, match=match)
    async with db.connection() as conn:
        challenge = await challenges.open(conn, token)
    assert challenge is not None
    assert challenge.watch_list_source == WatchListSource.BUILTIN
