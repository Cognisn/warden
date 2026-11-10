"""Password history (ruling PW6): Argon2id only, real verification, minimum age, pruning."""

from __future__ import annotations

import asyncio
import dataclasses
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from identity_support import FAST_HASHER

from warden.db import Database
from warden.identity import PermissionRegistry, User
from warden.identity.password_policy import PasswordRules
from warden.identity.password_policy.history import PasswordHistory
from warden.identity.password_policy.state import PasswordStates
from warden.identity.password_policy.store import PasswordPolicies, PolicySettings

pytestmark = pytest.mark.db

OLD = ["first synthetic secret 1", "second synthetic secret 2", "third synthetic secret 3"]


@pytest.fixture
def history(db: Database) -> PasswordHistory:
    return PasswordHistory(db, FAST_HASHER)


async def _remember(history: PasswordHistory, user: User, passwords: list[str]) -> None:
    for password in passwords:
        await history.record(user.id, await FAST_HASHER.hash(password))


async def test_a_previous_password_is_found_within_the_count(
    history: PasswordHistory, make_user: Any
) -> None:
    user: User = await make_user()
    await _remember(history, user, OLD)
    assert await history.reused(user.id, OLD[2], count=1)
    assert await history.reused(user.id, OLD[0], count=3)
    # Beyond the count, the oldest is not checked.
    assert not await history.reused(user.id, OLD[0], count=2)
    assert not await history.reused(user.id, "a password never used", count=24)
    assert not await history.reused(user.id, OLD[2], count=0)


async def test_history_is_per_user(history: PasswordHistory, make_user: Any) -> None:
    user: User = await make_user()
    other: User = await make_user()
    await _remember(history, user, OLD)
    assert not await history.reused(other.id, OLD[2], count=24)


async def test_only_argon2id_hashes_are_kept(history: PasswordHistory, make_user: Any) -> None:
    user: User = await make_user()
    with pytest.raises(ValueError, match="Argon2id"):
        await history.record(user.id, "pbkdf2:sha256:1000$salt$" + "0" * 64)


async def test_each_check_is_a_real_verification_off_the_event_loop(
    db: Database, make_user: Any
) -> None:
    threads: list[str] = []

    class Watching(type(FAST_HASHER)):  # type: ignore[misc]
        async def verify(self, encoded: str, password: str) -> Any:
            threads.append("called")
            return await super().verify(encoded, password)

    watcher = Watching(time_cost=1, memory_cost=8192, parallelism=1)
    history = PasswordHistory(db, watcher)
    user: User = await make_user()
    await _remember(history, user, OLD)
    main = threading.get_ident()
    seen: list[int] = []
    original = watcher._verify_argon2

    def spy(encoded: str, password: str) -> Any:
        seen.append(threading.get_ident())
        return original(encoded, password)

    watcher._verify_argon2 = spy  # type: ignore[method-assign]
    assert not await history.reused(user.id, "a password never used", count=3)
    assert len(threads) == 3
    assert seen and all(ident != main for ident in seen)


async def test_the_minimum_age(history: PasswordHistory, make_user: Any, db: Database) -> None:
    user: User = await make_user()
    states = PasswordStates(db)
    set_at = datetime(2026, 11, 10, 9, 0, tzinfo=UTC)
    await states.record_set(user.id, tier=None, set_at=set_at, expires_at=None, fingerprint=None)
    assert await history.too_soon(user.id, min_age_hours=24, now=set_at + timedelta(hours=23))
    assert not await history.too_soon(user.id, min_age_hours=24, now=set_at + timedelta(hours=24))
    assert not await history.too_soon(user.id, min_age_hours=0, now=set_at)
    # No recorded password: nothing to wait for. (Setting one would record it.)
    fresh: User = await make_user(password=None)
    assert not await history.too_soon(fresh.id, min_age_hours=24, now=set_at)


async def test_pruning_keeps_the_largest_count_any_policy_needs(
    db: Database, permissions: PermissionRegistry, history: PasswordHistory, make_user: Any
) -> None:
    policies = PasswordPolicies(db, permissions, seed_min_length=12, fingerprint_available=False)
    default = await policies.default()
    # Without a password: setting one would keep it in the history too.
    user: User = await make_user(password=None)
    passwords = [f"synthetic password number {i}" for i in range(6)]
    await _remember(history, user, passwords)
    # The default keeps none, so everything can go.
    keep = await policies.create(
        PolicySettings(name="Keeps four", rules=PasswordRules(min_length=12), history_count=4),
        priority=1,
        actor="a",
    )
    assert await history.prune(policies) == 2
    assert await history.reused(user.id, passwords[2], count=24)
    assert not await history.reused(user.id, passwords[1], count=24)
    await policies.update(
        keep.id,
        dataclasses.replace(keep.settings, history_count=0),
        expected_version=keep.version,
        actor="a",
    )
    assert default.settings.history_count == 0
    assert await history.prune(policies) == 4
    assert not await history.reused(user.id, passwords[5], count=24)


async def test_recording_and_checking_concurrently_never_errors(
    history: PasswordHistory, make_user: Any
) -> None:
    user: User = await make_user()
    hashes = [await FAST_HASHER.hash(p) for p in OLD]
    await asyncio.gather(*(history.record(user.id, h) for h in hashes))
    assert all([await history.reused(user.id, p, count=3) for p in OLD])
