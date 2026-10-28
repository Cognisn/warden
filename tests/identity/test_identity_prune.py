"""Pruning (#134): expired refresh and single-use tokens, MFA challenges, throttle windows."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from identity_support import PASSWORD, RecordingSender, UserFactory, enrol_totp

from warden.db import Database
from warden.identity import Identity
from warden.identity.prune import PruneReport

pytestmark = pytest.mark.db


async def _count(db: Database, table: str) -> int:
    async with db.connection() as conn:
        cur = await conn.execute(f"SELECT count(*) FROM warden.{table}")  # noqa: S608
        row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def _expire_all(db: Database, table: str, column: str = "expires_at") -> None:
    """Move every row of ``table`` into the past, keeping its own constraints."""
    created = {
        "refresh_tokens": "issued_at",
        "single_use_tokens": "created_at",
        "mfa_challenges": "created_at",
    }[table]
    async with db.connection() as conn:
        await conn.execute(
            f"UPDATE warden.{table} SET {created} = now() - interval '2 days',"  # noqa: S608
            f" {column} = now() - interval '1 second'"
        )


async def _fixtures(identity: Identity, make_user: UserFactory, mail: RecordingSender) -> Any:
    user = await make_user()
    signed_in = await identity.sign_in(user.email, PASSWORD)
    assert signed_in.tokens is not None
    await identity.resets.request(user.email)
    other = await make_user()
    await enrol_totp(identity, other)
    challenged = await identity.sign_in(other.email, PASSWORD)
    assert challenged.challenge is not None
    return user, signed_in.tokens


async def test_expired_rows_are_pruned_and_live_ones_kept(
    identity: Identity, db: Database, make_user: UserFactory, mail: RecordingSender
) -> None:
    """#134."""
    await _fixtures(identity, make_user, mail)
    assert await identity.prune() == PruneReport(0, 0, 0, 0)
    for table in ("refresh_tokens", "single_use_tokens", "mfa_challenges"):
        await _expire_all(db, table)
    # Live rows written after the expiry survive the prune.
    live_user = await make_user()
    live = await identity.sign_in(live_user.email, PASSWORD)
    assert live.tokens is not None
    await identity.resets.request(live_user.email)

    report = await identity.prune()
    assert report == PruneReport(
        refresh_tokens=1, single_use_tokens=1, mfa_challenges=1, sign_in_attempts=0
    )
    assert report.total == 3
    assert await _count(db, "refresh_tokens") == 1
    assert await _count(db, "single_use_tokens") == 1
    assert await _count(db, "mfa_challenges") == 0
    assert (await identity.refresh(live.tokens.refresh_token)).access_token


async def test_a_used_refresh_token_is_kept_until_it_expires(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    """Reuse detection needs used tokens until they expire; pruning must not remove them early."""
    user = await make_user()
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is not None
    await identity.refresh(result.tokens.refresh_token)
    assert (await identity.prune()).refresh_tokens == 0
    assert await _count(db, "refresh_tokens") == 2


async def test_ended_throttle_windows_are_pruned(
    identity: Identity, db: Database, make_user: UserFactory
) -> None:
    user = await make_user()
    from warden.identity import AuthenticationRefused

    with pytest.raises(AuthenticationRefused):
        await identity.sign_in(user.email, "wrong password entirely")
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.sign_in_attempts SET window_started_at = now() - interval '1 day'"
        )
    assert (await identity.prune()).sign_in_attempts == 1


async def test_pruning_runs_on_a_schedule(
    identity: Identity, db: Database, make_user: UserFactory, mail: RecordingSender
) -> None:
    await _fixtures(identity, make_user, mail)
    await _expire_all(db, "single_use_tokens")
    async with identity.pruning(every_seconds=0.05):
        for _ in range(100):
            if await _count(db, "single_use_tokens") == 0:
                break
            await asyncio.sleep(0.05)
    assert await _count(db, "single_use_tokens") == 0


async def test_a_failed_run_does_not_stop_the_schedule(
    identity: Identity, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0
    real = identity.prune

    async def flaky() -> PruneReport:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("database unavailable")
        return await real()

    monkeypatch.setattr(identity, "prune", flaky)
    async with identity.pruning(every_seconds=0.02):
        for _ in range(100):
            if calls >= 3:
                break
            await asyncio.sleep(0.02)
    assert calls >= 3


async def test_the_schedule_stops_with_its_block(identity: Identity) -> None:
    async with identity.pruning(every_seconds=0.01):
        pass
    await asyncio.sleep(0.05)  # nothing left running to complain about


def test_the_interval_must_be_positive(identity: Identity) -> None:
    with pytest.raises(ValueError, match="positive"):
        identity.pruning(every_seconds=0)
