"""Session policy: defaults from configuration, audited changes, cross-replica invalidation."""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from identity_support import audit_rows

from warden.audit import get_recorder
from warden.config import WardenConfig
from warden.db import Database
from warden.identity import PolicyError, PolicyStore, SessionPolicy
from warden.identity.actions import register_actions

pytestmark = pytest.mark.db


def _store(db: Database, config: WardenConfig, **kw: float) -> PolicyStore:
    register_actions(get_recorder().registry)
    return PolicyStore(db, SessionPolicy.from_config(config.identity), **kw)


async def test_defaults_come_from_configuration(db: Database, config: WardenConfig) -> None:
    policy = await _store(db, config).current()
    assert policy == SessionPolicy(
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=28_800,
        session_lifespan_seconds=43_200,
        refresh_reuse_grace_seconds=10,
        require_mfa=False,
    )


async def test_update_is_stored_and_audited(db: Database, config: WardenConfig) -> None:
    store = _store(db, config)
    updated = await store.update(actor="admin-1", require_mfa=True, refresh_reuse_grace_seconds=0)
    assert updated.require_mfa and updated.refresh_reuse_grace_seconds == 0
    assert await _store(db, config).current() == updated
    rows = await audit_rows(db, "warden.identity.policy.changed")
    assert rows == [
        {
            "action": "warden.identity.policy.changed",
            "outcome": "success",
            "actor": "admin-1",
            "resource_type": "session_policy",
            "resource_id": None,
            "details": {"refresh_reuse_grace_seconds": 0, "require_mfa": True},
        }
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"access_token_ttl_seconds": 30},
        {"access_token_ttl_seconds": 30_000},
        {"refresh_token_ttl_seconds": 600, "access_token_ttl_seconds": 900},
        {"session_lifespan_seconds": 3600},
        {"refresh_reuse_grace_seconds": -1},
        {"refresh_reuse_grace_seconds": 121},
        {"unknown_field": 5},
        {"require_mfa": "yes"},
    ],
)
async def test_inconsistent_updates_are_refused(
    db: Database, config: WardenConfig, changes: dict[str, object]
) -> None:
    store = _store(db, config)
    with pytest.raises(PolicyError):
        await store.update(actor="t", **changes)
    assert await store.current() == SessionPolicy.from_config(config.identity)


async def test_a_change_reaches_another_replica_promptly(
    db: Database, config: WardenConfig
) -> None:
    """Replica B caches the policy for an hour, yet sees A's change at once via NOTIFY."""
    replica_a = _store(db, config)
    replica_b = _store(db, config, max_age=3600)
    ready = asyncio.Event()
    listener = asyncio.create_task(replica_b.listen(ready=ready))
    try:
        await asyncio.wait_for(ready.wait(), timeout=10)
        assert (await replica_b.current()).session_lifespan_seconds == 43_200
        await replica_a.update(
            actor="admin-1", session_lifespan_seconds=7200, refresh_token_ttl_seconds=3600
        )
        for _ in range(100):
            if (await replica_b.current()).session_lifespan_seconds == 7200:
                break
            await asyncio.sleep(0.05)
        assert (await replica_b.current()).session_lifespan_seconds == 7200
    finally:
        listener.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await listener


async def test_without_a_listener_the_cache_expires(db: Database, config: WardenConfig) -> None:
    replica_a = _store(db, config)
    replica_b = _store(db, config, max_age=0.2)
    await replica_b.current()
    await replica_a.update(actor="t", require_mfa=True)
    await asyncio.sleep(0.3)
    assert (await replica_b.current()).require_mfa


async def test_reset_returns_to_configuration(db: Database, config: WardenConfig) -> None:
    store = _store(db, config)
    await store.update(actor="t", require_mfa=True)
    assert (await store.reset(actor="t")) == SessionPolicy.from_config(config.identity)
    assert await _store(db, config).current() == SessionPolicy.from_config(config.identity)


async def test_running_starts_and_stops_the_listener(
    db: Database,
    config: WardenConfig,
    keys: object,
    permissions: object,
    secrets: object,
) -> None:
    """The product wraps its app's lifespan in ``identity.running()``."""
    from identity_support import FAST_HASHER

    from warden.identity import Identity

    identity = Identity(
        config,
        db,
        keys,  # type: ignore[arg-type]
        permissions,  # type: ignore[arg-type]
        secrets=secrets,  # type: ignore[arg-type]
        hasher=FAST_HASHER,
        policy_max_age=3600,
    )
    other = _store(db, config)
    assert not identity.policy.listening
    async with identity.running():
        assert identity.policy.listening
        assert (await identity.policy.current()).require_mfa is False
        await other.update(actor="t", require_mfa=True)
        for _ in range(100):
            if (await identity.policy.current()).require_mfa:
                break
            await asyncio.sleep(0.05)
        assert (await identity.policy.current()).require_mfa
    assert not identity.policy.listening
