"""Helpers shared by identity tests (imported as ``identity_support``)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, User
from warden.identity.passwords import PasswordHasher
from warden.identity.totp import code_at, step_for

# Cheap parameters for speed; the timing test builds its own default-cost hasher.
FAST_HASHER = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "correct horse battery staple"

UserFactory = Callable[..., Awaitable[User]]


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value


def make_config(**identity: Any) -> WardenConfig:
    return parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "identity": {"require_mfa": False, **identity},
        }
    )


def current_code(secret: bytes, offset: int = 0) -> str:
    return code_at(secret, step_for(time.time()) + offset)


async def enrol_totp(identity: Identity, user: User) -> bytes:
    """Enrol and confirm TOTP for ``user``; returns the secret.

    Confirmation claims the current step, so a later verification in the
    same step needs the next step's code (``current_code(secret, 1)``).
    """
    enrolment = await identity.mfa.begin_enrolment(user.id, account=user.email)
    codes = await identity.mfa.confirm_enrolment(
        user.id, current_code(enrolment.secret), actor="test"
    )
    assert codes is not None
    return enrolment.secret


async def audit_rows(db: Database, action: str | None = None) -> list[dict[str, Any]]:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT action, outcome, actor, resource_type, resource_id, details"
            " FROM warden.audit_events WHERE %s::text IS NULL OR action = %s ORDER BY id",
            (action, action),
        )
        names = ("action", "outcome", "actor", "resource_type", "resource_id", "details")
        return [dict(zip(names, row, strict=True)) for row in await cur.fetchall()]


async def race(*calls: Callable[[], Awaitable[Any]]) -> list[Any]:
    """Run ``calls`` as concurrent tasks released together by a barrier.

    Every task waits at the barrier until all have been scheduled, then
    starts its database work. Exceptions are returned, not raised, so a
    test can assert on each outcome.
    """
    barrier = asyncio.Barrier(len(calls))

    async def run(call: Callable[[], Awaitable[Any]]) -> Any:
        await barrier.wait()
        return await call()

    return list(await asyncio.gather(*(run(c) for c in calls), return_exceptions=True))
