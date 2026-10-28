"""Pruning (#134): delete identity rows that can never be used again.

``Pruner.prune`` deletes expired refresh tokens, expired single-use tokens,
expired MFA challenges and ended sign-in throttle windows, and reports how
many of each. Only expired rows go: a used refresh token is kept until it
expires, because presenting it again is how reuse is detected.

warden ships no scheduler of its own. A product calls ``identity.prune()``
from its own scheduler, or runs ``identity.pruning(every_seconds=...)`` in
its FastAPI lifespan. Every replica may run it; the deletes are idempotent.
A failed run is logged and the next one goes ahead.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

from psycopg import sql

from warden.db import Database, schema, table
from warden.identity.single_use import SingleUseTokens
from warden.identity.throttle import SignInThrottle

__all__ = ["PruneReport", "Pruner"]

logger = logging.getLogger(__name__)

_REFRESH_TOKENS = table(schema.REFRESH_TOKENS)
_MFA_CHALLENGES = table(schema.MFA_CHALLENGES)


@dataclass(frozen=True, slots=True)
class PruneReport:
    """How many rows one prune deleted, by kind."""

    refresh_tokens: int
    single_use_tokens: int
    mfa_challenges: int
    sign_in_attempts: int

    @property
    def total(self) -> int:
        return (
            self.refresh_tokens
            + self.single_use_tokens
            + self.mfa_challenges
            + self.sign_in_attempts
        )


class Pruner:
    def __init__(self, db: Database, tokens: SingleUseTokens, throttle: SignInThrottle) -> None:
        self._db = db
        self._tokens = tokens
        self._throttle = throttle

    async def prune(self) -> PruneReport:
        """Delete every expired row once; each kind in its own short transaction."""
        refresh = await self._delete_expired(_REFRESH_TOKENS)
        single_use = await self._tokens.prune()
        challenges = await self._delete_expired(_MFA_CHALLENGES)
        attempts = await self._throttle.prune()
        report = PruneReport(refresh, single_use, challenges, attempts)
        if report.total:
            logger.info(
                "pruned %d refresh tokens, %d single-use tokens, %d MFA challenges,"
                " %d sign-in windows",
                refresh,
                single_use,
                challenges,
                attempts,
            )
        return report

    async def _delete_expired(self, name: sql.Identifier) -> int:
        async with self._db.transaction() as tx:
            cur = await tx.execute(sql.SQL("DELETE FROM {} WHERE expires_at <= now()").format(name))
            return cur.rowcount


def check_interval(every_seconds: float) -> None:
    if not every_seconds > 0:
        raise ValueError("the pruning interval must be positive")


@contextlib.asynccontextmanager
async def scheduled(
    prune: Callable[[], Awaitable[PruneReport]], every_seconds: float
) -> AsyncIterator[None]:
    """Run ``prune`` every ``every_seconds`` for the duration of a block."""

    async def loop() -> None:
        while True:
            try:
                await prune()
            except Exception as exc:
                # The type only: a driver's message can carry connection details.
                logger.warning(
                    "pruning failed (%s); trying again in %s seconds",
                    type(exc).__name__,
                    every_seconds,
                )
            await asyncio.sleep(every_seconds)

    task = asyncio.create_task(loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
