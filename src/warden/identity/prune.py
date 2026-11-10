"""Pruning (#134): delete identity rows that can never be used again.

``Pruner.prune`` deletes expired refresh tokens, expired single-use tokens,
expired MFA challenges, expired WebAuthn ceremony challenges, ended sign-in
throttle windows, password history beyond the largest count any password
policy keeps, and expired forced-change challenges, and reports how many of
each. Only expired rows
go: a used refresh token is kept until it expires, because presenting it
again is how reuse is detected.

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
from typing import TYPE_CHECKING, Protocol

from psycopg import sql

from warden.db import Database, schema, table
from warden.identity.single_use import SingleUseTokens
from warden.identity.throttle import SignInThrottle

if TYPE_CHECKING:
    from warden.identity.webauthn import WebAuthn

__all__ = ["PasswordPruning", "PruneReport", "Pruner"]

logger = logging.getLogger(__name__)

_REFRESH_TOKENS = table(schema.REFRESH_TOKENS)
_MFA_CHALLENGES = table(schema.MFA_CHALLENGES)


class PasswordPruning(Protocol):
    """What the pruner needs from password policies."""

    async def prune_history(self) -> int: ...

    async def prune_challenges(self) -> int: ...


@dataclass(frozen=True, slots=True)
class PruneReport:
    """How many rows one prune deleted, by kind."""

    refresh_tokens: int
    single_use_tokens: int
    mfa_challenges: int
    sign_in_attempts: int
    webauthn_challenges: int = 0
    """Expired passkey and security key ceremony challenges, used or not."""
    password_history: int = 0
    """Previous passwords beyond the largest history count any policy keeps."""
    password_change_challenges: int = 0
    """Expired forced-change challenges, used or not."""

    @property
    def total(self) -> int:
        return (
            self.refresh_tokens
            + self.single_use_tokens
            + self.mfa_challenges
            + self.sign_in_attempts
            + self.webauthn_challenges
            + self.password_history
            + self.password_change_challenges
        )


class Pruner:
    def __init__(
        self,
        db: Database,
        tokens: SingleUseTokens,
        throttle: SignInThrottle,
        *,
        webauthn: WebAuthn | None = None,
        passwords: PasswordPruning | None = None,
    ) -> None:
        """``webauthn`` is None where passkeys are not configured: nothing to prune.

        ``passwords`` prunes password history and forced-change challenges.
        """
        self._db = db
        self._tokens = tokens
        self._throttle = throttle
        self._webauthn = webauthn
        self._passwords = passwords

    async def prune(self) -> PruneReport:
        """Delete every expired row once; each kind in its own short transaction."""
        refresh = await self._delete_expired(_REFRESH_TOKENS)
        single_use = await self._tokens.prune()
        challenges = await self._delete_expired(_MFA_CHALLENGES)
        attempts = await self._throttle.prune()
        ceremonies = 0 if self._webauthn is None else await self._webauthn.prune()
        history = changes = 0
        if self._passwords is not None:
            history = await self._passwords.prune_history()
            changes = await self._passwords.prune_challenges()
        report = PruneReport(
            refresh, single_use, challenges, attempts, ceremonies, history, changes
        )
        if report.total:
            logger.info(
                "pruned %d refresh tokens, %d single-use tokens, %d MFA challenges,"
                " %d sign-in windows, %d WebAuthn challenges, %d previous passwords,"
                " %d password change challenges",
                refresh,
                single_use,
                challenges,
                attempts,
                ceremonies,
                history,
                changes,
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
