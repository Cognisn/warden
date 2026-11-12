"""Pruning for password policies: history beyond what any policy keeps, expired challenges."""

from __future__ import annotations

from warden.identity.password_policy.challenges import PasswordChangeChallenges
from warden.identity.password_policy.history import PasswordHistory
from warden.identity.password_policy.store import PasswordPolicies

__all__ = ["PasswordMaintenance"]


class PasswordMaintenance:
    """What ``Pruner`` calls to prune password history and forced-change challenges."""

    def __init__(
        self,
        history: PasswordHistory,
        policies: PasswordPolicies,
        challenges: PasswordChangeChallenges,
    ) -> None:
        self._history = history
        self._policies = policies
        self._challenges = challenges

    async def prune_history(self) -> int:
        return await self._history.prune(self._policies)

    async def prune_challenges(self) -> int:
        return await self._challenges.prune()
