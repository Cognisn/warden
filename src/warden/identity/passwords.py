"""Password hashing (design D15).

New hashes are Argon2id. A legacy ``pbkdf2:sha256:<iterations>$<salt>$<hex>``
hash (the format Termograph's users carry) is verified only so it can be
replaced with an Argon2id hash on the next successful sign-in.

Hashing and verification run in a worker thread so they never stall the
event loop. Every refusal, including a malformed stored hash, is a plain
``ok=False``; nothing here raises on a bad password or a bad hash.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

import argon2
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

__all__ = ["MAX_PASSWORD_LENGTH", "PasswordHasher", "Verification"]

# Long enough for any passphrase; short enough that hashing it is not a burden.
MAX_PASSWORD_LENGTH = 1024

_LEGACY = re.compile(r"pbkdf2:sha256:([1-9][0-9]{0,7})\$([^$\s]{1,128})\$([0-9a-f]{64})")


@dataclass(frozen=True, slots=True)
class Verification:
    """The outcome of checking a password against a stored hash."""

    ok: bool
    needs_rehash: bool


_REFUSED = Verification(ok=False, needs_rehash=False)


class PasswordHasher:
    """Argon2id hashing with legacy PBKDF2 verification.

    The defaults are argon2-cffi's (RFC 9106 low-memory profile). Lower
    parameters are for tests only.
    """

    def __init__(
        self,
        *,
        time_cost: int = argon2.DEFAULT_TIME_COST,
        memory_cost: int = argon2.DEFAULT_MEMORY_COST,
        parallelism: int = argon2.DEFAULT_PARALLELISM,
    ) -> None:
        self._hasher = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            type=argon2.Type.ID,
        )
        self._dummy: str | None = None

    async def hash(self, password: str) -> str:
        """An Argon2id hash of ``password``."""
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"password longer than {MAX_PASSWORD_LENGTH} characters")
        return await asyncio.to_thread(self._hasher.hash, password)

    async def verify(self, encoded: str, password: str) -> Verification:
        """Check ``password`` against ``encoded``; never raises for a bad input."""
        if len(password) > MAX_PASSWORD_LENGTH:
            return _REFUSED
        legacy = _LEGACY.fullmatch(encoded)
        if legacy is not None:
            return await asyncio.to_thread(_verify_legacy, legacy, password)
        if not encoded.startswith("$argon2id$"):
            return _REFUSED
        return await asyncio.to_thread(self._verify_argon2, encoded, password)

    async def dummy_verify(self, password: str) -> None:
        """Spend the time one Argon2id verification takes, for a user who has no hash.

        Sign-in calls this for an unknown user so the refusal takes as long
        as a wrong password does.
        """
        if self._dummy is None:
            self._dummy = await asyncio.to_thread(self._hasher.hash, secrets.token_urlsafe(32))
        await asyncio.to_thread(self._verify_argon2, self._dummy, password[:MAX_PASSWORD_LENGTH])

    def _verify_argon2(self, encoded: str, password: str) -> Verification:
        try:
            self._hasher.verify(encoded, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return _REFUSED
        return Verification(ok=True, needs_rehash=self._hasher.check_needs_rehash(encoded))


def _verify_legacy(match: re.Match[str], password: str) -> Verification:
    iterations, salt, expected = match.groups()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
    if hmac.compare_digest(digest.hex(), expected):
        return Verification(ok=True, needs_rehash=True)
    return _REFUSED
