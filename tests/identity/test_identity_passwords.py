"""Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash only."""

from __future__ import annotations

import hashlib

import pytest

from warden.identity.passwords import PasswordHasher, Verification

FAST = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)


def _legacy(password: str, salt: str = "c2FsdHNhbHQ", iterations: int = 1000) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2:sha256:{iterations}${salt}${digest}"


async def test_new_hashes_are_argon2id() -> None:
    encoded = await FAST.hash("correct horse battery staple")
    assert encoded.startswith("$argon2id$")


async def test_argon2_hash_verifies_the_right_password_only() -> None:
    encoded = await FAST.hash("correct horse battery staple")
    assert await FAST.verify(encoded, "correct horse battery staple") == Verification(
        ok=True, needs_rehash=False
    )
    assert not (await FAST.verify(encoded, "wrong horse battery staple")).ok


async def test_argon2_hash_with_weaker_parameters_needs_rehash() -> None:
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    strong = PasswordHasher(time_cost=2, memory_cost=8192, parallelism=1)
    result = await strong.verify(await weak.hash("pw-123456789012"), "pw-123456789012")
    assert result == Verification(ok=True, needs_rehash=True)


async def test_legacy_pbkdf2_verifies_and_always_needs_rehash() -> None:
    encoded = _legacy("legacy password 1")
    assert await FAST.verify(encoded, "legacy password 1") == Verification(
        ok=True, needs_rehash=True
    )
    assert not (await FAST.verify(encoded, "legacy password 2")).ok


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "plaintext",
        "pbkdf2:sha1:1000$salt$" + "0" * 40,
        "pbkdf2:sha256$salt$" + "0" * 64,
        "pbkdf2:sha256:0$salt$" + "0" * 64,
        "pbkdf2:sha256:1000$salt$" + "0" * 63,
        "pbkdf2:sha256:1000$salt$" + "0" * 64 + "\n",
        "pbkdf2:sha256:\uff11\uff10\uff10\uff10$salt$" + "0" * 64,
        "$argon2id$v=19$m=8192,t=1,p=1$garbage",
    ],
)
async def test_malformed_hashes_fail_closed(encoded: str) -> None:
    assert await FAST.verify(encoded, "anything at all") == Verification(
        ok=False, needs_rehash=False
    )


async def test_trailing_newline_on_a_legacy_hash_is_refused() -> None:
    """Anchored parsing uses fullmatch: a valid hash plus a newline is not valid (#135)."""
    encoded = _legacy("legacy password 1")
    assert (await FAST.verify(encoded, "legacy password 1")).ok
    assert not (await FAST.verify(encoded + "\n", "legacy password 1")).ok


async def test_dummy_verify_never_succeeds() -> None:
    await FAST.dummy_verify("anything")


async def test_overlong_password_is_refused_without_hashing() -> None:
    encoded = await FAST.hash("x" * 1024)
    assert (await FAST.verify(encoded, "x" * 1024)).ok
    assert not (await FAST.verify(encoded, "x" * 1025)).ok
    with pytest.raises(ValueError):
        await FAST.hash("x" * 1025)
