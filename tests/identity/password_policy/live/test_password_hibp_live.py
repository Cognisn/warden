"""Live check of the range client against the real Pwned Passwords API (ruling PW14).

Marked ``integration`` and skipped by default. Run it with::

    python -m pytest tests/identity/password_policy/live -m integration

It sends two five-character prefixes: one for the synthetic, well-known
breached password "password", and one for a random 40-character string that
no breach list should hold.
"""

from __future__ import annotations

import secrets
import string

import pytest

from warden.config import PasswordsConfig
from warden.identity.password_policy.fingerprint import password_digest
from warden.identity.password_policy.hibp import HibpRangeClient

pytestmark = pytest.mark.integration


async def test_a_well_known_breached_password_is_listed() -> None:
    client = HibpRangeClient(PasswordsConfig())
    assert await client.contains(password_digest("password"))


async def test_a_random_string_is_not_listed() -> None:
    alphabet = string.ascii_letters + string.digits
    random_text = "".join(secrets.choice(alphabet) for _ in range(40))
    client = HibpRangeClient(PasswordsConfig())
    assert not await client.contains(password_digest(random_text))
