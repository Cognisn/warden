"""Fixtures for the sample console's tests.

The sample lives outside the package, under ``examples/``, so the repository
root goes on the import path. ``examples`` is a regular package, so it wins
over this test directory of the same name.
"""

from __future__ import annotations

import contextlib
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from console_support import MemorySecrets, console_config

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def secrets() -> MemorySecrets:
    from warden.identity import TOTP_KEY_SECRET, new_totp_key

    store = MemorySecrets()
    store.set(TOTP_KEY_SECRET, new_totp_key())
    return store


@pytest.fixture
async def console(pool: Any, secrets: MemorySecrets) -> AsyncIterator[Any]:
    """The sample console, built exactly as ``serve`` builds it, on a test database."""
    from examples.console.app import build_console
    from warden.audit import get_recorder, set_recorder
    from warden.identity import PasswordHasher

    previous = None
    with contextlib.suppress(RuntimeError):
        previous = get_recorder()
    built = build_console(
        console_config(),
        pool,
        secrets,
        hasher=PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1),
    )
    # The README's bootstrap creates the signing key with ``warden keys rotate``.
    await built.keys.rotate()
    try:
        yield built
    finally:
        set_recorder(previous)


@pytest.fixture
async def client(console: Any) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=console.app, client=("192.0.2.10", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8040") as c:
        yield c
