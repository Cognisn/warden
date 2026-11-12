"""Tripwire: importing the key store loads no web stack.

Audit verifies checkpoints with ``warden.keys``, and a worker process that
uses audit alone must not pull in FastAPI to do so. The key publication
routes live in ``warden.jwks``; only importing that module loads FastAPI.
"""

from __future__ import annotations

import subprocess
import sys

WEB = ("fastapi", "starlette")


def _web_modules_after(statement: str) -> list[str]:
    probe = (
        f"import sys; {statement}; "
        f"print(','.join(sorted(m for m in sys.modules if m.split('.')[0] in {WEB!r})))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=60, check=True
    )
    return [m for m in result.stdout.strip().split(",") if m]


def test_importing_the_key_store_loads_no_web_framework() -> None:
    assert _web_modules_after("import warden.keys") == []


def test_the_probe_sees_the_web_framework_when_it_is_loaded() -> None:
    # The probe must be able to fail, or the test above guards nothing.
    assert "fastapi" in _web_modules_after("import warden.jwks")
