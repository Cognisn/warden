"""Tripwire: warden uses fido2's relying-party side only, never its device code.

fido2 also ships client code that talks to authenticators over HID, NFC and
smart-card readers (``pyscard``). A server never needs it, and on some
platforms loading it touches the operating system's device interfaces. Each
probe runs in a fresh interpreter, so the result is the same on Linux, macOS
and Windows.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

DEVICE = ("fido2.hid", "fido2.pcsc", "fido2.ctap", "fido2.ctap1", "fido2.ctap2", "fido2.client")
READERS = ("smartcard",)


def _device_modules_after(statement: str) -> list[str]:
    probe = (
        f"import sys; {statement}; "
        f"print(','.join(sorted(m for m in sys.modules"
        f" if m.split('.')[0] in {READERS!r}"
        f" or any(m == d or m.startswith(d + '.') for d in {DEVICE!r}))))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=60, check=True
    )
    return [m for m in result.stdout.strip().split(",") if m]


@pytest.mark.parametrize(
    "statement",
    ["import warden.config", "import warden.identity", "import warden.identity.webauthn"],
)
def test_importing_warden_loads_no_fido2_device_code(statement: str) -> None:
    assert _device_modules_after(statement) == []


def test_the_probe_sees_device_code_when_it_is_loaded() -> None:
    # The probe must be able to fail, or the test above guards nothing.
    assert "fido2.ctap1" in _device_modules_after("import fido2.ctap1")
