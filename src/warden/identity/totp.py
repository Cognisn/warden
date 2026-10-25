"""TOTP (RFC 6238, HMAC-SHA1, six digits, 30-second steps) and recovery codes.

Implemented directly rather than through a dependency, because the replay
guard lives with it: a code is accepted at most once per step, enforced by
one guarded ``UPDATE`` of the credential's last used step (see
``warden.identity.mfa``). This module holds the pure parts.

Codes are validated as exactly six ASCII digits. Python's ``int()`` and
``str.isdigit()`` accept other scripts' digits, so neither is used to
validate.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
from urllib.parse import quote, urlencode

__all__ = [
    "DIGITS",
    "PERIOD",
    "WINDOW",
    "code_at",
    "generate_recovery_codes",
    "generate_secret",
    "hash_recovery_code",
    "matching_step",
    "parse_code",
    "parse_recovery_code",
    "provisioning_uri",
    "step_for",
]

DIGITS = 6
PERIOD = 30
# Steps accepted either side of the current one, for clock drift.
WINDOW = 1

_CODE = re.compile(r"[0-9]{6}")
_RECOVERY = re.compile(r"[a-z2-7]{10}")
_RECOVERY_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def generate_secret() -> bytes:
    """A fresh 160-bit TOTP secret (RFC 4226's recommended length)."""
    return secrets.token_bytes(20)


def step_for(timestamp: float) -> int:
    """The TOTP time step containing ``timestamp`` (Unix seconds)."""
    return int(timestamp // PERIOD)


def code_at(secret: bytes, step: int, *, digits: int = DIGITS) -> str:
    """The code for ``step`` (RFC 4226 dynamic truncation)."""
    mac = hmac.digest(secret, struct.pack(">Q", step), "sha1")
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFF_FFFF
    return str(value % 10**digits).zfill(digits)


def parse_code(code: object) -> str | None:
    """``code`` if it is exactly six ASCII digits, otherwise None."""
    if not isinstance(code, str) or len(code) != DIGITS or _CODE.fullmatch(code) is None:
        return None
    return code


def matching_step(secret: bytes, code: object, now_step: int) -> int | None:
    """The step within the window whose code is ``code``, or None.

    Every candidate is compared in constant time, and all are compared
    whichever matches, so timing does not reveal which step matched.
    """
    parsed = parse_code(code)
    if parsed is None:
        return None
    found: int | None = None
    for step in range(now_step - WINDOW, now_step + WINDOW + 1):
        if hmac.compare_digest(code_at(secret, step), parsed) and found is None:
            found = step
    return found


def provisioning_uri(secret: bytes, *, account: str, issuer: str) -> str:
    """The ``otpauth://`` URI an authenticator app reads from a QR code."""
    label = quote(issuer, safe="") + ":" + quote(account, safe="")
    query = urlencode(
        {
            "secret": base64.b32encode(secret).decode("ascii").rstrip("="),
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": str(DIGITS),
            "period": str(PERIOD),
        },
        quote_via=quote,
    )
    return f"otpauth://totp/{label}?{query}"


def generate_recovery_codes(count: int = 10) -> list[str]:
    """``count`` distinct single-use recovery codes, ``xxxxx-xxxxx`` (50 bits each)."""
    codes: set[str] = set()
    while len(codes) < count:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.add(f"{raw[:5]}-{raw[5:]}")
    return sorted(codes)


def parse_recovery_code(code: object) -> str | None:
    """The normalised form of a recovery code (lower case, no hyphen), or None.

    ASCII is checked before lower-casing: ``str.lower`` maps some non-ASCII
    letters, such as the Kelvin sign, onto ASCII ones.
    """
    if not isinstance(code, str) or len(code) > 11 or not code.isascii():
        return None
    normalised = code.lower()
    if len(normalised) == 11 and normalised[5] == "-":
        normalised = normalised[:5] + normalised[6:]
    if _RECOVERY.fullmatch(normalised) is None:
        return None
    return normalised


def hash_recovery_code(normalised: str) -> bytes:
    """The stored form of a recovery code. Codes carry 50 random bits, so SHA-256 suffices."""
    return hashlib.sha256(normalised.encode("ascii")).digest()
