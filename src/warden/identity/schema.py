"""Names of identity's tables, now defined in ``warden.db.schema``.

Kept so existing imports keep working; new code imports from ``warden.db``.
"""

from __future__ import annotations

from warden.db.schema import (
    IDENTITY_TABLES,
    MFA_CHALLENGES,
    RECOVERY_CODES,
    REFRESH_TOKENS,
    ROLE_ASSIGNMENTS,
    SESSIONS,
    SIGN_IN_ATTEMPTS,
    TOTP_CREDENTIALS,
    USERS,
)

__all__ = [
    "IDENTITY_TABLES",
    "MFA_CHALLENGES",
    "RECOVERY_CODES",
    "REFRESH_TOKENS",
    "ROLE_ASSIGNMENTS",
    "SESSIONS",
    "SIGN_IN_ATTEMPTS",
    "TOTP_CREDENTIALS",
    "USERS",
]
