"""Single sign-on's names in warden's Postgres schema, now defined in ``warden.db.schema``.

Kept so existing imports keep working; new code imports from ``warden.db``.
"""

from __future__ import annotations

from warden.db.schema import (
    SSO_HANDOFF_CODES,
    SSO_IDENTITIES,
    SSO_LOGIN_TRANSACTIONS,
    SSO_SETTING,
    SSO_SETTINGS_LOCK_KEY,
    SSO_TABLES,
)

__all__ = [
    "SSO_HANDOFF_CODES",
    "SSO_IDENTITIES",
    "SSO_LOGIN_TRANSACTIONS",
    "SSO_SETTING",
    "SSO_SETTINGS_LOCK_KEY",
    "SSO_TABLES",
]
