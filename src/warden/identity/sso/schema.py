"""Single sign-on's names in warden's Postgres schema.

Defined here rather than in ``warden.db.schema`` because that module is
shared and edited only by the integration session, which may move them.
"""

from __future__ import annotations

__all__ = [
    "SSO_HANDOFF_CODES",
    "SSO_IDENTITIES",
    "SSO_LOGIN_TRANSACTIONS",
    "SSO_SETTING",
    "SSO_SETTINGS_LOCK_KEY",
    "SSO_TABLES",
]

# Each user's pinned (issuer, subject); at most one per user and per subject.
SSO_IDENTITIES = "sso_identities"
# Started sign-ins (state, nonce, PKCE verifier), each usable once.
SSO_LOGIN_TRANSACTIONS = "sso_login_transactions"
# One-time codes handed to the product's completion screen.
SSO_HANDOFF_CODES = "sso_handoff_codes"

SSO_TABLES = frozenset({SSO_IDENTITIES, SSO_LOGIN_TRANSACTIONS, SSO_HANDOFF_CODES})

# ``warden.settings`` key holding the administrator's single sign-on overrides.
SSO_SETTING = "identity.sso"

# Transaction-scoped advisory lock between changing the single sign-on
# settings (exclusive) and issuing a session through single sign-on
# (shared), so a session issued while SSO is being disabled is either
# refused or revoked by the disable. ASCII "warden" + 0x0201.
SSO_SETTINGS_LOCK_KEY = 0x7761_7264_656E_0201
