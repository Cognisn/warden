"""Names of identity's tables in the ``warden`` schema."""

from __future__ import annotations

USERS = "users"
TOTP_CREDENTIALS = "totp_credentials"
RECOVERY_CODES = "recovery_codes"
MFA_CHALLENGES = "mfa_challenges"
SESSIONS = "sessions"
REFRESH_TOKENS = "refresh_tokens"
ROLE_ASSIGNMENTS = "role_assignments"

IDENTITY_TABLES = frozenset(
    {
        USERS,
        TOTP_CREDENTIALS,
        RECOVERY_CODES,
        MFA_CHALLENGES,
        SESSIONS,
        REFRESH_TOKENS,
        ROLE_ASSIGNMENTS,
    }
)
