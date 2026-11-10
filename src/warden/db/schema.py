"""Names in warden's Postgres schema.

Every warden table lives in the ``warden`` schema and is always referenced
schema-qualified, so warden never depends on the product's ``search_path``.

Advisory lock keys are signed 64-bit integers: ASCII "warden" in the top six
bytes and a 16-bit number allocated by owner.

| Range | Owner | Allocated |
|---|---|---|
| 0x...00xx | db and audit | 0001 migrations, 0002 syslog forwarder, 0003 audit chain |
| 0x...01xx | identity | 0101 last administrator, 0102 password policies, 0103 watch lists |
| 0x...02xx | single sign-on | 0201 single sign-on settings |

Every allocated key is defined here. ``tests/test_db_schema.py`` scans every
``*_LOCK_KEY`` in ``src/warden`` and fails on a collision, a key outside the
table, or a key not recorded in it. Never change an allocated key: a replica
still running the old value would no longer be excluded.

Identity's session-policy writes lock ``hashtext(POLICY_SETTING)``, a 32-bit
value that cannot meet a key above, which all carry the prefix.
"""

from __future__ import annotations

from psycopg import sql

SCHEMA = "warden"
VERSION_TABLE = "alembic_version"

AUDIT_EVENTS = "audit_events"
SIGNING_KEYS = "signing_keys"
SETTINGS = "settings"

# Identity's tables.
USERS = "users"
TOTP_CREDENTIALS = "totp_credentials"
RECOVERY_CODES = "recovery_codes"
MFA_CHALLENGES = "mfa_challenges"
SESSIONS = "sessions"
REFRESH_TOKENS = "refresh_tokens"
ROLE_ASSIGNMENTS = "role_assignments"
SIGN_IN_ATTEMPTS = "sign_in_attempts"

IDENTITY_TABLES = frozenset(
    {
        USERS,
        TOTP_CREDENTIALS,
        RECOVERY_CODES,
        MFA_CHALLENGES,
        SESSIONS,
        REFRESH_TOKENS,
        ROLE_ASSIGNMENTS,
        SIGN_IN_ATTEMPTS,
    }
)

# Identity lifecycle's tables.
# Invitation and password reset tokens, each usable once.
SINGLE_USE_TOKENS = "single_use_tokens"
# The roles an invitation grants when it is accepted.
INVITATION_GRANTS = "invitation_grants"
API_KEYS = "api_keys"

LIFECYCLE_TABLES = frozenset({SINGLE_USE_TOKENS, INVITATION_GRANTS, API_KEYS})

# Single sign-on's tables.
# Each user's pinned (issuer, subject); at most one per user and per subject.
SSO_IDENTITIES = "sso_identities"
# Started sign-ins (state, nonce, PKCE verifier), each usable once.
SSO_LOGIN_TRANSACTIONS = "sso_login_transactions"
# One-time codes handed to the product's completion screen.
SSO_HANDOFF_CODES = "sso_handoff_codes"

SSO_TABLES = frozenset({SSO_IDENTITIES, SSO_LOGIN_TRANSACTIONS, SSO_HANDOFF_CODES})

# WebAuthn's tables (passkeys and security keys).
# Each credential's public key, signature counter and flags, owned by one user.
WEBAUTHN_CREDENTIALS = "webauthn_credentials"
# Each user's WebAuthn user handle: 64 random bytes, never derived from the user id.
WEBAUTHN_USER_HANDLES = "webauthn_user_handles"
# Registration and sign-in challenges, held as hashes, each usable once.
WEBAUTHN_CHALLENGES = "webauthn_challenges"

WEBAUTHN_TABLES = frozenset({WEBAUTHN_CREDENTIALS, WEBAUTHN_USER_HANDLES, WEBAUTHN_CHALLENGES})

# Password policies' tables (rulings PW0 to PW14 of 10 November 2026).
# Each policy: its rules, passphrase settings, tiers, history and watch-list settings.
PASSWORD_POLICIES = "password_policies"  # noqa: S105 - a name, not a secret
# Which policy a role maps to; a role maps to at most one.
PASSWORD_POLICY_ROLES = "password_policy_roles"  # noqa: S105 - a name, not a secret
# A policy an administrator pinned on one user, overriding the role mapping.
PASSWORD_POLICY_PINS = "password_policy_pins"  # noqa: S105 - a name, not a secret
# The watch lists each policy checks.
PASSWORD_POLICY_WATCH_LISTS = "password_policy_watch_lists"  # noqa: S105 - a name, not a secret
# Each user's password tier, expiry, change-required reason and sealed fingerprint.
PASSWORD_STATES = "password_states"  # noqa: S105 - a name, not a secret
# Each user's previous Argon2id hashes.
PASSWORD_HISTORY = "password_history"  # noqa: S105 - a name, not a secret
# Named watch lists, each with the reason a user is shown.
WATCH_LISTS = "watch_lists"
# A watch list's entries: SHA-1 digests and nothing else.
WATCH_LIST_ENTRIES = "watch_list_entries"
# A watch list's contained terms, matched without regard to case.
WATCH_LIST_TERMS = "watch_list_terms"
# Digests streamed in by an import, swapped into a list in one transaction.
WATCH_LIST_STAGING = "watch_list_staging"
# Forced-change challenges, held as hashes, each usable once.
PASSWORD_CHANGE_CHALLENGES = "password_change_challenges"  # noqa: S105 - a name, not a secret

PASSWORD_POLICY_TABLES = frozenset(
    {
        PASSWORD_POLICIES,
        PASSWORD_POLICY_ROLES,
        PASSWORD_POLICY_PINS,
        PASSWORD_POLICY_WATCH_LISTS,
        PASSWORD_STATES,
        PASSWORD_HISTORY,
        WATCH_LISTS,
        WATCH_LIST_ENTRIES,
        WATCH_LIST_TERMS,
        WATCH_LIST_STAGING,
        PASSWORD_CHANGE_CHALLENGES,
    }
)

# Transaction-scoped advisory lock taken by every migration run, so replicas
# that start together apply the chain one at a time. ASCII "warden" + 0x0001.
MIGRATION_LOCK_KEY = 0x7761_7264_656E_0001

# Session-scoped advisory lock held by the one syslog forwarder per deployment;
# other replicas wait on it and take over if the holder's session ends.
SYSLOG_FORWARDER_LOCK_KEY = 0x7761_7264_656E_0002

# Transaction-scoped advisory lock serialising appends to the audit chain. It
# is taken before a row's id is drawn and held until the transaction ends, so
# rows commit in id order. ASCII "warden" + 0x0003.
CHAIN_LOCK_KEY = 0x7761_7264_656E_0003

# Transaction-scoped advisory lock taken by every change that could remove an
# administrator, so two such changes never both pass the last-administrator
# check. ASCII "warden" + 0x0101.
ADMINISTRATOR_LOCK_KEY = 0x7761_7264_656E_0101

# Transaction-scoped advisory lock taken by every change to password policies,
# their priorities, role mappings and pins, and by seeding the default, so two
# replicas seeding together create one default. ASCII "warden" + 0x0102.
PASSWORD_POLICY_LOCK_KEY = 0x7761_7264_656E_0102

# Transaction-scoped advisory lock taken by every change to watch lists and
# their entries, so an import's swap and a concurrent edit never interleave.
# ASCII "warden" + 0x0103.
WATCH_LIST_LOCK_KEY = 0x7761_7264_656E_0103

# Transaction-scoped advisory lock between changing the single sign-on
# settings (exclusive) and issuing a session through single sign-on
# (shared), so a session issued while SSO is being disabled is either
# refused or revoked by the disable. ASCII "warden" + 0x0201.
SSO_SETTINGS_LOCK_KEY = 0x7761_7264_656E_0201

# The recorder NOTIFYs this channel in the same transaction as each audit
# insert, so a signal arrives only once the row has committed. The payload is
# the row id and nothing else.
AUDIT_CHANNEL = "warden_audit"

# ``warden.settings`` key holding the id of the last row the syslog forwarder sent.
SYSLOG_CURSOR_SETTING = "syslog.cursor"

# ``warden.settings`` key holding the administrator's session-policy
# overrides, and the channel a change is announced on.
POLICY_SETTING = "identity.session_policy"
POLICY_CHANNEL = "warden_identity_policy"

# The NOTIFY payload a password policy change sends on ``POLICY_CHANNEL``, the
# existing identity policy channel (ruling PW2).
PASSWORD_POLICY_NOTIFY = "password_policy"  # noqa: S105 - a name, not a secret

# ``warden.settings`` key holding the administrator's single sign-on overrides.
SSO_SETTING = "identity.sso"


def table(name: str) -> sql.Identifier:
    """A schema-qualified identifier for a warden table, for psycopg ``sql`` queries."""
    return sql.Identifier(SCHEMA, name)
