"""Names in warden's Postgres schema.

Every warden table lives in the ``warden`` schema and is always referenced
schema-qualified, so warden never depends on the product's ``search_path``.

Advisory lock keys are signed 64-bit integers: ASCII "warden" in the top six
bytes and a 16-bit number allocated by owner.

| Range | Owner | Allocated |
|---|---|---|
| 0x...00xx | db and audit | 0001 migrations, 0002 syslog forwarder, 0003 audit chain |
| 0x...01xx | identity | 0101 last administrator |
| 0x...02xx | single sign-on | none yet |

A key may be defined in the module that owns it, inside its owner's range;
``tests/test_db_schema.py`` scans every ``*_LOCK_KEY`` in ``src/warden`` and
fails on a collision or a key outside the table. Never change an allocated
key: a replica still running the old value would no longer be excluded.

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


def table(name: str) -> sql.Identifier:
    """A schema-qualified identifier for a warden table, for psycopg ``sql`` queries."""
    return sql.Identifier(SCHEMA, name)
