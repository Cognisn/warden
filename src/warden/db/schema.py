"""Names in warden's Postgres schema.

Every warden table lives in the ``warden`` schema and is always referenced
schema-qualified, so warden never depends on the product's ``search_path``.
"""

from __future__ import annotations

from psycopg import sql

SCHEMA = "warden"
VERSION_TABLE = "alembic_version"

AUDIT_EVENTS = "audit_events"
SIGNING_KEYS = "signing_keys"
SETTINGS = "settings"

# Transaction-scoped advisory lock taken by every migration run, so replicas
# that start together apply the chain one at a time. ASCII "warden" + 0x0001.
MIGRATION_LOCK_KEY = 0x7761_7264_656E_0001

# Session-scoped advisory lock held by the one syslog forwarder per deployment;
# other replicas wait on it and take over if the holder's session ends.
SYSLOG_FORWARDER_LOCK_KEY = 0x7761_7264_656E_0002

# The recorder NOTIFYs this channel in the same transaction as each audit
# insert, so a signal arrives only once the row has committed. The payload is
# the row id and nothing else.
AUDIT_CHANNEL = "warden_audit"

# ``warden.settings`` key holding the id of the last row the syslog forwarder sent.
SYSLOG_CURSOR_SETTING = "syslog.cursor"


def table(name: str) -> sql.Identifier:
    """A schema-qualified identifier for a warden table, for psycopg ``sql`` queries."""
    return sql.Identifier(SCHEMA, name)
