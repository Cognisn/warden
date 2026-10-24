"""warden's database contract: the pool adapter, schema names and migrations.

This package is shared: after the Foundation arc only the integration session
edits it. Arcs add new migration files only and never edit an existing one.
"""

from warden.db.migrate import current_revision, downgrade, heads, migrate, migrate_connection
from warden.db.pool import ConnectionSource, Database
from warden.db.schema import (
    AUDIT_CHANNEL,
    AUDIT_EVENTS,
    MIGRATION_LOCK_KEY,
    SCHEMA,
    SETTINGS,
    SIGNING_KEYS,
    SYSLOG_CURSOR_SETTING,
    SYSLOG_FORWARDER_LOCK_KEY,
    VERSION_TABLE,
    table,
)

__all__ = [
    "AUDIT_CHANNEL",
    "AUDIT_EVENTS",
    "MIGRATION_LOCK_KEY",
    "SCHEMA",
    "SETTINGS",
    "SIGNING_KEYS",
    "SYSLOG_CURSOR_SETTING",
    "SYSLOG_FORWARDER_LOCK_KEY",
    "VERSION_TABLE",
    "ConnectionSource",
    "Database",
    "current_revision",
    "downgrade",
    "heads",
    "migrate",
    "migrate_connection",
    "table",
]
