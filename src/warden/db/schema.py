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


def table(name: str) -> sql.Identifier:
    """A schema-qualified identifier for a warden table, for psycopg ``sql`` queries."""
    return sql.Identifier(SCHEMA, name)
