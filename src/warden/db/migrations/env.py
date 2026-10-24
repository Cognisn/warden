"""Alembic environment for warden's own chain, pinned to the ``warden`` schema.

Runs only through ``warden.db.migrate``, which supplies the connection.
Offline (SQL script) mode is not supported.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection, text

from warden.db.schema import MIGRATION_LOCK_KEY, SCHEMA, VERSION_TABLE


def _run(connection: Connection) -> None:
    # Serialise concurrent runs (replicas starting together) before any DDL.
    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
    # The version table lives in the schema, so the schema must exist first.
    connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"'))
    context.configure(
        connection=connection,
        target_metadata=None,
        version_table=VERSION_TABLE,
        version_table_schema=SCHEMA,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("warden migrations do not support offline mode")

_connection = context.config.attributes.get("connection")
if not isinstance(_connection, Connection):
    raise RuntimeError("warden migrations run through warden.db.migrate")
_run(_connection)
