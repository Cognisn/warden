"""Apply warden's Alembic chain.

warden's migrations live in this package and record their state in
``warden.alembic_version``, independent of any chain the product keeps.
A product runs them with ``warden migrate`` or by calling ``migrate(dsn)``
(or ``migrate_connection(conn)``) from its own migration step.
"""

from __future__ import annotations

import threading
from importlib import resources

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, create_engine, inspect
from sqlalchemy.pool import NullPool

from warden.db.schema import SCHEMA, VERSION_TABLE

__all__ = ["current_revision", "downgrade", "heads", "migrate", "migrate_connection"]

_DRIVER_PREFIXES = ("postgresql+psycopg://", "postgresql://", "postgres://")

# Alembic keeps the running migration context in module-level state, so two
# runs in one process must not overlap. Runs in separate processes (replicas)
# are serialised by the advisory lock the migration environment takes.
_IN_PROCESS = threading.Lock()


def _sqlalchemy_url(dsn: str) -> str:
    for prefix in _DRIVER_PREFIXES:
        if dsn.startswith(prefix):
            return "postgresql+psycopg://" + dsn[len(prefix) :]
    raise ValueError("dsn must be a postgresql:// connection URL")


def _config(connection: Connection | None = None) -> Config:
    config = Config()
    config.set_main_option(
        "script_location", str(resources.files("warden.db").joinpath("migrations"))
    )
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def heads() -> list[str]:
    """The chain's head revisions. A healthy chain has exactly one."""
    return list(ScriptDirectory.from_config(_config()).get_heads())


def migrate_connection(connection: Connection, revision: str = "head") -> None:
    """Upgrade through a SQLAlchemy connection the caller owns.

    If the connection has no transaction open, the upgrade runs in its own
    transaction and commits. Otherwise it runs inside the caller's
    transaction and the caller commits.
    """
    with _IN_PROCESS:
        if connection.in_transaction():
            command.upgrade(_config(connection), revision)
        else:
            with connection.begin():
                command.upgrade(_config(connection), revision)


def migrate(dsn: str, revision: str = "head") -> None:
    """Upgrade the database at ``dsn`` to ``revision`` in one transaction."""
    engine = create_engine(_sqlalchemy_url(dsn), poolclass=NullPool)
    try:
        with _IN_PROCESS, engine.begin() as connection:
            command.upgrade(_config(connection), revision)
    finally:
        engine.dispose()


def downgrade(dsn: str, revision: str) -> None:
    """Downgrade the database at ``dsn`` to ``revision`` (``"base"`` removes every table)."""
    engine = create_engine(_sqlalchemy_url(dsn), poolclass=NullPool)
    try:
        with _IN_PROCESS, engine.begin() as connection:
            command.downgrade(_config(connection), revision)
    finally:
        engine.dispose()


def current_revision(dsn: str) -> str | None:
    """The revision the database is at, or ``None`` if none is applied."""
    engine = create_engine(_sqlalchemy_url(dsn), poolclass=NullPool)
    try:
        with engine.connect() as connection:
            if not inspect(connection).has_table(VERSION_TABLE, schema=SCHEMA):
                return None
            context = MigrationContext.configure(
                connection,
                opts={"version_table": VERSION_TABLE, "version_table_schema": SCHEMA},
            )
            return context.get_current_revision()
    finally:
        engine.dispose()
