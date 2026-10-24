"""The ``warden`` command.

    warden [--config FILE] [--env-prefix PREFIX] migrate [--revision REV]
    warden [--config FILE] [--env-prefix PREFIX] keys rotate

Configuration is read through konfig exactly as a product reads it: the
``warden`` section of the given config file, overridden by environment
variables under ``--env-prefix``. ``warden.db.dsn`` names the database;
it may be a ``secret://`` reference. Output carries identifiers only, never
key material or connection strings.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

import psycopg
import sqlalchemy.exc
from psycopg import AsyncConnection

from warden import __version__
from warden.config import ConfigError, SecretSource, SettingsSource, WardenConfig, load_config
from warden.db import Database, current_revision, migrate
from warden.keys import KeyStore, KeyStoreError, SecretStore

__all__ = ["main"]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2

# Fixed wording: the driver's own message can carry the host, database and user.
MIGRATE_CONNECTION_FAILED = "warden migrate: could not connect to the database"


class _OneConnection:
    """A connection source lending a single connection, for one CLI command."""

    def __init__(self, conn: AsyncConnection[Any]) -> None:
        self._conn = conn

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection[Any]]:
        yield self._conn


class _LazySecrets:
    """konfig ``Secrets``, constructed only if a command actually needs a secret."""

    def __init__(self, service_name: str, settings: Any) -> None:
        self._service_name = service_name
        self._settings = settings
        self._secrets: Any = None

    def _backend(self) -> Any:
        if self._secrets is None:
            from konfig import Secrets

            self._secrets = Secrets(service_name=self._service_name, settings=self._settings)
        return self._secrets

    def get(self, key: str) -> str | None:
        value = self._backend().get(key)
        return None if value is None else str(value)

    def set(self, key: str, value: str) -> None:
        self._backend().set(key, value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warden", description="warden administration")
    parser.add_argument("--version", action="version", version=f"warden {__version__}")
    parser.add_argument("--config", help="konfig config file (YAML, TOML or JSON)")
    parser.add_argument("--env-prefix", help="environment variable prefix for konfig")
    parser.add_argument("--service-name", default="warden", help="konfig secrets namespace")
    commands = parser.add_subparsers(dest="command", required=True)

    migrate_cmd = commands.add_parser("migrate", help="upgrade the warden schema")
    migrate_cmd.add_argument("--revision", default="head")

    keys_cmd = commands.add_parser("keys", help="signing key management")
    keys_sub = keys_cmd.add_subparsers(dest="keys_command", required=True)
    keys_sub.add_parser("rotate", help="add a signing key; earlier keys keep verifying")
    return parser


def _dsn(config: WardenConfig) -> str:
    if config.db.dsn is None:
        raise ConfigError(
            "invalid warden configuration:\n  warden.db.dsn: is required for this command"
        )
    return config.db.dsn.get_secret_value()


def _run_async(coro: Any) -> Any:
    if sys.platform == "win32":
        # psycopg's async driver cannot run on the Proactor event loop.
        return asyncio.run(coro, loop_factory=asyncio.SelectorEventLoop)
    return asyncio.run(coro)


async def _rotate(dsn: str, secrets: SecretStore, config: WardenConfig) -> str:
    conn = await AsyncConnection.connect(dsn)
    try:
        store = KeyStore(Database(_OneConnection(conn)), secrets, config.keys)
        return (await store.rotate()).key_id
    finally:
        await conn.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: SettingsSource | None = None,
    secrets: SecretStore | None = None,
) -> int:
    """Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests."""
    args = _parser().parse_args(argv)
    if settings is None:
        from konfig import Settings

        settings = Settings(config_file=args.config, env_prefix=args.env_prefix)
    if secrets is None:
        secrets = _LazySecrets(args.service_name, settings)
    source: SecretSource = secrets

    try:
        config = load_config(settings, source)
        dsn = _dsn(config)
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return EXIT_CONFIG

    if args.command == "migrate":
        try:
            migrate(dsn, args.revision)
            revision = current_revision(dsn)
        except (psycopg.OperationalError, sqlalchemy.exc.OperationalError):
            print(MIGRATE_CONNECTION_FAILED, file=sys.stderr)
            return EXIT_FAILED
        print(f"warden schema at revision {revision}")
        return EXIT_OK

    try:
        key_id = _run_async(_rotate(dsn, secrets, config))
    except KeyStoreError as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED
    print(f"new signing key {key_id}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
