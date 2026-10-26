"""The ``warden`` command.

    warden [--config FILE] [--env-prefix PREFIX] migrate [--revision REV]
    warden [--config FILE] [--env-prefix PREFIX] keys rotate
    warden [--config FILE] [--env-prefix PREFIX] audit verify
    warden [--config FILE] [--env-prefix PREFIX] audit purge [--retention-days N] [--actor NAME]
    warden audit grants --app-role ROLE [--forwarder-role ROLE] [--purger-role ROLE]

Configuration is read through konfig exactly as a product reads it: the
``warden`` section of the given config file, overridden by environment
variables under ``--env-prefix``. ``warden.db.dsn`` names the database;
it may be a ``secret://`` reference. Output carries identifiers only, never
key material or connection strings. ``audit grants`` only prints SQL and
needs no database.

``audit purge`` deletes audit rows, so it must connect as the purger role
(see ``warden.audit.grants``); the application's role cannot delete them.
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
from warden.audit.actions import register_audit_actions
from warden.audit.grants import grants_sql
from warden.audit.recorder import AuditRecorder
from warden.audit.registry import ActionRegistry
from warden.audit.retention import PurgeResult, RetentionError, purge
from warden.audit.verify import VerificationReport, verify_chain
from warden.config import ConfigError, SecretSource, SettingsSource, WardenConfig, load_config
from warden.db import Database, current_revision, migrate
from warden.keys import KeyStore, KeyStoreError, SecretStore

__all__ = ["main"]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2

# Fixed wording: the driver's own message can carry the host, database and user.
MIGRATE_CONNECTION_FAILED = "warden migrate: could not connect to the database"
AUDIT_CONNECTION_FAILED = "warden audit: could not connect to the database"


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

    audit_cmd = commands.add_parser("audit", help="audit trail verification and retention")
    audit_sub = audit_cmd.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("verify", help="verify the audit hash chain")
    purge_cmd = audit_sub.add_parser("purge", help="delete audit rows past the retention period")
    purge_cmd.add_argument(
        "--retention-days", type=int, help="overrides warden.audit.retention_days"
    )
    purge_cmd.add_argument("--actor", help="who is running the purge, for its audit record")
    grants_cmd = audit_sub.add_parser("grants", help="print the append-only grant SQL")
    grants_cmd.add_argument("--app-role", required=True)
    grants_cmd.add_argument("--forwarder-role")
    grants_cmd.add_argument("--purger-role")
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


async def _connect(dsn: str) -> Database:
    # Autocommit, so each warden operation runs in a transaction of its own.
    conn = await AsyncConnection.connect(dsn, autocommit=True)
    return Database(_OneConnection(conn))


async def _close(db: Database) -> None:
    async with db.connection() as conn:
        await conn.close()


async def _audit_verify(dsn: str, secrets: SecretStore, config: WardenConfig) -> VerificationReport:
    db = await _connect(dsn)
    try:
        return await verify_chain(db, KeyStore(db, secrets, config.keys))
    finally:
        await _close(db)


async def _audit_purge(
    dsn: str, secrets: SecretStore, config: WardenConfig, days: int, actor: str | None
) -> PurgeResult:
    db = await _connect(dsn)
    try:
        registry = ActionRegistry()
        register_audit_actions(registry)
        recorder = AuditRecorder(db, registry, details_max_bytes=config.audit.details_max_bytes)
        keys = KeyStore(db, secrets, config.keys)
        return await purge(recorder, keys, retention_days=days, actor=actor)
    finally:
        await _close(db)


def _audit(args: argparse.Namespace, dsn: str, secrets: SecretStore, config: WardenConfig) -> int:
    if args.audit_command == "verify":
        try:
            report = _run_async(_audit_verify(dsn, secrets, config))
        except psycopg.OperationalError:
            print(AUDIT_CONNECTION_FAILED, file=sys.stderr)
            return EXIT_FAILED
        if report.broken is not None:
            broken = report.broken
            print(f"audit chain broken at row {broken.row_id}: {broken.description}")
            return EXIT_FAILED
        print(
            f"audit chain intact: {report.rows} rows, {report.checkpoints} checkpoints"
            + ("" if report.last_id is None else f", head row {report.last_id}")
        )
        return EXIT_OK

    days = args.retention_days or config.audit.retention_days
    if days is None:
        print(
            "invalid warden configuration:\n"
            "  warden.audit.retention_days: is required for warden audit purge",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    try:
        result = _run_async(_audit_purge(dsn, secrets, config, days, args.actor))
    except psycopg.OperationalError:
        print(AUDIT_CONNECTION_FAILED, file=sys.stderr)
        return EXIT_FAILED
    except (RetentionError, KeyStoreError) as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED
    if result.purged_rows == 0:
        print("nothing to purge")
    else:
        print(
            f"purged {result.purged_rows} audit rows through row {result.through_id};"
            f" checkpoint row {result.checkpoint_id}"
        )
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: SettingsSource | None = None,
    secrets: SecretStore | None = None,
) -> int:
    """Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests."""
    args = _parser().parse_args(argv)
    if args.command == "audit" and args.audit_command == "grants":
        try:
            print(
                grants_sql(
                    app_role=args.app_role,
                    forwarder_role=args.forwarder_role,
                    purger_role=args.purger_role,
                ),
                end="",
            )
        except ValueError as exc:
            print(f"warden audit grants: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        return EXIT_OK
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

    if args.command == "audit":
        return _audit(args, dsn, secrets, config)

    try:
        key_id = _run_async(_rotate(dsn, secrets, config))
    except KeyStoreError as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED
    print(f"new signing key {key_id}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
