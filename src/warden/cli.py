"""The ``warden`` command.

    warden [--config FILE] [--env-prefix PREFIX] migrate [--revision REV]
    warden [--config FILE] [--env-prefix PREFIX] keys rotate
    warden [--config FILE] [--env-prefix PREFIX] audit verify [--anchors FILE]
    warden [--config FILE] [--env-prefix PREFIX] audit purge [--retention-days N] [--actor NAME]
    warden [--config FILE] [--env-prefix PREFIX] audit anchor [--actor NAME] [--min-rows N]
    warden audit grants --app-role ROLE [--forwarder-role ROLE] [--purger-role ROLE]

Configuration is read through konfig exactly as a product reads it: the
``warden`` section of the given config file, overridden by environment
variables under ``--env-prefix``. ``warden.db.dsn`` names the database;
it may be a ``secret://`` reference. Output carries identifiers only, never
key material or connection strings. ``audit grants`` only prints SQL and
needs no database.

``audit purge`` deletes audit rows, so it must connect as the purger role
(see ``warden.audit.grants``); the application's role cannot delete them.

``audit anchor`` appends a signed attestation of the chain head, for the
product's scheduler to run (warden ships none); the application's role is
enough. ``audit verify --anchors FILE`` also checks the chain against anchors
exported from a SIEM, as NDJSON or as forwarded syslog messages, one per line.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import psycopg
import sqlalchemy.exc
from psycopg import AsyncConnection

from warden import __version__
from warden.audit.actions import register_audit_actions
from warden.audit.anchor import (
    MAX_ANCHOR_ACTOR,
    AnchorError,
    AnchorRecord,
    ExternalAnchor,
    anchor,
    read_anchors,
)
from warden.audit.grants import grants_sql
from warden.audit.recorder import AuditRecorder
from warden.audit.registry import ActionRegistry
from warden.audit.retention import PurgeResult, RetentionError, purge
from warden.audit.verify import AnchorReport, VerificationReport, verify_anchors, verify_chain
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
KEYS_CONNECTION_FAILED = "warden keys: could not connect to the database"


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
    verify_cmd = audit_sub.add_parser("verify", help="verify the audit hash chain")
    verify_cmd.add_argument(
        "--anchors", help="also check anchors exported from a SIEM (NDJSON or syslog lines)"
    )
    purge_cmd = audit_sub.add_parser("purge", help="delete audit rows past the retention period")
    purge_cmd.add_argument(
        "--retention-days", type=int, help="overrides warden.audit.retention_days"
    )
    purge_cmd.add_argument("--actor", help="who is running the purge, for its audit record")
    anchor_cmd = audit_sub.add_parser("anchor", help="append a signed attestation of the head")
    anchor_cmd.add_argument(
        "--actor",
        type=_anchor_actor,
        help=f"who is anchoring, for the anchor's audit record (at most {MAX_ANCHOR_ACTOR})",
    )
    anchor_cmd.add_argument(
        "--min-rows",
        type=_positive,
        help="anchor only if at least N rows were appended since the last anchor",
    )
    grants_cmd = audit_sub.add_parser("grants", help="print the append-only grant SQL")
    grants_cmd.add_argument("--app-role", required=True)
    grants_cmd.add_argument("--forwarder-role")
    grants_cmd.add_argument("--purger-role")
    return parser


def _positive(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _anchor_actor(text: str) -> str:
    if len(text) > MAX_ANCHOR_ACTOR:
        raise argparse.ArgumentTypeError(f"must be at most {MAX_ANCHOR_ACTOR} characters")
    return text


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


async def _audit_verify_anchors(
    dsn: str, secrets: SecretStore, config: WardenConfig, anchors: list[ExternalAnchor]
) -> AnchorReport:
    db = await _connect(dsn)
    try:
        return await verify_anchors(db, KeyStore(db, secrets, config.keys), anchors)
    finally:
        await _close(db)


async def _audit_anchor(
    dsn: str, secrets: SecretStore, config: WardenConfig, actor: str | None, min_rows: int | None
) -> AnchorRecord | None:
    db = await _connect(dsn)
    try:
        registry = ActionRegistry()
        register_audit_actions(registry)
        recorder = AuditRecorder(db, registry, details_max_bytes=config.audit.details_max_bytes)
        keys = KeyStore(db, secrets, config.keys)
        return await anchor(recorder, keys, actor=actor, min_rows=min_rows)
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


def _print_chain(report: VerificationReport) -> None:
    if report.broken is not None:
        broken = report.broken
        print(f"audit chain broken at row {broken.row_id}: {broken.description}")
        return
    print(
        f"audit chain intact: {report.rows} rows, {report.checkpoints} checkpoints"
        + ("" if report.last_id is None else f", head row {report.last_id}")
    )


def _print_anchors(report: AnchorReport) -> None:
    checks = report.anchors
    matched = sum(1 for c in checks if c.status == "matched")
    covered = sum(1 for c in checks if c.status == "checkpointed")
    failed = [c for c in checks if not c.ok]
    print(
        f"anchors: {len(checks)} checked, {matched} matched,"
        f" {covered} behind checkpoints, {len(failed)} failed"
    )
    for check in failed:
        where = "" if check.head_id is None else f" (head row {check.head_id})"
        print(f"anchor on line {check.line}{where}: {check.description}")


def _read_anchors_file(path: str) -> list[ExternalAnchor] | None:
    try:
        text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    # Split on newlines only: str.splitlines() would also split on characters
    # such as U+2028 that a syslog value or JSON string may legitimately hold.
    return read_anchors(text.split("\n"))


def _audit_verify_command(
    args: argparse.Namespace, dsn: str, secrets: SecretStore, config: WardenConfig
) -> int:
    if args.anchors is None:
        try:
            report = _run_async(_audit_verify(dsn, secrets, config))
        except psycopg.OperationalError:
            print(AUDIT_CONNECTION_FAILED, file=sys.stderr)
            return EXIT_FAILED
        _print_chain(report)
        return EXIT_OK if report.ok else EXIT_FAILED

    anchors = _read_anchors_file(args.anchors)
    if anchors is None:
        # The path is the operator's own, but it is kept out of the output all the same.
        print("warden audit verify: cannot read the anchors file", file=sys.stderr)
        return EXIT_CONFIG
    if not anchors:
        print("warden audit verify: no anchors found in the anchors file", file=sys.stderr)
        return EXIT_FAILED
    try:
        full = _run_async(_audit_verify_anchors(dsn, secrets, config, anchors))
    except psycopg.OperationalError:
        print(AUDIT_CONNECTION_FAILED, file=sys.stderr)
        return EXIT_FAILED
    _print_chain(full.chain)
    _print_anchors(full)
    return EXIT_OK if full.ok else EXIT_FAILED


def _audit_anchor_command(
    args: argparse.Namespace, dsn: str, secrets: SecretStore, config: WardenConfig
) -> int:
    try:
        written = _run_async(_audit_anchor(dsn, secrets, config, args.actor, args.min_rows))
    except psycopg.OperationalError:
        print(AUDIT_CONNECTION_FAILED, file=sys.stderr)
        return EXIT_FAILED
    except (AnchorError, KeyStoreError) as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED
    if written is None:
        print("nothing to anchor")
    else:
        print(f"anchored head row {written.anchor.head_id} in audit row {written.row_id}")
    return EXIT_OK


def _audit(args: argparse.Namespace, dsn: str, secrets: SecretStore, config: WardenConfig) -> int:
    if args.audit_command == "verify":
        return _audit_verify_command(args, dsn, secrets, config)
    if args.audit_command == "anchor":
        return _audit_anchor_command(args, dsn, secrets, config)

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
    except psycopg.OperationalError:
        print(KEYS_CONNECTION_FAILED, file=sys.stderr)
        return EXIT_FAILED
    except KeyStoreError as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED
    print(f"new signing key {key_id}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
