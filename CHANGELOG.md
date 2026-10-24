# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `warden.db.AUDIT_CHANNEL` (`warden_audit`), `SYSLOG_FORWARDER_LOCK_KEY` and `SYSLOG_CURSOR_SETTING`: the names the syslog forwarder uses to follow committed audit rows.
- The audit recorder issues `pg_notify` on `AUDIT_CHANNEL` with the row id, in the same transaction as each insert, so a notification arrives only for a committed row.

### Changed

- `AuditRecorder.record` offers events to sinks only after warden's own transaction commits, and never for a record written inside a caller's transaction (`conn=`). A rolled-back event no longer reaches a sink. Upgrade note: a sink that relied on seeing caller-owned records must read committed rows instead, as syslog forwarding now does.

- CI runs the test suite on Windows (Python 3.12 and 3.13), excluding the database tests, which need Linux containers and stay on the Linux job.

### Fixed

- `scripts/bump_version.py` now writes LF line endings on Windows, matching the repository's `eol=lf` rule.

## [0.1.0a1] - 2026-10-25

First pre-release of the initial build: the foundation (configuration, database access, key store and audit recorder contract).

### Added

- Repository scaffolding: working agreement, design overview, licence, notice, security policy and changelog.
- Minimum supported Python version set to 3.12.
- Packaging as `cognisn-warden` (import `warden`, typed), with a single version source in `warden.__version__` and `scripts/bump_version.py`, which stamps only on a matching `release/vX.Y.Z` branch.
- CI on Python 3.12 and 3.13: ruff, `mypy --strict`, the test suite against a real Postgres, and a licence audit (`scripts/licence_audit.py`) that refuses copyleft runtime dependencies, with psycopg (LGPL-3.0) as the one recorded exception.
- `warden.config`: `WardenConfig`, one typed configuration object loaded through konfig with `load_config()`, covering the `http`, `db`, `keys`, `audit`, `syslog`, `identity`, `sso` and `mail` sections. Invalid, unknown or inconsistent values raise `ConfigError` at start-up, naming each field and never echoing its value. `secret://` references resolve through the secrets store, and the SSO callback URL is derived rather than configured.
- `warden.db`: a `Database` adapter over the product's own psycopg 3 async pool with a `transaction()` helper that joins a caller's transaction, schema constants, and `migrate()`, `migrate_connection()`, `downgrade()`, `heads()` and `current_revision()` for warden's own Alembic chain in the `warden` schema (`warden.alembic_version`). Concurrent migration runs are serialised.
- Baseline migration creating `warden.audit_events`, `warden.signing_keys` and `warden.settings`, fully reversible.
- `warden.keys`: `KeyStore`, which holds Ed25519 signing keys by key id, with rotation, retirement (never of the last key, even under concurrent requests), verification and JWK publication. Private halves are held only in konfig's secrets store.
- `warden.audit`: the `AuditEvent` model, `Severity`, an `ActionRegistry` for product-registered actions with summary templates, the `AuditSink` protocol, and `record_audit()` / `AuditRecorder.record()` as the single writer to the audit table.
- `warden` command: `warden migrate` and `warden keys rotate`.
- Tripwire tests: a single writer to the audit table, `warden.audit` never importing `warden.identity`, anchored patterns using `fullmatch`, and no direct reading of the environment or files.
