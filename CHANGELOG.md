# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Hash-chained audit rows. Each row stores `prev_hash` and a SHA-256 `row_hash` over a canonical serialisation of every stored column, specified in `docs/design/audit-chain.md`. `record_audit()` and `AuditRecorder.record()` keep their signatures. Appends take a transaction-scoped chain lock before the row's id is drawn and hold it until the transaction ends, so the chain never forks and row id order equals commit order. A record written inside a caller's transaction holds the lock until the caller commits, so keep such transactions short.
- `warden.audit.AuditChainConflict`, raised instead of forking the chain when a REPEATABLE READ or SERIALIZABLE transaction's snapshot predates the chain head; retry the transaction.
- `AuditRecorder(details_max_bytes=...)` enforces the details cap (default 8192 bytes, `audit.details_max_bytes`). Oversized details are replaced whole by the declared marker `{"warden.truncated": {"original_bytes": N}}`, and the key `warden.truncated` is reserved. Details holding a non-finite number or a NUL character are refused.
- Migration `3f7a2c9d1b6e` adds `audit_events.recorded_at`, server time defaulting to `clock_timestamp()`, which chain order and retention follow instead of the caller-supplied `occurred_at`. It also makes the chain hashes required and 32 bytes long, adds a unique index on `prev_hash` so two rows cannot claim one predecessor, and constrains `outcome` to `success` or `failure`. Reversible. Upgrade note: the upgrade refuses to run while unchained rows written by 0.1.0a1 or 0.1.0a2 exist.
- `warden.audit.verify_chain()` verifies the audit trail from one consistent snapshot. It returns a `VerificationReport` whose `broken` names the first broken link by row id and reason: altered contents, a broken link to the previous row, an unanchored first row, or a malformed, forged or revoked-key retention checkpoint. Checkpoint signatures are checked with `KeyStore.verify_historical()`, so routine key retirement leaves them valid.
- Retention. `warden.audit.purge()` deletes the oldest prefix of the trail whose rows are all older than `retention_days`, which may not be below `MIN_RETENTION_DAYS` (provisionally 365). It first verifies that prefix and refuses, recording the refusal, if it is broken, so a purge cannot launder tampering. It then appends a checkpoint row signed with warden's Ed25519 key, carrying the hash the surviving chain links to, and deletes the prefix in the same transaction. The checkpoint (action `warden.audit.purge`) is the purge's own audit record and is never truncated, and verification continues across it. The format is specified in `docs/design/audit-chain.md`.
- A tripwire test fails if any module other than the retention purge deletes audit rows, or if any module edits or truncates them.

## [0.1.0a2] - 2026-10-25

Second pre-release: the contract changes wave 1 builds on (audit forwarding from committed rows, retired and revoked signing keys), plus CI and CLI hardening.

### Added

- `warden.db.AUDIT_CHANNEL` (`warden_audit`), `SYSLOG_FORWARDER_LOCK_KEY` and `SYSLOG_CURSOR_SETTING`: the names the syslog forwarder uses to follow committed audit rows.
- The audit recorder issues `pg_notify` on `AUDIT_CHANNEL` with the row id, in the same transaction as each insert, so a notification arrives only for a committed row.
- Signing key revocation. `KeyStore.revoke()` marks a compromised key so nothing it signed is trusted; it also retires the key and refuses the last unretired key, even under concurrent requests. `KeyStore.verify_historical()` verifies historical artefacts such as audit checkpoints, accepting retired keys but never revoked ones; `verify()` keeps refusing both. `public_keys()` never lists a revoked key, even with `include_retired=True`.
- Migration `8d41b7c3a9f2` adds `warden.signing_keys.revoked_at`, with checks that a revocation is not earlier than creation and that a revoked key is also retired. Reversible.

### Changed

- CI pins every GitHub Action to a full commit SHA instead of a movable tag, and a tripwire test fails on any action that is not pinned.

- `AuditRecorder.record` offers events to sinks only after warden's own transaction commits, and never for a record written inside a caller's transaction (`conn=`). A rolled-back event no longer reaches a sink. Upgrade note: a sink that relied on seeing caller-owned records must read committed rows instead, as syslog forwarding now does.

- CI runs the test suite on Windows (Python 3.12 and 3.13), excluding the database tests, which need Linux containers and stay on the Linux job.

### Fixed

- `warden migrate` no longer prints a traceback when it cannot reach the database. It prints a fixed message, without the host, database or user, and exits with code 1.

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
