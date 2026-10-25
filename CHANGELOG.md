# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `warden.audit.syslog`: RFC 5424 formatting of committed audit rows. `format_message()` puts the row id in MSGID, the event in structured data under the configured SD-ID, and the action's summary in MSG; it replaces every control character (C0, DEL, C1 and the Unicode line separators) in every value, including MSG, before RFC 5424 escaping, and holds the whole message at or under `max_message_bytes`, cutting details first and marking the message `truncated="true"`. `SyslogSettings` carries the forwarder's settings, built from `SyslogConfig` with `SyslogSettings.from_config()`; the SD-ID has no default and refuses the documentation number 32473.
- Syslog transports: UDP, and TCP or TLS with octet-counting (default) or LF framing, opened with `open_transport()`. TLS verifies the collector's certificate chain and host name, requires TLS 1.2 or later and fails closed, with no plaintext fallback and no setting that disables verification; trust anchors come from `tls_ca_pem` (for konfig's secrets store), `tls_ca_file` or the system store. Failures raise `TransportError` with a fixed category, never the underlying error text. A tripwire test fails if any module disables certificate or host name verification.
- `SyslogForwarder`: forwards committed audit rows to syslog. It holds the session advisory lock `SYSLOG_FORWARDER_LOCK_KEY`, so one replica forwards and the others stand by and take over when its session ends; it listens on `AUDIT_CHANNEL` and, on each notification and on a periodic safety poll, reads rows above its cursor in id order from the table, so a rolled-back audit write is never forwarded. The cursor (`SYSLOG_CURSOR_SETTING` in `warden.settings`) advances only after a row is handed to the transport and never moves backwards; on first start it begins at the newest row unless `start_from="beginning"`. Delivery is at-least-once, with the row id as MSGID. A gap in row ids is held open for `grace_seconds` so a lower id that commits late is still sent in order, then passed. Rows committed while the collector is down are delivered when it returns, without affecting request latency, and notifications keep being read meanwhile. `status()` reports the cursor, the lag (rows not yet forwarded) and the last error; `reconfigure()` swaps settings without leaving a second connection open. The leading connection is borrowed from the product's pool for the forwarder's lifetime and closed, not returned, when leadership ends.

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
