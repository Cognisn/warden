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
- Query and export. `AuditQuery` filters by time range (`occurred_at`), actions, actor, resource and outcome. `list_events()` pages newest first with a `before_id` cursor, and `iter_events()` streams every match in chain order from one snapshot. `warden.audit.export.export()` streams CSV or NDJSON and records the export itself (action `warden.audit.export`, with the filter) before the first line. CSV cells beginning with `=`, `+`, `-`, `@`, a tab or a carriage return are prefixed with `'`. NDJSON is ASCII-escaped, so no value can split a record.
- Append-only database grants. `warden.audit.grants_sql()` (and `warden audit grants`) produces re-runnable SQL for three non-owning roles. The application role reads and writes warden's tables but holds only `INSERT` and `SELECT` on `audit_events`, and only `SELECT` on the migration version table. The syslog forwarder role holds `SELECT` on `audit_events` and `SELECT`, `INSERT` and `UPDATE` on `settings`. The purger role holds `SELECT`, `INSERT` and `DELETE` on `audit_events` and `SELECT` on `signing_keys`. Re-run it after each migration.
- `warden.proxy.TrustedProxyMiddleware`, ASGI middleware that sets the request's client address from `X-Forwarded-For`, believed only when the peer is in `audit.trusted_proxies`. Entries are read from the right, skipping those added by further trusted proxies, and a malformed entry stops at the last known hop. `Forwarded` and `X-Real-IP` are never read, and IPv4-mapped peers are matched as IPv4. `resolve_client_ip()` is the single gate.
- `warden.audit.router.audit_router()`, FastAPI routes the product mounts under its audit prefix. `GET /events` lists events, `GET /export?format=csv|ndjson` streams an export and `GET /verify` returns the verification report. The product supplies authorisation as a dependency parameter (`authorise`, optionally `authorise_export` and `authorise_verify`), so `warden.audit` still imports nothing from `warden.identity`. Exports are recorded with the dependency's actor and the client address.
- Runtime dependency `fastapi` (MIT), agreed for this release in the development plan. Development dependency `httpx`, for tests.
- `warden audit verify`, which reports the chain intact (exit 0) or the first broken row and why (exit 1), never row contents. `warden audit purge [--retention-days N] [--actor NAME]`, which applies retention, defaulting to `audit.retention_days` and refusing a period below the minimum. Run it as the purger role. `warden audit grants --app-role ROLE [--forwarder-role ROLE] [--purger-role ROLE]` prints the grant SQL and needs no database. A connection failure prints a fixed message and exits 1.
- `warden.audit.syslog`: RFC 5424 formatting of committed audit rows. `format_message()` puts the row id in MSGID, the event in structured data under the configured SD-ID, and the action's summary in MSG; it replaces every control character (C0, DEL, C1 and the Unicode line separators) in every value, including MSG, before RFC 5424 escaping, and holds the whole message at or under `max_message_bytes`, cutting details first and marking the message `truncated="true"`. `SyslogSettings` carries the forwarder's settings, built from `SyslogConfig` with `SyslogSettings.from_config()`; the SD-ID has no default and refuses the documentation number 32473.
- Syslog transports: UDP, and TCP or TLS with octet-counting (default) or LF framing, opened with `open_transport()`. TLS verifies the collector's certificate chain and host name, requires TLS 1.2 or later and fails closed, with no plaintext fallback and no setting that disables verification; trust anchors come from `tls_ca_pem` (for konfig's secrets store), `tls_ca_file` or the system store. Failures raise `TransportError` with a fixed category, never the underlying error text. A tripwire test fails if any module disables certificate or host name verification.
- `SyslogForwarder`: forwards committed audit rows to syslog. It holds the session advisory lock `SYSLOG_FORWARDER_LOCK_KEY`, so one replica forwards and the others stand by and take over when its session ends; it listens on `AUDIT_CHANNEL` and, on each notification and on a periodic safety poll, reads rows above its cursor in id order from the table, so a rolled-back audit write is never forwarded. The cursor (`SYSLOG_CURSOR_SETTING` in `warden.settings`) advances only after a row is handed to the transport and never moves backwards; on first start it begins at the newest row unless `start_from="beginning"`. Delivery is at-least-once, with the row id as MSGID. A gap in row ids is held open for `grace_seconds` so a lower id that commits late is still sent in order, then passed. Rows committed while the collector is down are delivered when it returns, without affecting request latency, and notifications keep being read meanwhile. `status()` reports the cursor, the lag (rows not yet forwarded) and the last error; `reconfigure()` swaps settings without leaving a second connection open. The leading connection is borrowed from the product's pool for the forwarder's lifetime and closed, not returned, when leadership ends.
- `syslog_router()`: `GET /syslog/status` (role, connection, cursor, lag, last error) and `POST /syslog/test` (one test message over a fresh connection, reporting a fixed error category), mounted under a prefix the product chooses. The product supplies an `authorise` dependency that refuses unauthorised callers and returns the actor id; with a recorder, each test send is audited as `warden.syslog.test_sent` (register it with `register_syslog_actions()`).
- A live check of syslog forwarding against a real rsyslog collector over UDP, TCP and TLS, in both framings, including a hostile value under LF framing and a TLS refusal with the wrong CA (`tests/syslogfwd/test_syslog_live.py`, marked `integration`; the collector's image, configuration and compose file are in `tests/syslogfwd/live`).
- `warden.identity`, the identity core. A product constructs one `Identity` with its configuration, database, key store and `PermissionRegistry`, calls `identity.install(app)`, and mounts `identity.auth_router()` under its auth prefix.
- Users (`identity.users`) with the statuses `invited`, `active`, `suspended` and `deactivated`, and a sign-in method of `password_and_sso` or `sso_only`. Email addresses are unique regardless of case. Every change is audited.
- Passwords hashed with Argon2id. A legacy `pbkdf2:sha256` hash is verified and replaced with an Argon2id hash on the next successful sign-in.
- TOTP (RFC 6238) and recovery codes. A code is accepted at most once per time step and a recovery code at most once, even under concurrent requests. Codes must be six ASCII digits, so other scripts' digits are refused cleanly. An unconfirmed enrolment is never treated as MFA. With `identity.require_mfa`, a user without a confirmed enrolment must enrol before a session is issued.
- Sessions: short-lived EdDSA access tokens signed through the key store with the key id in the header, and verified only with `KeyStore.verify`, so retired and revoked keys refuse live tokens. Refresh tokens rotate in families. Reusing a refresh token revokes its family, with the reason in the audit trail; the immediate predecessor presented within the configurable grace window is refused without revoking. Sessions have an absolute lifespan, and shortening it ends existing sessions that are already older than the new limit.
- Session policy (token lifetimes, lifespan, reuse grace and MFA requirement) that an administrator can change at run time. Every replica caches it and drops the cache on a Postgres `NOTIFY` when it changes.
- Roles and permissions. The product registers permissions and defines roles as named sets of them. Users hold several roles, each optionally expiring. The last active administrator cannot be demoted, suspended or deactivated, even by concurrent requests. Every change is audited.
- FastAPI dependencies `require_user` and `require_permission`, with an optional resource-scope hook the product implements; a scoped check without a hook refuses.
- Public routes: sign in, TOTP verify, recovery code, refresh, sign out, change password, and TOTP enrolment. Every authentication failure returns the same 401 response (a signed-in user's wrong enrolment code gets a 400 instead, so the client does not take it for a sign-out), and sign-in takes the same time for an unknown user, a wrong password and an SSO-only user. The specific reason is recorded only in the audit trail.
- TOTP secrets are stored encrypted (AES-256-GCM, bound to their user) under a key held in konfig's secrets store as `warden.totp-key`. `Identity` refuses to start without it; generate one with `warden.identity.new_totp_key()`. To rotate, move the old key to `warden.totp-key.previous`, set a new one, run `identity.mfa.reseal_all()`, then remove the previous key.
- Sign-in throttling per identifier and source address: once a pair uses up its attempts in the window (default 10 in 15 minutes), further attempts get the same 401 without checking the password. Unknown identifiers are throttled alike, and only issuing a session clears the count. Expired records are removed by `identity.prune_sign_in_attempts()`.
- `identity.running()`, an async context manager for the product's FastAPI lifespan that runs the session-policy listener.
- A refused sign-in records the typed identifier in the audit trail only if it looks like an email address, so a password typed into the email field is never recorded.
- Migration `b7e14a2c9d30`, which follows `3f7a2c9d1b6e`, creates `warden.users`, `totp_credentials`, `recovery_codes`, `mfa_challenges`, `sessions`, `refresh_tokens`, `role_assignments` and `sign_in_attempts`. Reversible.
- Runtime dependency `argon2-cffi` (MIT), from the agreed set, for password hashing.

### Changed

- The design overview describes syslog forwarding from committed rows, replacing the earlier in-process queue that dropped a copy when full.

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
