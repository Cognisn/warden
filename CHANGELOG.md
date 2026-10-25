# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- Migration `b7e14a2c9d30` creates `warden.users`, `totp_credentials`, `recovery_codes`, `mfa_challenges`, `sessions`, `refresh_tokens`, `role_assignments` and `sign_in_attempts`. Reversible.
- Runtime dependencies `argon2-cffi` and `fastapi`, both from the agreed set; `httpx` for tests only.

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
