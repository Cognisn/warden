# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffolding: working agreement, design overview, licence, notice, security policy and changelog.
- Minimum supported Python version set to 3.12.
- Packaging as `cognisn-warden` (import `warden`, typed), with a single version source in `warden.__version__` and `scripts/bump_version.py`, which stamps only on a matching `release/vX.Y.Z` branch.
- CI on Python 3.12 and 3.13: ruff, `mypy --strict`, the test suite against a real Postgres, and a licence audit (`scripts/licence_audit.py`) that refuses copyleft runtime dependencies, with psycopg (LGPL-3.0) as the one recorded exception.
- `warden.config`: `WardenConfig`, one typed configuration object loaded through konfig with `load_config()`, covering the `http`, `db`, `keys`, `audit`, `syslog`, `identity`, `sso` and `mail` sections. Invalid, unknown or inconsistent values raise `ConfigError` at start-up, naming each field and never echoing its value. `secret://` references resolve through the secrets store, and the SSO callback URL is derived rather than configured.
