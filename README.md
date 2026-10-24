# warden

Identity and audit for Python web applications: users, sign-in, invitations, OpenID Connect single sign-on, roles and permissions, API keys, and a tamper-evident audit trail with syslog forwarding.

> **Status: pre-alpha.** The design is agreed and implementation has not started. Nothing here is usable yet, and the API will change without notice until the first release.

warden is built by [Cognisn](https://github.com/Cognisn) as the shared identity and audit foundation for its products. It is an embedded library, not a service: an application installs it, passes in its database connection pool and configuration, and mounts warden's FastAPI routers wherever it chooses. warden has no user interface; each application builds its own screens against warden's documented HTTP contract.

## What it will provide

**Identity**

- User lifecycle: invite, activate, suspend and deactivate.
- Password sign-in with TOTP and recovery codes, with Argon2id hashing.
- Invitations and password reset by single-use, expiring emailed links.
- OpenID Connect single sign-on: authorisation code with PKCE, pre-provisioned accounts only, and local password sign-in kept as the break-glass path.
- Access tokens and rotating refresh tokens, with reuse detection and an absolute session lifespan.
- API keys scoped to a subset of permissions.
- Roles defined by the application as named sets of its own permissions, with FastAPI dependencies to enforce them.

**Audit**

- One recording funnel for warden's own events and the application's.
- A hash-chained, append-only audit trail, with a verification command.
- Forwarding to a syslog collector (RFC 5424 over UDP, TCP or TLS) that never slows a request.
- Filtering and export to CSV or NDJSON.
- Configurable retention, with signed checkpoints that keep the chain verifiable across purges.

The audit half works on its own, so an application with its own authentication can still use it.

## Requirements (planned)

- Python 3.12 or later.
- PostgreSQL. warden keeps its tables in a dedicated `warden` schema with its own migration history.
- FastAPI and psycopg 3.
- [`cognisn-konfig`](https://pypi.org/project/cognisn-konfig/) for configuration and secrets.

## Documentation

- [Design overview](docs/design/overview.md): decisions, scope, acceptance tests and delivery plan.
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE). Copyright 2026 Cognisn Pty Ltd. See [NOTICE](NOTICE).
