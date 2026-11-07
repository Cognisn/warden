# warden

Identity and audit for Python web applications: users, sign-in, invitations, OpenID Connect single sign-on, roles and permissions, API keys, and a tamper-evident audit trail with syslog forwarding.

> **Status: beta.** 0.1.0 is feature complete and in testing; it takes fixes only until its release. Before 1.0 a minor version may break the public API, and every break is named in the [changelog](https://github.com/Cognisn/warden/blob/main/CHANGELOG.md) with an upgrade note.

warden is built by [Cognisn](https://github.com/Cognisn) as the shared identity and audit foundation for its products. It is an embedded library, not a service: an application installs it, passes in its database connection pool and configuration, and mounts warden's FastAPI routers wherever it chooses. warden has no user interface; each application builds its own screens against warden's documented HTTP contract.

## What it provides

**Identity**

- User lifecycle: invite, activate, suspend and deactivate.
- Password sign-in with TOTP and recovery codes, with Argon2id hashing.
- Passkeys and security keys (WebAuthn): as a second factor beside TOTP, or a passkey on its own, with a `passkey_only` sign-in method, an emailed registration link and passkey invitations.
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
- Signed anchors of the chain's head, which a SIEM keeps and verification checks the database against.

The audit half works on its own, so an application with its own authentication can still use it.

## Requirements

- Python 3.12 or later.
- PostgreSQL. warden keeps its tables in a dedicated `warden` schema with its own migration history.
- FastAPI and psycopg 3, installed with warden.
- [`cognisn-konfig`](https://pypi.org/project/cognisn-konfig/) for configuration and secrets, installed with warden.

psycopg needs the PostgreSQL client library, libpq. Install the binary build alongside warden (`psycopg[binary]`) or provide a system libpq.

## Installation

```
pip install cognisn-warden "psycopg[binary]"
```

The import name is `warden`. A pre-release, such as `0.1.0rc1`, needs `pip install --pre cognisn-warden` or the exact version.

An application loads its `WardenConfig` through konfig, runs `warden migrate` against its database, passes warden its connection pool, and mounts warden's routers under prefixes it chooses. The [client-behaviour guide](https://github.com/Cognisn/warden/blob/main/docs/guide/clients.md) describes what a client of those routes must do, and the [HTTP contract](https://github.com/Cognisn/warden/blob/main/docs/contract/openapi.json) documents every route.

## Documentation

- [Design overview](https://github.com/Cognisn/warden/blob/main/docs/design/overview.md): decisions, scope, acceptance tests and delivery plan.
- [Client-behaviour guide](https://github.com/Cognisn/warden/blob/main/docs/guide/clients.md)
- [HTTP contract](https://github.com/Cognisn/warden/blob/main/docs/contract/openapi.json)
- [Changelog](https://github.com/Cognisn/warden/blob/main/CHANGELOG.md)
- [Security policy](https://github.com/Cognisn/warden/blob/main/SECURITY.md)

## Sample console

[`examples/console`](https://github.com/Cognisn/warden/blob/main/examples/console/README.md) is a small sample product that mounts warden's routers in FastAPI and exercises them from a plain HTML and JavaScript console: sign-in with TOTP, single sign-on, invitations and password reset (with an in-memory outbox), administration, API keys, and the audit trail with export, verification, anchors and syslog. It shows how a product integrates warden, using only warden's public surface. It is for local development only, not a deployment template, and it is not part of the published package.

## Licence

Licensed under the [Apache License, Version 2.0](https://github.com/Cognisn/warden/blob/main/LICENSE). Copyright 2026 Cognisn Pty Ltd. See [NOTICE](https://github.com/Cognisn/warden/blob/main/NOTICE).
