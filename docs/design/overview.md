# warden: Design Overview

**Status:** Design agreed, implementation not started.
**Last updated:** 24 October 2026

This is the design document the code is built against. Decisions recorded here are standing; see `CLAUDE.md` for how they are changed.

## 1. Purpose

warden is a reusable Python library that gives every Cognisn product the same identity and audit foundation: users, sign-in, invitations, single sign-on, roles and permissions, API keys, and a tamper-evident audit trail with syslog forwarding, filtering, export and retention.

It is written from scratch. The design draws on the identity and audit implementation in Cognisn's Termograph product and on the hardening findings recorded against it, which become warden's acceptance tests (section 5). No code is copied from any other product. VOR is the first consumer; Termograph adopts warden in its v0.8.0 release.

## 2. Decisions

| # | Area | Decision |
|---|---|---|
| D1 | Origin | Written from scratch, using Termograph's design and lessons as reference only. No code is copied. |
| D2 | Shape | An embedded toolkit installed into each product, with FastAPI routers the product mounts. Not a separate service or container. |
| D3 | Front end | Python only. Each product builds its own screens against a documented, versioned HTTP contract, which includes the client-side rules (token storage, refresh races, reuse handling). |
| D4 | Tenancy | Single organisation per deployment. No tenant column. Organisation, tier and platform-administrator concepts stay in the product. |
| D5 | Authorisation | Each product declares its permissions and defines roles as named sets of them. Users may hold several roles. warden stores and enforces assignments, audits every change and protects the last administrator. Resource-level scoping (for example per-collection access) is a product hook. |
| D6 | Credentials | Local password with TOTP (the break-glass path), recovery codes, invitations, password reset, OIDC single sign-on with PKCE and pre-provisioned accounts, access and refresh tokens with rotation families, and API keys. |
| D7 | OAuth server | Out of scope. An OAuth 2.1 authorisation server for MCP clients stays in each product, or becomes a spindl capability that calls warden to validate users and keys. |
| D8 | Distribution | Public on PyPI as `cognisn-warden` (import name `warden`), Apache-2.0. |
| D9 | Mounting | The product mounts warden's routers under prefixes it chooses and supplies, through one typed configuration object read via konfig: public base URL, mount prefixes, and UI link templates (accept invitation, reset password, SSO completion). The SSO callback URI is derived, never configured separately. Missing or inconsistent values fail at start-up. |
| D10 | Audit | warden includes an audit subsystem: a single recording funnel, product-defined events, syslog forwarding (RFC 5424 over UDP, TCP or TLS), filtering and export, and configurable retention. |
| D11 | Audit independence | `warden.audit` imports nothing from `warden.identity`; identity records through audit. A product with its own authentication, or a worker process, can use audit alone. Enforced by an import tripwire test. |
| D12 | Syslog naming | Structured data uses `warden@<PEN>` with Cognisn's IANA Private Enterprise Number, registered before the first release. The documentation number 32473 is never shipped. |
| D13 | Tamper evidence | Hash-chained audit rows, append-only database grants, and signed checkpoint events written by every retention purge, with a verification route and CLI. |
| D14 | Signing | Ed25519 keys held in konfig's secrets store, identified by key id, rotatable without signing users out. One key family signs session tokens and audit checkpoints. Public keys are published so other components can verify without being able to sign. |
| D15 | Passwords | Argon2id (`argon2-cffi`) for new hashes. Legacy `pbkdf2:sha256` hashes are verified and transparently rehashed on the next successful sign-in, so migrating users need no forced reset. |
| D16 | Database | warden's tables live in a dedicated `warden` Postgres schema with its own Alembic chain and version table (`warden.alembic_version`), applied by `warden migrate` or a single call from the product's migration step. At runtime the product passes in its existing psycopg 3 async pool, so a product write and its audit event can share a transaction. |
| D17 | Python | Python 3.12 or later. Python 3.10 reached end of life in October 2026, and 3.12 is what VOR targets and what Termograph's CI already tests against. |

## 3. Scope

### 3.1 In scope for the first release

**Identity (`warden.identity`)**

- Users: create, invite, activate, suspend and deactivate, with the statuses `invited`, `active`, `suspended` and `deactivated`.
- A sign-in method per user, `password_and_sso` or `sso_only`, set by an administrator.
- Local password sign-in with TOTP, recovery codes, and a forced MFA enrolment policy. Unknown users, wrong passwords and SSO-only accounts are handled identically in both response body and timing.
- Invitations: single-use, expiring, hashed tokens carrying staged role grants, with resend and revoke, and password and SSO acceptance variants.
- Password reset by emailed link, change password, and refusal paths for SSO-only accounts.
- OIDC single sign-on:
  - one identity provider per deployment
  - authorisation code with PKCE (S256)
  - cached discovery and JWKS
  - pre-provisioned accounts only, with the subject pinned on first sign-in
  - allowed email domains
  - an administrator test-configuration action
  - one generic failure message in the browser, with the real reason recorded in the audit trail only
  - provider presets (Entra ID, Google, Okta, generic) used as labels for setup guidance only
- Sessions:
  - short-lived signed access tokens
  - rotating refresh tokens grouped in families, with reuse detection and a configurable rotation grace window
  - an absolute session lifespan, with a cut-off when the lifespan is shortened
  - a byte-identical refusal for every failure
- API keys: prefixed, hashed, expiring, revocable, scoped to a subset of the product's permissions, and refused once their user is no longer active.
- Roles and permissions: a product-declared registry, users holding several roles, `require_user` and `require_permission` FastAPI dependencies, a resource-scope hook, protection of the last administrator, and optional expiry on a role assignment.
- Mail: a sender protocol the product implements (for example SES, SMTP or Microsoft 365), and templated messages for invitation, password reset and MFA enrolment, which the product can override.
- Pruning of expired refresh and single-use tokens.

**Audit (`warden.audit`)**

- `record_audit()` as the only writer, with a tripwire test that fails on any second writer.
- Product-registered event actions with severity and summary templates.
- Actor, action, resource, outcome, source IP and structured details on every event, with the details size-capped.
- Trusted-proxy middleware for the real client IP: forwarded headers are believed only from configured proxy ranges, and the rightmost forwarded entry is used.
- Syslog forwarding:
  - RFC 5424 over UDP, TCP or TLS, with octet-counting or LF framing
  - control characters neutralised in every value
  - a bounded queue that drops a copy rather than ever blocking a request
  - TLS that fails closed, with no plaintext fallback
  - secrets read through konfig
  - status and test-send routes
- Filtering by time range, action, actor, resource and outcome, and export as CSV (with formula-injection escaping) or NDJSON. Exports are themselves audited.
- Retention: a configurable period with an enforced minimum, a scheduled purge, and a signed checkpoint per purge.
- Tamper evidence: a per-row hash chain, plus a verification route and a `warden audit verify` CLI that report the first broken link.

**Shared**

- Ed25519 key management with rotation, and a public-keys route.
- konfig-backed configuration with start-up validation.
- Cache invalidation across replicas for settings and session policy, over Postgres `LISTEN/NOTIFY` (no Redis dependency).
- A documented HTTP contract: OpenAPI plus a client-behaviour guide.

### 3.2 Out of scope

- User interface components (D3).
- An OAuth 2.1 authorisation server for MCP clients (D7).
- SAML, SCIM, mapping identity-provider groups to roles, and more than one identity provider per deployment.
- Multi-tenancy (D4).
- Idle session timeout (a later setting).
- Product-specific resource scoping, entitlements and licensing.

## 4. Package layout (proposed)

```
src/warden/
  config.py            typed configuration, konfig binding, start-up validation
  keys.py              Ed25519 key store, rotation, public-key publication
  proxy.py             trusted-proxy middleware
  cli.py               warden migrate, keys rotate, audit verify, audit purge
  db/                  pool adapter, schema helpers, Alembic environment (schema "warden")
  audit/               recorder, event registry, hash chain, syslog emitter,
                       query and export, retention and checkpoints, routers
  identity/
    users.py           user model and lifecycle
    passwords.py       Argon2id, legacy PBKDF2 verify, rehash on sign-in
    totp.py            TOTP with step replay guard, recovery codes
    tokens.py          access and refresh tokens, families, session policy
    single_use.py      invitation and reset tokens (atomic consume)
    apikeys.py         API keys
    roles.py           permission registry, role sets, assignments
    mail.py            sender protocol, templates
    dependencies.py    require_user, require_permission, resource hook
    sso/               discovery, JWKS, PKCE client, id_token validation, matching
    routers/           public sign-in routes, administration routes
```

## 5. Acceptance tests

Each behaviour below is written as a failing test before the code that satisfies it. The numbered items correspond to hardening findings recorded against Termograph's implementation.

| Origin | Behaviour warden must show |
|---|---|
| Termograph #124 | A TOTP code is accepted at most once per time step. |
| Termograph #125 | A non-ASCII TOTP code is refused cleanly, never with a server error. |
| Termograph #126 | A recovery code cannot be used twice by concurrent requests. |
| Termograph #127 | Invitation and reset tokens cannot be consumed twice by concurrent submits. |
| Termograph #128 | Accepting an invitation checks the user's current status. |
| Termograph #129 | Revoking an invitation cannot delete a user who accepted concurrently. |
| Termograph #130 | An unconfirmed TOTP enrolment is not treated as MFA. |
| Termograph #131 | Refresh-token reuse is detected through rotation families, with a uniform refusal and an audited reason. |
| Termograph #132 | Refresh, TOTP verification and API keys issue nothing to users who are no longer active. |
| Termograph #133 | Sign-in timing does not reveal whether a username exists. |
| Termograph #134 | Expired refresh and single-use tokens are pruned. |
| Termograph #135 | Every anchored validation pattern rejects a trailing newline. |
| Termograph #154 | A wrong-method invitation acceptance leaves the invitation usable; a status refusal uses it up. |
| Syslog review | No audit value can inject a second syslog frame under LF framing. |
| Single writer | No module other than the audit recorder inserts into the audit table. |
| Independence | `warden.audit` imports nothing from `warden.identity`. |

## 6. Delivery plan

| Milestone | Content | Exit criteria |
|---|---|---|
| M0 Groundwork | Package skeleton, CI (tests, type checking, lint, licence audit), konfig binding, `warden` Postgres schema and Alembic chain, key store. | `warden migrate` creates an empty schema; CI green. |
| M1 Audit core | Recorder, event registry, hash chain and verification, query and export routes, retention with checkpoints, trusted-proxy middleware. | Single-writer and independence tripwires green; chain verification detects an altered row. |
| M2 Syslog | Emitter, transports, formatter with control-character neutralisation, status and test routes. | Live check against a real collector over UDP, TCP and TLS; a forced-drop run shows no change in request latency. |
| M3 Identity core | Users, passwords, TOTP, sessions and refresh families, permissions and roles, dependencies, public sign-in routes. | Acceptance tests #124, #125, #126, #130, #131, #132 and #133 green. |
| M4 Lifecycle | Invitations, password reset, mail protocol and templates, administration routes, API keys, pruning. | #127, #128, #129, #134 and #154 green. |
| M5 Single sign-on | OIDC client, discovery and JWKS caching, account matching, settings and test-configuration routes. | Live round trip against a stub identity provider, including break-glass sign-in with the provider stopped. |
| M6 Contract and release | OpenAPI contract, client-behaviour guide, examples, `0.1.0` release candidate. | A consuming product integrates on a feature branch; contract reviewed. |

## 7. Adoption

**VOR (first consumer).** VOR takes warden as a dependency alongside konfig and Kvasir, declares its permissions and role set (Viewer, Analyst, Detection Engineer, Approver, Auditor, Admin, Respondent) and implements the mail sender. Its time-limited Respondent role uses the optional expiry on role assignments.

**Termograph (v0.8.0).** A dedicated migration slice in that product:

- Map its roles and per-collection memberships onto warden permissions plus the resource-scope hook.
- Migrate users, TOTP credentials and SSO subject pins into the `warden` schema. Existing PBKDF2 hashes carry over and are rehashed on sign-in.
- Migrate its audit events into warden's audit table, starting a new hash chain with a checkpoint recording the import.
- Move syslog forwarding to warden, switching the structured-data identifier to the registered PEN, and tell clients to update their SIEM rules.
- Move its container images from `python:3.10-slim` to `python:3.12-slim` (D17), aligning the shipped runtime with the version its CI already tests.
- Retire its own identity, SSO and syslog modules once parity is proven by its live suites.

## 8. Open items

1. Register Cognisn's IANA Private Enterprise Number before the first release (D12).
2. Licence choice pending legal confirmation (D8).
3. Default retention period and minimum for the audit trail.
4. Whether checkpoint signatures should also be anchored outside the database (for example, emitted to syslog), so a database administrator cannot replace both the chain and its checkpoints.

## References

- RFC 5424, The Syslog Protocol, section 6.3.2: <https://www.rfc-editor.org/rfc/rfc5424#section-6.3.2>
- RFC 5612, Enterprise Number for Documentation Use: <https://www.rfc-editor.org/rfc/rfc5612>
- RFC 6238, TOTP: Time-Based One-Time Password Algorithm, section 5.2: <https://www.rfc-editor.org/rfc/rfc6238#section-5.2>
- RFC 7636, Proof Key for Code Exchange: <https://www.rfc-editor.org/rfc/rfc7636>
- OpenID Connect Core 1.0: <https://openid.net/specs/openid-connect-core-1_0.html>
- IANA Private Enterprise Numbers: <https://pen.iana.org>
- OWASP Password Storage Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
