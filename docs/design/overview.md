# warden: Design Overview

**Status:** Design agreed; implementation in progress (0.1.0 pre-releases).
**Last updated:** 10 November 2026

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
| D12 | Syslog naming | Structured data uses `warden@67382`, from Cognisn's IANA Private Enterprise Number 67382, as the default SD-ID. A product may set its own valid SD-ID. The documentation number 32473 is never shipped and is refused. |
| D13 | Tamper evidence | Hash-chained audit rows, append-only database grants, and signed checkpoint events written by every retention purge, with a verification route and CLI. Signed head attestations can be exported (for example to a SIEM) and checked against the chain, so a database administrator cannot replace both the chain and its checkpoints unnoticed. |
| D14 | Signing | Ed25519 keys held in konfig's secrets store, identified by key id, rotatable without signing users out. One key family signs session tokens and audit checkpoints. Public keys are published so other components can verify without being able to sign. |
| D15 | Passwords | Argon2id (`argon2-cffi`) for new hashes. Legacy `pbkdf2:sha256` hashes are verified and transparently rehashed on the next successful sign-in, so migrating users need no forced reset. |
| D16 | Database | warden's tables live in a dedicated `warden` Postgres schema with its own Alembic chain and version table (`warden.alembic_version`), applied by `warden migrate` or a single call from the product's migration step. At runtime the product passes in its existing psycopg 3 async pool, so a product write and its audit event can share a transaction. |
| D17 | Python | Python 3.12 or later. Python 3.10 reached end of life in October 2026, and 3.12 is what VOR targets and what Termograph's CI already tests against. |
| D18 | WebAuthn | Passkeys and security keys (WebAuthn) are added to 0.1.0 as additive scope. They serve as a second factor beside TOTP and, for discoverable credentials registered with user verification, as a sign-in on their own, with a `passkey_only` sign-in method. The relying party defaults to the host of the public base URL and every allowed origin is compared exactly. Registration accepts any authenticator unless trusted attestation roots are configured, in which case only chains to a root register (synced passkeys then do not); warden never fetches attestation metadata. User verification is preferred for a second factor and required for a passkey. Each challenge is single-use and consumed by one guarded write, a signature counter that does not increase is refused as a suspected clone, and every refusal is the uniform refusal with its reason in the audit trail only. An administrator's reset of every second factor, and an emailed single-use link, recover a user who has lost their passkeys. Built on `fido2`'s data types and attestation verifiers, with every ceremony check written in warden; no device code is loaded. |
| D19 | Password policies | Password policies, watch lists and live feedback join 0.1.0 as additive scope (rulings PW0 to PW14 of 10 November 2026). **Model.** Policies live in the `warden` schema and are managed at run time through administration routes behind a permission. A user's policy is, in order, a pin on the user, the highest-priority policy mapped from a role the product still declares, or the one default policy, which is seeded to reproduce 0.1.0b18 (the minimum length from `identity.password_min_length`, no class rule, no expiry, no history) and adds the built-in common-password list. Rules are fixed and deterministic: length in Unicode code points after NFC, a required count of character classes, the longest run of one character, whether the email local part or display name may appear, and a passphrase (length and word count) that may waive the class rule. Ordered tiers, strongest first, give each password a maximum age or none. The rules are published as a versioned JSON description that a browser evaluates, `docs/contract/password-rule-vectors.json` holds 59 test cases a client uses to prove it agrees, and the server stays the authority. One path, `PasswordEnforcement`, applies the policy at every place a password is set and at password sign-in. **Storage.** History keeps Argon2id hashes only, never a faster hash, checked by a real Argon2id verification off the event loop and only when a password is submitted, never by the live check route. No column holds a password, its length or makeup, an unsealed digest or a hash prefix. A policy may enable a sealed fingerprint: the SHA-1 of the password, sealed with AES-256-GCM under a konfig key (current and previous, rotating like the TOTP keys) and bound to the user's id, so that `warden passwords recheck` can compare passwords in use with lists that changed later. The trade-off is accepted and stated: anyone holding both the database and the key can recover a fast hash of each fingerprinted password. It is off in the seeded default. **Watch lists.** The built-in list (about 100,000 SHA-1 digests from SecLists, MIT) is on in the default; local lists hold exact passwords (SHA-1), imports in Have I Been Pwned's downloader format with a threshold, and contained terms, each with the reason a user is shown. The Pwned Passwords range API (k-anonymity: five hex characters are sent, answers are padded, the base URL is configurable for a self-hosted mirror) is the only third-party request warden makes on a user's behalf, is made only for a policy that enables it, and is off in the default. When it cannot answer, the policy chooses to allow (audited) or refuse, and it never stops a sign-in. **Forced change.** After a correct password and the second factor, a required change (reason `expired`, `watch_list`, `administrator` or `policy`) answers `password_change_required` with a short-lived, single-use challenge in place of a session, and the new password is accepted only against that challenge. Passkey and single sign-on sign-ins are never blocked by a password's state. **NIST SP 800-63B-4.** The default follows section 3.1.1.2: length over composition, a blocklist with the reason given, and change on evidence of compromise. Scheduled change (tiers with a maximum age), class rules and the substring-based rules (terms, user details, repeat) depart from it; each is a setting that is off in the default, so an operator departs knowingly. |

## 3. Scope

### 3.1 In scope for the first release

**Identity (`warden.identity`)**

- Users: create, invite, activate, suspend and deactivate, with the statuses `invited`, `active`, `suspended` and `deactivated`.
- A sign-in method per user, `password_and_sso` or `sso_only`, set by an administrator.
- Local password sign-in with TOTP, recovery codes, and a forced MFA enrolment policy. Unknown users, wrong passwords and SSO-only accounts are handled identically in both response body and timing.
- Passkeys and security keys (WebAuthn, D18):
  - as a second factor beside TOTP: registration signed in or in a forced enrolment, completing an `mfa_required` sign-in, listing, renaming and removing keys, and `methods` on the `mfa_required` answer
  - passkey sign-in on its own: discoverable credentials only, user verification required, no email first, throttled by source address and by credential, `amr` `["hwk", "mfa"]`
  - a `passkey_only` sign-in method, the administrator's emailed registration link, and invitations accepted by registering a passkey
  - the administrator's reset of every second factor
  - optional trusted attestation roots, a per-user credential limit, a signature-counter clone check, and a configured relying party and allowed origins
- Invitations: single-use, expiring, hashed tokens carrying staged role grants, with resend and revoke, and password and SSO acceptance variants.
- Password reset by emailed link, change password, and refusal paths for SSO-only accounts.
- Password policies, watch lists and live feedback (D19):
  - policies chosen by pin, role priority or the default, with rules, passphrases, change-period tiers, history and a minimum age, managed at run time
  - the built-in common-password list, local watch lists (exact passwords, imports in HIBP's downloader format with a threshold, contained terms) and an optional Pwned Passwords range lookup
  - one enforcement path at every place a password is set and at password sign-in, with the forced change (`password_change_required`) after the second factor and an expiry warning on `signed_in`
  - live feedback for a signed-in change, an invitation, a reset link and the forced change: a policy description a browser evaluates, a check route, and a file of rule test cases
  - an optional sealed fingerprint, `warden passwords recheck` and `warden passwords import`, and an exposure report
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
- Product-registered event actions with severity and summary templates. Every action warden itself records lives under `warden.` (for example `warden.identity.sign_in`, `warden.audit.purge`); a product cannot register an action in that namespace.
- Actor, action, resource, outcome, source IP and structured details on every event, with the details size-capped.
- Trusted-proxy middleware for the real client IP: forwarded headers are believed only from configured proxy ranges, and the rightmost forwarded entry is used. Identity uses the same resolver for audit records and the sign-in throttle, so clients behind one proxy are throttled separately.
- Syslog forwarding:
  - RFC 5424 over UDP, TCP or TLS, with octet-counting or LF framing
  - control characters neutralised in every value
  - forwarding from committed rows: one elected forwarder per deployment tails the audit table from a stored cursor, so a rolled-back event is never sent, a slow or stopped collector never blocks a request, and rows committed during an outage are delivered when it ends (at-least-once, with the row id as MSGID)
  - TLS that fails closed, with no plaintext fallback
  - secrets read through konfig
  - status and test-send routes
- Filtering by time range, action, actor, resource and outcome, and export as CSV (with formula-injection escaping) or NDJSON. Exports are themselves audited.
- Retention: by default the trail is kept for ever; a product may set a period of at least 365 days and run the purge on its own schedule (warden ships no scheduler). Each purge writes a signed checkpoint.
- Tamper evidence: a per-row hash chain, plus a verification route and a `warden audit verify` CLI that report the first broken link.

**Shared**

- Ed25519 key management with rotation, and key publication: `keys_router` (from `warden.jwks`), which the product mounts at `http.keys_prefix`, serves RFC 7517 JWK Sets of RFC 8037 OKP keys, unauthenticated, read-only and publicly cacheable for five minutes, with no audit event per request. `<keys>/jwks.json` carries the keys that sign and verify live credentials (neither retired nor revoked); `<keys>/jwks-historical.json` adds retired keys, for verifying audit checkpoints. A revoked key is in neither, and no private member is ever published. Importing `warden.keys` does not load FastAPI.
- konfig-backed configuration with start-up validation.
- Cache invalidation across replicas for settings and session policy, over Postgres `LISTEN/NOTIFY` (no Redis dependency).
- A documented HTTP contract: the OpenAPI document [`docs/contract/openapi.json`](../contract/openapi.json), plus the client-behaviour guide [`docs/guide/clients.md`](../guide/clients.md).

### 3.2 Out of scope

- User interface components (D3).
- An OAuth 2.1 authorisation server for MCP clients (D7).
- SAML, SCIM, mapping identity-provider groups to roles, and more than one identity provider per deployment.
- Multi-tenancy (D4).
- Idle session timeout (a later setting).
- Product-specific resource scoping, entitlements and licensing.

## 4. Package layout

The layout as built for 0.1.0. The public API is what each package exports in `__all__` (pinned by `tests/test_public_api.py`), plus the HTTP contract ([`docs/contract/openapi.json`](../contract/openapi.json), pinned by `tests/test_openapi_contract.py`, with the client-behaviour guide [`docs/guide/clients.md`](../guide/clients.md)) and the database schema; every other name is internal. The compatibility modules the guide lists in section 14 are deprecated and kept until 1.0. `warden/__init__.py` exports only `__version__` and imports no subpackage, so `import warden.audit` never loads identity (D11).

```
src/warden/
  __init__.py          __version__ only; names the subpackages
  config.py            typed configuration, konfig binding, start-up validation    (public)
  keys.py              Ed25519 key store, rotation, published key lists             (public)
  jwks.py              key publication router: jwks.json, jwks-historical.json      (public)
  proxy.py             trusted-proxy middleware                                     (public)
  cli.py               warden migrate, keys rotate, audit verify, purge, anchor, grants
  db/                  pool adapter, schema names and lock keys, migrations         (public)
    schema.py          every table name, settings key and advisory lock key
    migrate.py         Alembic chain in schema "warden"
    migrations/        one chain, new files only
  audit/               recorder, registry, hash chain, query, export, retention     (public)
                       and checkpoints, anchors, verification, router
    syslog/            RFC 5424 forwarding over UDP, TCP or TLS, routes             (public)
  identity/            Identity, users, sign-in, sessions, roles, lifecycle, SSO    (public)
    service.py         Identity: the object a product constructs and mounts
    users.py           user model, statuses, sign-in methods, listing
    passwords.py       Argon2id, legacy PBKDF2 verify, rehash on sign-in
    password_enforcement.py  one path for every place a password is set, the
                       sign-in assessment, the forced change and live feedback
    password_policy/   policies and their store, rule engine, watch lists, history,
                       state, forced-change challenges, sealed fingerprints, range
                       client, recheck, and data/ (the built-in list and its README)
    totp.py, mfa.py    TOTP with step replay guard, recovery codes, challenges
    webauthn/          passkeys and security keys: registration and sign-in
                       ceremonies, single-use challenges, credential store,
                       attestation roots
    tokens.py          EdDSA access tokens, rotating refresh-token families
    policy.py          session policy and its run-time overrides
    roles.py           permission registry, role sets, assignments
    throttle.py        sign-in throttle per identifier and source address
    single_use.py      invitation and reset tokens (atomic consume)
    invitations.py     invitations, staged grants, acceptance by password or SSO
    reset.py           password reset by emailed link
    mail.py            sender protocol, templates
    apikeys.py         API keys
    prune.py           removal of rows that can never be used again
    dependencies.py    require_user, require_permission, resource hook
    sso/               discovery, JWKS, PKCE client, id_token validation,
                       matching and pinning, settings, label-only presets
    routers/           sign-in, WebAuthn, lifecycle, administration, password
                       policy administration and SSO routes
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
| WebAuthn: challenges | A WebAuthn challenge is single-use: the same response submitted concurrently registers or signs in once, a refused response uses its challenge up, and an expired, unknown, replayed or wrong-ceremony challenge is refused. |
| WebAuthn: origin | A response from an origin that is not an allowed origin exactly, or from a cross-origin frame, is refused. |
| WebAuthn: user verification | User verification is required for a passkey registration and sign-in and only preferred for a second factor; a passkey that did not verify the user, or is not discoverable, cannot sign in alone. |
| WebAuthn: uniform refusal | Every refused key or passkey sign-in is byte-identical to a wrong password's or code's refusal, with indistinguishable timing; the reason is audited only. |
| WebAuthn: no enumeration | Passkey sign-in options name no credential and are the same for every caller. |
| WebAuthn: status | Inactive and `sso_only` users get nothing at any step of a ceremony, including one that began before they were suspended. |
| WebAuthn: clone check | A signature counter that does not increase is refused and audited as a suspected clone; an authenticator without a counter keeps working. |
| WebAuthn: attestation | With trusted roots set, an attestation that does not chain to a root is refused; without roots any authenticator registers, recorded as unverified. |
| WebAuthn: limits | A user cannot exceed the credential limit, even by ceremonies begun before the limit was reached. |
| WebAuthn: last factor | The last second factor cannot be removed while one is required, even by two concurrent removals; the administrator's reset removes every factor and ends every session. |
| WebAuthn: single-use links | A passkey registration link or passkey invitation used twice at once registers one credential, and a used, expired or replaced link is refused. |
| WebAuthn: sign-in methods | A `passkey_only` user's password sign-in is byte-identical to a wrong password's, and a user holding keys cannot be switched to `sso_only`. |
| WebAuthn: no credential material | No public key, signature, client data, attestation or challenge reaches a log or an exception. |
| WebAuthn: no device access | Importing warden loads no `fido2` device code. |
| Password policies: no password material | No password, hash, digest, digest prefix, fingerprint or challenge reaches a log, an audit record or an exception; no column holds a password, its length or makeup; history holds Argon2id hashes only; the only other stored form is the optional sealed fingerprint. |
| Password policies: second factor first | A caller holding only the password gets `mfa_required` and learns nothing of the password's state; `password_change_required` comes only after the second factor, and the second factor's challenge cannot change the password. |
| Password policies: single use | A forced-change challenge is consumed by one guarded write, even under concurrent requests; a refused password costs it an attempt; a user suspended meanwhile gets nothing. |
| Password policies: history | History is checked only when a password is submitted, by a real Argon2id verification; the live check route never checks it. |
| Password policies: uniform refusal | A wrong password, a flagged user's wrong password and a dead reset or invitation link get the uniform refusal, with timing unchanged by the password's state. |
| Password policies: client agreement | Every case in `docs/contract/password-rule-vectors.json` agrees with the rule engine and with the check route, and the file is exactly what the engine generates. |
| Syslog review | No audit value can inject a second syslog frame under LF framing. |
| Single writer | No module other than the audit recorder inserts into the audit table. |
| Independence | `warden.audit` imports nothing from `warden.identity`. |

## 6. Delivery plan

| Milestone | Content | Exit criteria |
|---|---|---|
| M0 Groundwork | Package skeleton, CI (tests, type checking, lint, licence audit), konfig binding, `warden` Postgres schema and Alembic chain, key store. | `warden migrate` creates an empty schema; CI green. |
| M1 Audit core | Recorder, event registry, hash chain and verification, query and export routes, retention with checkpoints, trusted-proxy middleware. | Single-writer and independence tripwires green; chain verification detects an altered row. |
| M2 Syslog | Forwarder, transports, formatter with control-character neutralisation, status and test routes. | Live check against a real collector over UDP, TCP and TLS; a collector-outage run shows no change in request latency and delivers every committed row once the collector returns. |
| M3 Identity core | Users, passwords, TOTP, sessions and refresh families, permissions and roles, dependencies, public sign-in routes. | Acceptance tests #124, #125, #126, #130, #131, #132 and #133 green. |
| M4 Lifecycle | Invitations, password reset, mail protocol and templates, administration routes, API keys, pruning. | #127, #128, #129, #134 and #154 green. |
| M5 Single sign-on | OIDC client, discovery and JWKS caching, account matching, settings and test-configuration routes. | Live round trip against a stub identity provider, including break-glass sign-in with the provider stopped. |
| M6a WebAuthn | Passkeys and security keys (D18): core ceremonies and store, a second factor and the administrator's reset, passkey sign-in, `passkey_only`, the registration link and passkey invitations, then the guide, the sample console's screens and live checks against real authenticator behaviour. | The WebAuthn acceptance tests in section 5 green; the guide's routes tied to the contract. |
| M6b Password policies | Policy core and schema (D19), enforcement at every set point and at sign-in with the forced change and live feedback, administration routes, the exposure report and the `warden passwords` commands, then this design record, the client guide's section 18 and the sample console's screens. | The password policy acceptance tests in section 5 green; the guide's routes tied to the contract; a live check of the range API against the real service. |
| M6 Contract and release | OpenAPI contract ([`docs/contract/openapi.json`](../contract/openapi.json), exported by `scripts/export_openapi.py`), client-behaviour guide ([`docs/guide/clients.md`](../guide/clients.md)), examples, `0.1.0` release candidate. | A consuming product integrates on a feature branch; contract reviewed. |

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

1. Licence choice pending legal confirmation (D8).

### Resolved

| Item | Resolution |
|---|---|
| IANA Private Enterprise Number (D12) | Registered: 67382. The default SD-ID is `warden@67382`. |
| Audit retention default and minimum | No default period: the trail is kept for ever unless the product sets `audit.retention_days`, which must be at least 365. |
| Anchoring checkpoints outside the database | In 0.1.0: signed head attestation rows, a `warden audit anchor` command, and verification against anchors exported from a SIEM (D13). |
| Syslog mutual TLS | Deferred past 0.1.0. TLS to the collector verifies the server and fails closed; client certificates are a later release. |
| Audit action names | Every action warden registers lives under `warden.`; the registry refuses a product action there. |
| Refused sign-in identifier | A refused sign-in records the typed identifier only when it is shaped like an email address, so a password typed into the wrong field is never recorded. |
| Licence policy for dependencies | No strong copyleft (GPL, AGPL, SSPL, EUPL, OSL) in runtime dependencies. Weak copyleft (LGPL, MPL) only as a named, reviewed exception for an unmodified, separately installed package: psycopg (LGPL-3.0), certifi (MPL-2.0) and fido2 (its own licence is BSD-2-Clause, but it bundles the Mozilla public suffix list, MPL-2.0, which the relying-party checks read). Enforced by `scripts/licence_audit.py`. |
| WebAuthn dependency | `fido2` (Yubico), for WebAuthn data types, COSE keys, public suffix rules and attestation verifiers only; a tripwire checks that importing warden loads no `fido2` device code. Agreed 6 November 2026. |
| Built-in common-password list licence (D19) | A named data exception in `scripts/licence_audit.py`, not a dependency: `src/warden/identity/password_policy/data/common-passwords.sha1.gz` holds SHA-1 digests of SecLists' `xato-net-10-million-passwords-100000.txt` (MIT licence), with a README beside it recording the source commit, checksums, how to rebuild it and the licence text. The audit fails if the file or its README is missing or the licence is not permissive. Agreed 10 November 2026 (Skuld question 33). |
| WebAuthn attestation metadata | Not fetched. Attestation is verified only against roots the product configures (D18). |

## References

- RFC 5424, The Syslog Protocol, section 6.3.2: <https://www.rfc-editor.org/rfc/rfc5424#section-6.3.2>
- RFC 5612, Enterprise Number for Documentation Use: <https://www.rfc-editor.org/rfc/rfc5612>
- RFC 6238, TOTP: Time-Based One-Time Password Algorithm, section 5.2: <https://www.rfc-editor.org/rfc/rfc6238#section-5.2>
- RFC 7636, Proof Key for Code Exchange: <https://www.rfc-editor.org/rfc/rfc7636>
- OpenID Connect Core 1.0: <https://openid.net/specs/openid-connect-core-1_0.html>
- Web Authentication: An API for accessing Public Key Credentials, Level 3 (W3C): <https://www.w3.org/TR/webauthn-3/>
- RFC 8176, Authentication Method Reference Values: <https://www.rfc-editor.org/rfc/rfc8176>
- IANA Private Enterprise Numbers: <https://pen.iana.org>
- OWASP Password Storage Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management, section 3.1.1.2, Password Verifiers: <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>
- Pwned Passwords API, range searches (k-anonymity): <https://haveibeenpwned.com/API/v3#PwnedPasswords>
- Pwned Passwords downloader: <https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader>
- SecLists, Daniel Miessler and contributors (MIT licence): <https://github.com/danielmiessler/SecLists>
- Unicode Standard Annex 15, Unicode Normalization Forms (NFC): <https://unicode.org/reports/tr15/>
