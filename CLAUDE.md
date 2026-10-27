# warden

# Project configuration
- Kvasir library: warden
- Issue tracker: github
- GitHub repository: Cognisn/warden
- Default branch: main
- Release branch style: release/v<version>
- Workstream branches: <kind>/<version>-<aspect>, cut from the release branch; the version never carries a `v` (for example `feat/0.1.0-sso`)
- Merge to main: squash, only when the maintainer instructs it
- Commit scopes: audit, identity, sso, syslog, keys, db, config, cli, docs, ci
- Shared modules: src/warden/__init__.py, src/warden/config.py, src/warden/db/, src/warden/keys.py, and the migration chain
- Worktree recipe: dev/worktree.json (Compose template dev/sandbox-compose.yml)

This file is the project-level working agreement for warden. It sits under the workstation's global working agreement on any Cognisn development workstation; where the two overlap, the global agreement governs process (branching, versioning, commit format, worktrees, ports, Kvasir protocols, tagging) and this file governs what is specific to warden. On a machine without the global agreement (for example a cloud session), the rules in "Minimum rules without the global agreement" still apply.

Project knowledge lives in the mwh-kvasir library `warden`; pass `library: "warden"` on every call. The active development plan, decisions, runbooks and per-workstream briefings are there.

## What warden is

warden is a reusable Python library that gives Cognisn products the same identity and audit foundation: users, sign-in, invitations, OIDC single sign-on, roles and permissions, API keys, and a tamper-evident audit trail with syslog forwarding, filtering, export and retention. Products install it and mount its FastAPI routers; it has no user interface of its own.

It is published publicly on PyPI as `cognisn-warden` (import name `warden`) under Apache-2.0.

`docs/design/overview.md` is the authoritative statement of design and scope. Read it at the start of any session that touches behaviour. Further design documents the code is built against live in `docs/design/` and are versioned with the code; all other project knowledge lives in the `warden` Kvasir library.

## This is a public repository

Everything committed here is world-readable, including history.

- Never commit client names, client data, hostnames, internal paths, deployment addresses, credentials, keys, or anything received under NDA.
- Never commit internal business, commercial or legal discussion. Record that in Kvasir.
- Test fixtures are synthetic. Example domains use `example.com`, `example.org` and `example.net`; example addresses use the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
- A security defect is never described in a commit message, public issue or issue title before it is fixed and released. Record it in Kvasir. See `SECURITY.md`.

## Relationship to other Cognisn products

- **Design references, not code sources.** The design draws on Termograph's identity, SSO and audit implementation and on its hardening findings. No code is copied from Termograph or any other product. If code elsewhere looks reusable, record the need as a Kvasir note and discuss it with the user.
- **Dependencies.** warden depends on `cognisn-konfig` for configuration, secrets and logging. It does not depend on any other Cognisn product.
- **Consumers.** VOR is the first consumer; Termograph adopts warden in its v0.8.0 release. A change that would break a consumer is a breaking change to warden's public API (see Versioning).
- **Out of scope by decision.** An OAuth 2.1 authorisation server for MCP clients belongs to each product or to spindl, which call warden to validate users and API keys. Do not build it here.

## Architecture decisions

The full list, with reasoning, is section 2 of `docs/design/overview.md`. These are standing decisions. Do not reopen them in a session; if a task cannot be completed within them, stop and say so.

- **Embedded toolkit.** warden is a library a product imports, never a service or container of its own. The product mounts warden's routers under prefixes it chooses.
- **No user interface.** Every capability is reached through the documented HTTP contract or the Python API.
- **Single organisation per deployment.** No tenant column, no tenant parameter.
- **Product-declared permissions.** warden never hardcodes a product's roles or permissions. A product registers its permissions and defines roles as named sets of them; resource-level scoping is a product hook.
- **Audit is independent of identity.** `warden.audit` imports nothing from `warden.identity`. Identity records through audit, never around it.
- **One database schema, one migration chain.** All tables live in the `warden` Postgres schema, versioned by warden's own Alembic chain in `warden.alembic_version`. Never write a migration that touches a table outside that schema. At runtime warden uses the connection pool the product passes in; it never opens its own.
- **Asymmetric signing.** Ed25519 keys from konfig's secrets store, identified by key id, sign session tokens and audit checkpoints. Never introduce a shared-secret (HMAC) signing path.
- **Argon2id passwords.** New hashes are Argon2id. Legacy PBKDF2 hashes are verified only so they can be rehashed on the next successful sign-in.
- **Configuration through konfig.** Application code never reads environment variables or files directly. Configuration is one typed object, validated at start-up, so a missing or inconsistent value fails at boot rather than at first use.

## Security rules

These are enforced in code and tests, not left to configuration or documentation.

- **One audit writer.** Only the audit recorder inserts into the audit table. A tripwire test fails on any second writer.
- **The audit trail is append-only.** The application's database role holds only `INSERT` and `SELECT` on audit rows. Rows are hash-chained; a retention purge writes a signed checkpoint and is itself audited. Nothing in warden edits or deletes an audit row except the retention purge.
- **Uniform refusals.** Sign-in, refresh, token and key failures return byte-identical responses with indistinguishable timing. The specific reason goes to the audit trail, never to the caller.
- **Single-use means single-use under concurrency.** Every single-use credential (TOTP step, recovery code, invitation, reset token, refresh token) is consumed by one guarded, atomic write. A check followed by a separate write is a defect.
- **Inactive users get nothing.** Every path that issues or honours a credential checks the user's current status.
- **Anchored patterns use `fullmatch`.** Python's `$` matches before a trailing newline; never rely on it for validation.
- **No secrets or personal data in logs or exceptions.** Log identifiers, never passwords, tokens, keys, codes, email bodies or audit details.
- **Syslog values are neutralised.** Every value reaching a syslog frame has control characters replaced, whatever the framing. TLS fails closed; there is no plaintext fallback and no verification bypass.
- **Exports are escaped.** CSV exports escape formula-leading characters.
- **No third-party request on a user's behalf** beyond the configured identity provider, mail sender and syslog collector.

## Development conventions

- Australian English in code comments, documentation, error messages and commit messages. Cyber Security is written as two words with capitals in prose.
- No AI attribution anywhere: no `Co-Authored-By` trailers, no "generated with" footers, no session links in commits, code or documents.
- Branching follows the global agreement. `main` holds only the current released version. All work for a release happens on `release/v<version>`, through workstream branches `<kind>/<version>-<aspect>` cut from it and merged back by the integration session. Pre-release suffixes (`0.1.0a1`, `0.1.0b1`, `0.1.0rc1`) appear only on release branches. A release reaches `main` as a squash merge, only when the maintainer instructs it.
- Conventional Commits: `type(scope): lower-case imperative summary`, with the scopes in the project configuration above. A release stamp commit takes no scope: `chore: stamp 0.1.0a4`.
- Keep a Changelog: update `CHANGELOG.md` under `[Unreleased]` in the same commit as the change.
- Versioning follows Semantic Versioning. Before 1.0 a minor version may break the public API, but every break is named in the changelog with an upgrade note.
- The public API is whatever is importable from `warden` without a leading underscore, plus the HTTP contract and the database schema. Anything else is internal.
- Python 3.12 or later (`requires-python = ">=3.12"`). Do not add compatibility code for older versions.
- Type hints on every function; `mypy --strict` passes on `src/`.
- A new runtime dependency needs the user's agreement in the session and a licence check (`scripts/licence_audit.py`). No copyleft licences in runtime dependencies.

## Migrations across parallel workstreams

- A workstream (arc) adds new migration files only, for its own tables. It never edits an existing migration and never relies on a revision number.
- Two workstreams adding a migration from the same head produce two heads. The integration session alone re-chains (`down_revision`) at merge, to a single head.
- Every migration is reversible, and its downgrade is tested.

## Integration procedure

The integration session works in the main clone on the release branch and merges workstreams one at a time:

1. Check the workstream tip's CI conclusion (`gh run list --branch <branch> --limit 1`). Never merge or fast-forward a red tip.
2. Merge with a merge commit (`git merge --no-ff`).
3. Re-chain migrations; confirm a single head (`python -c "from warden.db import heads; print(heads())"`) and that `warden migrate` from empty reaches it.
4. Run the full suite and every tripwire, then the checks (ruff, `mypy --strict`, licence audit), each as its own command.
5. Stamp with the version script (`python scripts/bump_version.py 0.1.0aN`), update `CHANGELOG.md`, re-run the editable install, and re-run the suite. Commit as plain `chore: stamp 0.1.0aN`, as a separate step from the tests.
6. Push the release branch and confirm CI on the pushed commit.

## Testing

- Write the failing test first. The acceptance tests in section 5 of the design overview are written before the code that satisfies them.
- Unit tests never call a live identity provider, mail service or syslog collector. Use stubs, recorded fixtures or containers; anything needing a live service is marked `integration` (skipped by default).
- Database tests run against a real Postgres (testcontainers), never a mock, because the concurrency guarantees are properties of the database.
- Concurrency claims are proven with genuinely concurrent requests (barriers, parallel tasks), not by reading the code.
- Every guard and tripwire test is mutation-checked: show that it fails when the property it protects is removed, and record the check in the session summary. A guard that cannot fail is not a guard.
- Never weaken an assertion to make a test pass. Re-point it only when the behaviour has legitimately changed, and say so in the commit message.

## Worktrees and the sandbox

`dev/worktree.json` is warden's worktree recipe for the workstation's shared worktree setup script, and `dev/sandbox-compose.yml` is its Compose template. Each worktree's ports come from its slot plus the recipe's offsets: `postgres`, `syslog` (UDP and TCP), `syslog_tls`, and `stub_idp` (reserved; no stub identity provider exists yet). Every port binds to `127.0.0.1`.

- The test suites use testcontainers, not the sandbox. Testcontainers runs count against the workstation's heavy-workload cap; run a session's database suites one at a time.
- The sandbox Postgres is for manual checks only.
- The live syslog check (`tests/syslogfwd/test_syslog_live.py`, marked `integration`) runs against the sandbox's `syslog` service. Write the certificates with `python tests/syslogfwd/live/make_certs.py <sandbox>/certs`, start the stack with `--profile syslog` added to the sandbox's start command, and set `WARDEN_IT_SANDBOX`, `WARDEN_IT_SYSLOG_PORT` and `WARDEN_IT_SYSLOG_TLS_PORT` from the sandbox's ports. That check also starts a testcontainers Postgres.

## Parallel sessions

When a session is running in a git worktree (`git rev-parse --git-common-dir` resolves outside the working tree), assume other sessions are active concurrently and apply these rules:

- Work only inside your own worktree, on your own branch. Never touch the main clone or another worktree.
- The Kvasir library is always `warden`, never the worktree directory name, and every document submitted from a worktree session carries that branch's `branch-` tag.
- Worktree sessions never bump the version and never create release stamp commits.
- The shared modules in the project configuration are edited only by the session assigned them in its kick-off prompt. Any other session that needs a change there records the need and stops.

## Minimum rules without the global agreement

If the global working agreement is not present on this machine, these still apply:

- Australian English; no AI attribution in commits, changelogs or release notes.
- The release-branch workflow above.
- Do not push, tag, publish to PyPI or open a pull request unless the user instructs it in the session.
- Use the `warden` Kvasir library for project knowledge, pass `library: "warden"` on every call, and submit a `type-session` summary at the end of every session with the mandatory `project-`, `type-`, `status-` and `source-` tags.

## Session start checklist

1. Follow the global session start protocol (Kvasir library check, context retrieval, summary to the user).
2. Read this file, `README.md`, `docs/design/overview.md`, and the `[Unreleased]` section of `CHANGELOG.md`.
3. Confirm the task fits the architecture decisions and security rules above. If it does not, say so before writing code.
4. In worktree mode, confirm which shared modules, if any, the kick-off prompt assigns to this session.
