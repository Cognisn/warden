# warden: client-behaviour guide

What a product's client (its web console, mobile app or command-line tool) must do to work with warden's routes. The routes themselves, with every request body, response body and status, are in the HTTP contract, [`docs/contract/openapi.json`](../contract/openapi.json). This guide explains how to use them together.

Paths here use the default mount prefixes: `/auth`, `/admin`, `/audit` and `/keys` (`http.auth_prefix`, `http.admin_prefix`, `http.audit_prefix` and `http.keys_prefix`). A product may mount warden's routers elsewhere; substitute its prefixes. Durations given as defaults are the configuration's defaults; the product may change them. Every route named here is an operation in the contract, listed under the same method and path.

## 1. Mounting the routers

The product builds warden's objects and mounts each router under the prefix it configured. The reference app that produces the contract, `scripts/export_openapi.py`, does exactly this:

```python
identity = Identity(config, db, keys, permissions, secrets=secrets, mail_sender=sender)
identity.install(app)  # so require_user and require_permission find it
http = config.http
app.include_router(identity.auth_router(), prefix=http.auth_prefix)
app.include_router(identity.lifecycle_router(), prefix=http.auth_prefix)
app.include_router(identity.sso_router(), prefix=http.auth_prefix)
app.include_router(identity.admin_router(permission="example.administer"), prefix=http.admin_prefix)
app.include_router(identity.sso_settings_router(authorise=authorise), prefix=http.admin_prefix)
app.include_router(
    audit_router(recorder=recorder, keys=keys, authorise=authorise), prefix=http.audit_prefix
)
app.include_router(
    syslog_router(forwarder, authorise=authorise, recorder=recorder), prefix=http.audit_prefix
)
app.include_router(keys_router(keys=keys), prefix=http.keys_prefix)
```

`audit_router` comes from `warden.audit.router`, `syslog_router` from `warden.audit.syslog` and `keys_router` from `warden.jwks`; none is exported from a package root, so importing `warden.audit` or `warden.keys` never loads FastAPI. The administration router's permission is one the product registered (warden hardcodes none); `roles=`, `invitations=` and `api_keys=` may name a different permission for each area. The `authorise` dependency of the audit, syslog and single sign-on administration routers is the product's: it refuses the caller by raising (its own 401 or 403) and otherwise returns the actor id recorded in the audit trail, for example a `require_permission(...)` the product chose.

## 2. Sign-in

[`POST /auth/sign-in`](../contract/openapi.json) takes `{"email", "password"}` and answers 200 with one of four `status` values:

| `status` | Meaning | Next step |
|---|---|---|
| `signed_in` | A session: `access_token`, `token_type` (`Bearer`), `expires_in`, `refresh_token`, `refresh_expires_in`. | Use the access token (section 3). Within the password's expiry warning window it also carries `password_expires_in_days`. |
| `mfa_required` | The password was right and the user has a second factor. The body carries a `challenge`, its `expires_in` and `methods`, the kinds the user holds (`"totp"`, `"webauthn"`). | For `totp`, ask for a code and send it to [`POST /auth/totp/verify`](../contract/openapi.json) as `{"challenge", "code"}`, or a recovery code to [`POST /auth/recovery-code`](../contract/openapi.json). For `webauthn`, complete it with a key (section 16.2). |
| `password_change_required` | The password (and any second factor) was right, but the password must change before a session is issued. The body carries a `challenge`, its `expires_in` and a `reason`. | Complete the change at [`POST /auth/password-change`](../contract/openapi.json) (section 18.6). Wherever a session would be issued, this answer can take its place. |
| `mfa_enrolment_required` | The password was right, the deployment requires a second factor (`identity.require_mfa`, on by default) and the user has none confirmed. The body carries a `challenge`. | Enrol under the challenge (section 5); confirming the enrolment signs the user in. |

Every other outcome (an unknown address, a wrong password, an `sso_only` user, a user who is not `active`, a throttled attempt) is the uniform refusal (section 4). Do not tell the user which; you cannot know.

A challenge is single-purpose and short-lived: it expires after `identity.mfa_challenge_ttl_seconds` (300 seconds by default) and is used up by the step it was issued for. After `identity.mfa_max_failures` wrong codes (5 by default) it stops working, so the user must sign in again. A TOTP code is six ASCII digits; any other text (including other scripts' digits) is refused like a wrong code. A code is accepted at most once per 30-second step, so a user who submits the same code twice gets the refusal the second time.

Every route that issues a session answers with the same `signed_in` body: password sign-in, TOTP verification, a recovery code, a security key (section 16.2), a passkey (section 16.3), refresh, confirming an enrolment under a challenge, and the single sign-on handoff. A client can handle them with one function. A password sign-in, TOTP verification, a recovery code, a security key as a second factor and confirming an enrolment can answer `password_change_required` instead of `signed_in` (section 18.6), and a password sign-in's `signed_in` can carry `password_expires_in_days` (section 18.6).

## 3. Access and refresh tokens

**Access tokens.** Send the access token as `Authorization: Bearer <access_token>`. It is an EdDSA-signed token with a short life (`expires_in`, 15 minutes by default). Treat it as opaque: warden checks the signature, that its session is still live and that its user is still `active` on every request, so a token stops working at once when its session ends or its user is suspended, whatever its expiry says. Components outside the product's process can verify its signature with the published keys (section 10), but only warden knows whether the session is live.

**Refresh tokens.** Before the access token expires, or when a request is refused, exchange the refresh token at [`POST /auth/refresh`](../contract/openapi.json) (`{"refresh_token"}`). The answer is a new pair: a new access token and a new refresh token. Refresh tokens rotate:

- each refresh token works once; always replace the stored one with the new one in the answer;
- presenting a refresh token that has already been used is treated as theft: the whole session (every token descended from the same sign-in) ends, and the reason is audited as `warden.identity.session.reuse_detected`;
- the one exception is the immediate predecessor of the newest token, presented within `identity.refresh_reuse_grace_seconds` (10 seconds by default) of being used. It is refused, but the session is left alone. This covers a client that sent the same refresh twice (two tabs, a retried request) and lost the first answer.

So a client must **serialise its refreshes**: one refresh in flight at a time, shared by every request that needs it, with the stored refresh token replaced before the next one starts. If two refreshes do race, exactly one succeeds; the other gets the refusal, and the session survives if the loser presented its token within the grace window. Use the winner's tokens.

A session has an absolute lifespan (`identity.session_lifespan_seconds`, 12 hours by default) counted from sign-in: refreshing does not extend it. When a refresh is refused, the session is over; send the user to sign in again.

**Where to keep them.** warden returns tokens in response bodies only and sets no session cookie, so the product decides where its client keeps them. Advice (not enforced by warden): keep the access token in memory; keep the refresh token where scripts from other origins cannot read it; never put either in a URL, a log or local storage shared with other applications. Every token response carries `Cache-Control: no-store`.

**Signing out.** [`POST /auth/sign-out`](../contract/openapi.json) with the access token as the bearer ends the session (204); discard both tokens. It needs an access token, not an API key.

**Changing the password.** [`POST /auth/password`](../contract/openapi.json), with the access token as the bearer, takes `{"current_password", "new_password"}`. It answers 204 and ends the user's other sessions; the current one stays. A wrong current password, or a user with no password (`sso_only`), gets 400 `password change refused`; a new password the user's password policy refuses gets a 400 naming every failure (section 18.5).

## 4. The uniform refusal

Every authentication failure on every identity route, and on any product route guarded by `require_user` or `require_permission`, answers with exactly the same response:

```
HTTP/1.1 401 Unauthorized
content-type: application/json
www-authenticate: Bearer
cache-control: no-store

{"detail":"authentication failed"}
```

The bytes, headers and status are identical whatever went wrong (a wrong password, an unknown user, an expired or reused token, a used invitation link, a revoked API key, a throttled attempt), and sign-in takes the same time for an unknown user, a wrong password and an `sso_only` user. This is deliberate: a response that differed by reason would tell an attacker which email addresses have accounts, which tokens were once valid, and which guesses came close. The specific reason is recorded in the audit trail only, where an administrator can see it.

So a client must not try to tell refusals apart. On a refusal of an access token, refresh once (section 3); if the refresh is refused too, sign in again. A signed-in user without the permission a route requires gets 403 `{"detail":"forbidden"}` instead, which does mean "signed in, not allowed": do not sign the user out for it.

Request bodies are parsed by warden, not by FastAPI's validation, so a malformed body is treated as a refusal (or a fixed 400 message) and never answered with a 422 that echoes what was sent. The contract lists 422 only where FastAPI validates query or path parameters itself (the audit routes) or adds it to a route with a parameter; identity's routes answer with their own fixed messages.

## 5. TOTP enrolment, verification and recovery codes

**Enrolling.** [`POST /auth/totp/enrolment`](../contract/openapi.json) begins an enrolment. A signed-in user sends their access token as the bearer and no body; a user in a forced enrolment sends `{"challenge"}` from the `mfa_enrolment_required` answer instead. The answer is `{"secret", "uri"}`: show the `otpauth://` URI as a QR code, with the base32 `secret` for manual entry. A user who already has a confirmed enrolment gets 409.

**Confirming.** [`POST /auth/totp/enrolment/confirm`](../contract/openapi.json) takes `{"code"}` (and `"challenge"` in a forced enrolment). An enrolment counts as a second factor only once confirmed. The answer carries `recovery_codes`; under a challenge it is also the `signed_in` session body. A wrong code is a 400 (`code not accepted`) for a signed-in user, so the client does not mistake it for losing the session; under a challenge it is the uniform refusal. After confirming, warden mails the user a notice that a second factor was enrolled, if the product supplied a mail sender.

**Recovery codes.** Show the codes once, at confirmation; warden keeps only their hashes and cannot show them again. There are `identity.recovery_code_count` of them (10 by default), each `xxxxx-xxxxx`. Each works once, at [`POST /auth/recovery-code`](../contract/openapi.json) with the `mfa_required` challenge, in place of a TOTP code; it may be typed in either case, with or without the hyphen. Two concurrent requests with the same code cannot both succeed.

**Replacing codes.** A user cannot yet replace their own recovery codes, or remove their own enrolment: beginning an enrolment answers 409 while one is confirmed. Self-service regeneration of recovery codes is planned for 0.2.0. Until then, a user who has used up or lost their codes keeps signing in with their authenticator.

**Lost both factors: the administrator's reset.** A user who has lost their authenticator and their recovery codes cannot complete a password sign-in, so an administrator resets their enrolment with [`DELETE /admin/users/{user_id}/totp`](../contract/openapi.json), behind the administration router's users permission. It answers 204 with no body, or 404 for no such user. In one transaction it removes the user's TOTP enrolment (confirmed or not) and every recovery code, ends every session of the user (as a password reset does), and records `warden.identity.mfa.reset` with the administrator as actor. The user's next password sign-in answers `mfa_enrolment_required` where the deployment requires a second factor (or `signed_in` where it does not), and they enrol again as above; their old codes are refused. A user with nothing enrolled gets a 204 too, still audited, so pressing the button twice is harmless. Confirm the user's identity some other way before resetting: the reset is what stands between a stolen password and the account. A product's server can call `Identity.reset_totp(user_id, actor=...)` directly.

**Security keys and passkeys.** A security key or passkey (WebAuthn) is a second factor beside TOTP, and `mfa_required` lists the kinds a user holds in `methods`. A passkey can also sign a user in alone. Section 16 covers both, with their routes.

## 6. Single sign-on

Single sign-on is OIDC with one identity provider per deployment, for users an administrator has already created or invited (warden never creates an account from a sign-in). The flow is browser-based and needs three things from the product: a link or button that starts it, a completion screen at `http.sso_completion_link`, and HTTPS (the login cookie is `Secure`).

1. **Start.** Navigate the browser (a top-level navigation, not a fetch) to [`GET /auth/sso/start`](../contract/openapi.json). warden stores a login transaction (PKCE S256, state and nonce), sets the login binding cookie and redirects (302) to the provider.
2. **The cookie.** `__Secure-warden-sso`: HttpOnly, Secure, SameSite=Lax, path `/auth/sso` (the auth prefix plus `/sso`), lasting `sso.login_transaction_ttl_seconds` (10 minutes by default). It binds the login to this browser. The client never reads it; the browser sends it to the callback and the handoff.
3. **Callback.** The provider redirects back to [`GET /auth/sso/callback`](../contract/openapi.json), the redirect URI to register with the provider: `http.public_base_url` + `http.auth_prefix` + `/sso/callback` (the single sign-on settings show it as `callback_url`). warden checks the cookie, redeems the code, validates the id_token and matches the user, then redirects (302) to the completion link with one parameter: `?code=<handoff code>`.
4. **Completion screen.** The product's page at `http.sso_completion_link` reads `code` from its URL and posts `{"code"}` to [`POST /auth/sso/handoff`](../contract/openapi.json) from the same browser, so the cookie goes with it (a same-origin `fetch` with `credentials: "same-origin"` or `"include"`). The answer is the `signed_in` body, exactly as from password sign-in, and clears the cookie. The handoff code works once and expires after `sso.handoff_code_ttl_seconds` (60 seconds by default), so post it at once. Advice: remove the code from the address bar (`history.replaceState`) once read.
5. **Failure.** Every failure in the browser leg (single sign-on disabled, a provider error, a forged or expired state, an unverified or disallowed email, no matching user, a user who is not `active`) lands on the completion link with `?error=sso_failed` and nothing else, and clears the cookie. Show the fixed message `SSO_FAILURE_MESSAGE` (`warden.identity.SSO_FAILURE_MESSAGE`); the reason is in the audit trail as `warden.identity.sso.sign_in`. If no completion link is configured, the failure is a 400 with that message as plain text. A refused handoff is the uniform refusal.

No token, verifier or secret ever appears in a URL warden sends, and its redirects carry `Referrer-Policy: no-referrer`.

The first single sign-on of a user matches a verified email (`email_verified` must be true), ignoring case, and pins the provider's subject to the user; later sign-ins match by subject. An administrator can remove a pin with [`DELETE /admin/sso/users/{user_id}/pin`](../contract/openapi.json), so the next sign-in matches by email again. Single sign-on never asks for a second factor; `identity.require_mfa` applies to password sign-in only. Password sign-in keeps working while the provider is down, for users whose method is `password_and_sso` (the break-glass path).

**Administration.** The settings routes, under the product's `authorise` dependency: [`GET /admin/sso/settings`](../contract/openapi.json), [`PUT /admin/sso/settings`](../contract/openapi.json) (only the fields given change; turning `enabled` off ends every session issued through single sign-on), [`POST /admin/sso/settings/reset`](../contract/openapi.json), [`PUT /admin/sso/client-secret`](../contract/openapi.json) (stored in konfig's secrets store, never returned) and [`POST /admin/sso/test`](../contract/openapi.json) (checks the configuration without signing anyone in).

## 7. Invitations and password reset links

warden mails links built from the product's templates, `http.accept_invitation_link` and `http.reset_password_link`, each with `{token}` where the token goes (for example `https://app.example.com/accept-invitation?t={token}`). The product's screen at that address reads the token from its URL and posts it. Advice: remove the token from the address bar once read, and serve those screens with `Referrer-Policy: no-referrer`.

**Inviting.** An administrator invites with [`POST /admin/invitations`](../contract/openapi.json) (`email`, optional `display_name`, `sign_in_method` and staged `roles`), lists with [`GET /admin/invitations`](../contract/openapi.json), resends with [`POST /admin/invitations/{user_id}/resend`](../contract/openapi.json) (a new link; the old one stops working) and revokes with [`DELETE /admin/invitations/{user_id}`](../contract/openapi.json). An invitation link lasts `identity.invitation_ttl_seconds` (7 days by default).

**Accepting with a password.** [`POST /auth/invitations/accept`](../contract/openapi.json) takes `{"token", "password"}`. Success (200 `{"status": "accepted", "email"}`) activates the user and applies the staged roles, but does not sign them in: send them to sign-in next. A password the user's policy refuses (400, with every failure named, section 18.5) leaves the link usable, so let the user try again. An invitation whose method is `sso_only` answers 409 and leaves the link usable: accept it through single sign-on instead. A used, expired or revoked link is the uniform refusal.

**Accepting through single sign-on.** The accept-invitation screen submits the token to [`POST /auth/sso/start`](../contract/openapi.json) in the field `invitation`, as a top-level form submission (`application/x-www-form-urlencoded`) or a JSON body, so the token stays out of every URL. warden answers 303 to the provider; from there the flow is section 6. The provider's verified email must be the invited address (ignoring case); the callback then accepts the invitation and the completion screen's handoff signs the new user in. A mismatched identity leaves the invitation usable and lands on `?error=sso_failed`.

**Password reset.** [`POST /auth/password-reset`](../contract/openapi.json) (`{"email"}`) always answers 202 `{"status": "requested"}` before doing any work, whether or not the address has an account, so neither the answer nor its timing says. Show the same message whatever the address ("if an account exists, a link is on its way"). A link is mailed only to an `active` user whose method is `password_and_sso`, and earlier links stop working. It lasts `identity.reset_ttl_seconds` (1 hour by default). [`POST /auth/password-reset/complete`](../contract/openapi.json) takes `{"token", "new_password"}`, answers 204 and ends every session of the user. A password the user's policy refuses (400, section 18.5) leaves the link usable; a bad, used or expired link is the uniform refusal, and it is refused before the password is looked at. An administrator can also send a link with [`POST /admin/users/{user_id}/password-reset`](../contract/openapi.json), which reports whether it was sent.

Each link works once, even under concurrent submits.

## 8. API keys

An administrator creates a key with [`POST /admin/api-keys`](../contract/openapi.json) (`user_id`, `name`, `scopes`, optional `expires_at`), lists keys with [`GET /admin/api-keys`](../contract/openapi.json) and revokes one with [`DELETE /admin/api-keys/{key_id}`](../contract/openapi.json). The answer to creation carries the key itself (`key`, beginning with `identity.api_key_prefix`, `wdn_` by default) exactly once; warden keeps only a hash and a short `hint`. Show it once and tell the holder to store it.

A program uses the key as a bearer token: `Authorization: Bearer wdn_...`. `require_user` and `require_permission` accept it on the product's routes and on the administration routes. Its permissions are its `scopes` intersected with its user's current permissions, so a key never exceeds its user. It is refused (the uniform refusal) once it expires or is revoked, and while its user is not `active`. The session routes, sign-out and change password, need an access token and refuse a key.

## 9. The sign-in throttle

Password sign-in is throttled per pair of identifier (the email as typed, ignoring case) and client address: once a pair has made `identity.sign_in_attempt_limit` attempts (10 by default) within `identity.sign_in_window_seconds` (15 minutes by default), further attempts get the uniform refusal without the password being checked. Unknown addresses are throttled alike, so throttling reveals nothing. Only issuing a session clears the count; a right password followed by an MFA challenge does not. A throttled user sees the same refusal as a wrong password: advise them to wait, or to reset their password, rather than retrying. Passkey sign-in has its own throttle (section 16.3).

## 10. Published keys

[`GET /keys/jwks.json`](../contract/openapi.json) is an RFC 7517 JWK Set of the keys that sign live credentials; [`GET /keys/jwks-historical.json`](../contract/openapi.json) adds retired keys, for verifying audit checkpoints and anchors. Both are unauthenticated, `application/jwk-set+json`, and cacheable for five minutes (`Cache-Control: public, max-age=300`). A verifier that meets an unknown key id should fetch again. A revoked key is in neither set.

## 11. Audit: query, export and verification

The audit routes are guarded by the product's `authorise` dependency (optionally a stronger `authorise_export` and `authorise_verify`); their refusals are the product's.

- [`GET /audit/events`](../contract/openapi.json) lists matching events newest first, `limit` at a time (1 to 1000, default 100). The answer carries `next_before_id`; pass it as `before_id` for the next page, until it is null. Filters: `since` (inclusive) and `until` (exclusive), both on `occurred_at` with a zone offset; `action` (repeatable, any of); `actor`; `resource_type`; `resource_id`; `outcome` (`success` or `failure`). An invalid filter is a 422.
- [`GET /audit/export`](../contract/openapi.json) takes the same filters and `format=csv` or `format=ndjson`, and streams every match in chain order as an attachment. The export is itself recorded (`warden.audit.export`, with the filter, the actor and the client address) before the first line. CSV cells that begin with `=`, `+`, `-`, `@`, a tab or a carriage return are prefixed with `'`, so a spreadsheet does not run them as formulas.
- [`GET /audit/verify`](../contract/openapi.json) verifies the hash chain and every retention checkpoint from one snapshot. `ok` false means the trail was altered; `broken` names the first broken link by row id and reason (a `warden.audit.BreakReason`), never by contents. The `warden audit verify` command does the same, and with `--anchors` also checks the chain against signed anchors exported from the SIEM.

The syslog routes, [`GET /audit/syslog/status`](../contract/openapi.json) and [`POST /audit/syslog/test`](../contract/openapi.json), show the forwarder's state and send a test message; errors are fixed categories, never the underlying error text.

For the product's server, not its client: an audit event recorded inside the product's own transaction (`conn=`) holds the audit chain lock until that transaction ends, serialising every other audit write behind it. Keep such transactions short.

## 12. Trusted proxies and the client address

warden records the client address on audit events and uses it for the sign-in throttle. Behind a reverse proxy the TCP peer is the proxy, so configure `audit.trusted_proxies` with the proxies' networks. `X-Forwarded-For` is believed only when the peer is one of them; entries are read from the right, skipping those added by further trusted proxies, and a malformed entry stops at the last known hop. `Forwarded` and `X-Real-IP` are never read. A forwarded header from a peer that is not a trusted proxy is ignored, so a client cannot choose its own address.

Identity's routes resolve the address themselves. The audit export reads the request's client address, so behind a proxy install `warden.proxy.TrustedProxyMiddleware(app, trusted_proxies=config.audit.trusted_proxies)` as well; resolving twice gives the same address.

## 13. Administration routes

The rest of the administration routes, each behind the permission the product named when it built the router, with the uniform refusal for a bad bearer and 403 for a missing permission:

- users: [`GET /admin/users`](../contract/openapi.json) (oldest first, ties by id, optionally one `status`; every user unless `limit` or `after` is given, in which case the body also carries `next`, the cursor to pass as `after` for the following page, null on the last), [`GET /admin/users/{user_id}`](../contract/openapi.json), [`POST /admin/users/{user_id}/status`](../contract/openapi.json) and [`POST /admin/users/{user_id}/sign-in-method`](../contract/openapi.json);
- roles: [`GET /admin/roles`](../contract/openapi.json), [`PUT /admin/users/{user_id}/roles/{role}`](../contract/openapi.json) (optionally until `expires_at`) and [`DELETE /admin/users/{user_id}/roles/{role}`](../contract/openapi.json).

The last active administrator cannot be suspended, deactivated or lose their administrator role (409), even under concurrent requests. Times are ISO 8601 with a zone offset. Error bodies are fixed `detail` messages, listed in the contract for each route; none echoes the request.

## 14. Compatibility modules (deprecated)

These import paths still work and will keep working through 0.x. They are deprecated, kept only for compatibility, and will be removed in 1.0 (a named breaking change, with an upgrade note). Import from `warden.db` instead. They raise no warning at run time.

| Deprecated | Import instead from `warden.db` |
|---|---|
| `warden.identity.schema` (identity's table names and `IDENTITY_TABLES`) | the same names |
| `warden.identity.sso.schema` (single sign-on's table names, `SSO_TABLES`, `SSO_SETTING`, `SSO_SETTINGS_LOCK_KEY`) | the same names |
| `warden.identity.apikeys.API_KEYS` | `API_KEYS` |
| `warden.identity.invitations.INVITATION_GRANTS` | `INVITATION_GRANTS` |
| `warden.identity.single_use.SINGLE_USE_TOKENS` | `SINGLE_USE_TOKENS` |

## 15. What the product builds itself in 0.1.0

Some capabilities are in warden's Python API or command line but have no warden route. A product that wants them on a screen writes its own routes over the Python API, guarded by `require_user` or by `require_permission` with a permission it registered. The sample console (`examples/console`, in `console_routes.py` and `bootstrap.py`) does each of these.

**Who am I.** warden has no route that tells a client who its bearer is. A product route that depends on `require_user` gets the uniform refusal for a bad bearer and otherwise a `Principal`: `user_id`, `session_id`, `email`, `roles`, `permissions`, `amr` (how the session was authenticated) and, for an API key, `api_key_id`. A who-am-I route under the auth prefix (`<auth>/me`) is planned for 0.2.0.

**The first administrator.** warden has no command that creates one. The product's own bootstrap command, run after `warden migrate` and `warden keys rotate`, creates the user with `Identity.users.create(email, actor=..., password=...)` and gives them an administrator role with `Identity.roles.assign(user_id, role, actor=...)`. The sample's `create-admin` command does this and is safe to run twice: it looks the user up with `Identity.users.get_by_email` and checks `Identity.roles.roles_of` first.

**The session policy.** The session policy (`access_token_ttl_seconds`, `refresh_token_ttl_seconds`, `session_lifespan_seconds`, `refresh_reuse_grace_seconds` and `require_mfa`) has no warden route. Read it with `Identity.policy.current()` (the configured values are `Identity.policy.defaults`), change fields with `Identity.policy.update(actor=..., **fields)` (an unknown field or a bad value raises `PolicyError`) and return to the configured values with `Identity.policy.reset(actor=...)`. Each change is audited as `warden.identity.policy.changed`. Other processes of the deployment pick it up through the listener `Identity.running()` starts, and in any case within `identity.policy_cache_seconds`.

**Audit anchors.** Anchoring is on the command line (`warden audit anchor`, and `warden audit verify --anchors FILE` to check) and in Python: `warden.audit.anchor(recorder, keys, actor=...)` appends a signed attestation of the chain head (returning None, and writing nothing, for an empty trail or, with `min_rows`, when fewer rows than that have been appended since the last anchor), and `verify_anchors(db, keys, read_anchors(lines))` checks the chain against anchors read back from the SIEM, as NDJSON or syslog lines. A product that wants an anchoring screen writes its routes over these.

**Syslog settings.** Syslog forwarding is configured from the `syslog` section of the configuration, read when the product starts. warden has no route that changes it and stores no change made at run time, so to reconfigure syslog for good, change the configuration and restart the product's processes. A product's server can switch a running `SyslogForwarder` with `reconfigure(settings)`, but that is not audited, reaches only the forwarder in that process, and is lost at the next start.

**Single sign-on behind a private CA.** warden's single sign-on client checks the provider's certificate against certifi's bundle and, in 0.1.0, has no setting for another CA; one is planned for 0.2.0. For a provider whose certificate chains to a private CA, set the `SSL_CERT_FILE` environment variable of the product's process to a PEM bundle. It replaces the whole trust store of the process's HTTPS clients rather than adding to it, so the bundle must hold every CA the process needs, public ones included (for example certifi's bundle with the private CA appended). Python's own default trust store reads the variable as well, and syslog over TLS uses that store when neither `syslog.tls_ca_file` nor `syslog.tls_ca_secret` is set, so give the collector its CA through one of those.

## 16. Security keys and passkeys (WebAuthn)

warden accepts WebAuthn credentials in two roles. A **security key or passkey as a second factor** completes a password sign-in, as a peer of TOTP. A **passkey on its own** signs a user in with no email and no password. The account is the same either way; the difference is how the credential was registered and how it is asked for. warden has no user interface: the product's front end drives the browser's WebAuthn API and passes the results to warden's routes.

### 16.1 The browser side

Every ceremony has the same shape. The client asks warden for options, hands them to the browser, and posts the browser's answer back.

- warden answers an options route with `{"public_key", "expires_at"}`. `public_key` is the JSON form of the WebAuthn options (camelCase names, binary values as base64url text), ready for the Level 3 JSON helpers. `expires_at` is when the challenge stops working (`webauthn.challenge_ttl_seconds`, 300 seconds by default).
- To register, call `navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(public_key)})`. To sign in, call `navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(public_key)})`.
- Post the result as the `credential` field, in the form `credential.toJSON()` gives. warden reads that JSON form only.
- A challenge is single-use. If the user cancels, the browser times out or warden refuses the answer, ask for fresh options; do not reuse the old ones.

```js
// Registration: options from warden, answer back to warden.
const { public_key } = await (await fetch(optionsUrl, request)).json();
const created = await navigator.credentials.create({
  publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(public_key),
});
await fetch(confirmUrl, post({ credential: created.toJSON(), nickname }));
```

Check for support with `window.PublicKeyCredential` before offering the feature. The three Level 3 helpers (`parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and `toJSON`) are newer than the rest of the API, so test for them too (`typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function"`). Where a browser has the API but not the helpers, do the conversion by hand:

- Before the call, decode from base64url to an `ArrayBuffer`: `challenge`, `user.id`, and the `id` of every entry in `excludeCredentials` or `allowCredentials`.
- After the call, build the JSON yourself with base64url (no padding) for every binary value: `id`, `rawId`, `type`, `authenticatorAttachment`, `clientExtensionResults` (from `getClientExtensionResults()`) and a `response` of `clientDataJSON` and `attestationObject` plus `transports` (from `response.getTransports()`) for registration, or `clientDataJSON`, `authenticatorData`, `signature` and `userHandle` for sign-in.

Where the browser has no WebAuthn at all, do not offer the feature, and keep every other sign-in method working. Do not show a different message for each failure: a browser error such as `NotAllowedError` means only that the ceremony did not finish.

### 16.2 A key as a second factor

**Registering, signed in.** [`POST /auth/webauthn/registration`](../contract/openapi.json), with the access token as the bearer and no body, answers with the options for `navigator.credentials.create()`. Post the answer, with an optional `nickname` (1 to 64 characters), to [`POST /auth/webauthn/registration/confirm`](../contract/openapi.json). The answer is `{"credential", "recovery_codes"}`. `recovery_codes` holds fresh codes, shown once, only when the key is the user's first second factor; otherwise the list is empty. Section 5's advice for recovery codes applies: show them at once, because warden cannot show them again.

**Registering, in a forced enrolment.** A user who was told `mfa_enrolment_required` may register a key instead of TOTP. Send `{"challenge"}` to the registration route and `{"challenge", "credential", "nickname"}` to the confirm route, with no bearer. Confirming signs the user in: the answer is the `signed_in` body (section 2) with `recovery_codes` and `credential` added, and `amr` `["pwd", "hwk"]`.

The registration asks for a resident key and user verification as preferences, not requirements, so a plain security key works. A credential that comes out discoverable and verified the user is recorded as such and may also sign in alone (section 16.3). A user who signs in only through single sign-on cannot register one (409).

**Completing a sign-in.** When [`POST /auth/sign-in`](../contract/openapi.json) answers `mfa_required`, read `methods`: `["totp"]`, `["webauthn"]` or both. Existing clients that ignore the field keep working, because the TOTP routes are unchanged. To use a key:

1. Post `{"challenge"}` to [`POST /auth/webauthn/verify/options`](../contract/openapi.json). The options list only that user's own credentials.
2. Call `navigator.credentials.get()` with them.
3. Post `{"challenge", "credential"}` to [`POST /auth/webauthn/verify`](../contract/openapi.json). The answer is the `signed_in` body with `amr` `["pwd", "hwk"]`.

A refused answer counts against the challenge as a wrong code does (`identity.mfa_max_failures`), and every refusal is the uniform refusal (section 4). A signature counter that fails to increase is refused and audited as a suspected cloned key.

**Managing keys.** [`GET /auth/webauthn/credentials`](../contract/openapi.json) lists the signed-in user's keys, oldest first: `id`, `nickname`, `created_at`, `last_used_at`, `aaguid`, `backup_eligible`, `backup_state`, `discoverable` and `passkey`. `passkey` is true exactly when the key is discoverable and was registered with user verification, the rule a passkey sign-in applies (section 16.3), so a client can label which keys sign in on their own without guessing; a discoverable key registered without user verification is listed with `passkey` false and cannot sign in alone. It never shows the public key. [`PATCH /auth/webauthn/credentials/{credential_id}`](../contract/openapi.json) renames one (`{"nickname"}`; null clears it) and [`DELETE /auth/webauthn/credentials/{credential_id}`](../contract/openapi.json) removes one. Removing a user's last second factor while the session policy requires one is a 409; where none is required, removing the last one also removes the recovery codes. An id that is not the user's own, or not a UUID, is a 404.

**Lost every factor.** [`DELETE /admin/users/{user_id}/mfa`](../contract/openapi.json) is the administrator's reset of every second factor: TOTP, recovery codes, keys and passkeys, and every session. It is 204 even for a user with nothing enrolled, and 404 for no such user. `DELETE /admin/users/{user_id}/totp` (section 5) resets TOTP only and leaves keys in place.

### 16.3 Signing in with a passkey

A passkey is a discoverable credential registered with user verification, so the authenticator itself holds the account and verifies the user (by PIN, biometric or device unlock). Signing in needs no email first.

1. Post nothing to [`POST /auth/passkey/options`](../contract/openapi.json). The options carry a fresh challenge, `userVerification: "required"` and no `allowCredentials`. They are the same for every caller and reveal nothing about any account.
2. Call `navigator.credentials.get()` with them.
3. Post `{"credential"}` to [`POST /auth/passkey/sign-in`](../contract/openapi.json). The answer is the `signed_in` body with `amr` `["hwk", "mfa"]`. That satisfies `identity.require_mfa`: there is no second step and no `mfa_required` challenge.

Offer it two ways, as a sign-in screen should:

- **Conditional mediation (autofill).** Give the email field `autocomplete="username webauthn"`. Where `await PublicKeyCredential.isConditionalMediationAvailable()` is true, fetch the options when the screen loads and call `navigator.credentials.get({publicKey, mediation: "conditional", signal})`. The browser then offers the user's passkeys in the field's autofill list, and the call settles when the user picks one. Pass an `AbortController` signal so the pending call is cancelled when the user starts a different sign-in.
- **A button.** For browsers without conditional mediation, a "Sign in with a passkey" button runs the same call without `mediation`, and the browser shows its own chooser. Fetch fresh options when the button is pressed; the challenge from page load may have expired.

Only a discoverable passkey that verified the user at registration can sign in alone. A security key held only as a second factor cannot, and neither can a credential of a user who is not `active` or whose method is `sso_only`. Every failure is the uniform refusal; do not try to say which.

Passkey sign-in is throttled by source address and, separately, by credential id, each at `identity.sign_in_attempt_limit` attempts per `identity.sign_in_window_seconds`. Clients behind one shared address, such as a corporate NAT, share the address budget, so a product serving them may raise the limit (and must configure `audit.trusted_proxies`, section 12, so the address is the client's and not the proxy's). A sign-in that issues a session clears both counts.

The options route, [`POST /auth/passkey/options`](../contract/openapi.json), is throttled by source address on a count of its own, at the same limit and window: once an address has used it up, the route gives the uniform refusal and no challenge until the window ends. Fetching options does not spend the sign-in counts, and failed sign-ins do not spend the options count. A passkey sign-in that issues a session clears the options count for its address too. Clients behind one shared address share this count as well, so fetch options when they are needed (once when a sign-in screen loads, and again when the button is pressed) rather than on a timer.

### 16.4 `passkey_only` users, registration links and invitations

An administrator sets a user's sign-in method with [`POST /admin/users/{user_id}/sign-in-method`](../contract/openapi.json). The method `passkey_only` means the user signs in with a passkey and nothing else. Password sign-in is refused exactly as a wrong password is (the uniform refusal), single sign-on is refused, and password reset and change of password are refused as for `sso_only`. The answer to setting `passkey_only` carries `has_passkey`; when it is false, the user cannot sign in until they register a passkey. Switching a user who holds keys to `sso_only` is a 409 until the administrator's reset removes them.

**The registration link.** [`POST /admin/users/{user_id}/passkey-registration`](../contract/openapi.json) mails the user a single-use link built from `http.passkey_registration_link` (with `{token}` where the token goes) and answers 202 with `expires_at`. The link lasts `identity.reset_ttl_seconds` (1 hour by default); sending again stops the earlier link working. There is no self-service request. It is refused (409) for a user who is not `active` or is `sso_only`, and answers 503 where no mail sender or link template is configured. For a user who has lost every passkey, reset first (`DELETE /admin/users/{user_id}/mfa`), then send the link.

The product's screen at that address reads the token from its URL (and removes it from the address bar, as section 7 advises), then:

1. posts `{"token"}` to [`POST /auth/passkey-registration/options`](../contract/openapi.json) and calls `navigator.credentials.create()` with the options;
2. posts `{"token", "credential", "nickname"}` to [`POST /auth/passkey-registration`](../contract/openapi.json).

The options ask for a resident key and user verification as requirements. The answer is `{"status", "credential", "recovery_codes"}`. It does not sign the user in: send them to passkey sign-in next. `recovery_codes` holds fresh codes, shown once, when the user held no second factor before. An answer that is not a passkey is a 400 and leaves the link usable, so let the user try again; a bad, used or expired link is the uniform refusal.

**Passkey invitations.** An invitation whose `sign_in_method` is `passkey_only` is accepted by registering a passkey, not by choosing a password. The accept-invitation screen posts `{"token"}` to [`POST /auth/invitations/accept/passkey/options`](../contract/openapi.json), calls `navigator.credentials.create()`, and posts `{"token", "credential", "nickname"}` to [`POST /auth/invitations/accept/passkey`](../contract/openapi.json). In one transaction warden registers the passkey, activates the user, applies the staged roles and uses the link up. The answer is `{"status": "accepted", "email", "credential", "recovery_codes"}` (the codes shown once) and, as with a password acceptance, does not sign the user in. A `passkey_only` invitation offered a password, or taken through single sign-on, is a 409 and stays usable; so is another invitation offered a passkey. Inviting `passkey_only` where WebAuthn is not configured is a 409.

### 16.5 Relying party, origins and what warden checks

A passkey is bound to a **relying party ID**, a domain. By default it is the host of `http.public_base_url`, and the only allowed **origin** is that URL's origin. Set `webauthn.rp_id` to share passkeys across subdomains (it must be each allowed origin's host or a registrable suffix of it, never a public suffix), and `webauthn.allowed_origins` for further origins, compared exactly with no wildcards; an origin must be `https`, except for `localhost`. A deployment whose base URL is an IP address needs `webauthn.rp_id`, or WebAuthn is unavailable and the key routes answer 409 `WebAuthn is not configured`. Changing the relying party ID after users have registered strands their passkeys, so choose it once.

Every response is checked for a challenge warden issued for this ceremony and user, still unexpired and unused; the client data type; an allowed origin and no cross-origin frame; the relying party ID hash; user presence, and user verification where required; and, for sign-in, a signature and the credential's backup eligibility.

**Attestation roots.** By default warden accepts any authenticator. Set `webauthn.attestation_roots` (PEM CA certificates, usually `secret://<name>`) to accept only authenticators whose attestation chains to one of them. For example, to allow only YubiKeys, put Yubico's published attestation root certificate (from Yubico's developer documentation) in that secret. The options then request direct attestation. warden never fetches attestation metadata, so a root must be one you chose to trust. With roots set, **synced passkeys are refused**: they give no attestation chain, as with "none" or self attestation. Set roots only for a deployment that mandates hardware keys.

**The credential limit.** A user may register at most `webauthn.max_credentials_per_user` credentials (10 by default). Registration past it is a 409 `the credential limit is reached`.

### 16.6 User verification and `amr`

User verification (the PIN, biometric or device unlock) is not a setting. As a **second factor** it is preferred: the password already proved the first factor, so a plain security key that only proves presence is accepted. For **passkey sign-in** it is required, at registration and at every sign-in, because the passkey alone is both factors.

The `amr` of a session, on the access token and the `Principal`, says which happened:

| Sign-in | `amr` |
|---|---|
| Password | `["pwd"]` |
| Password and TOTP | `["pwd", "otp"]` |
| Password and recovery code | `["pwd", "recovery_code"]` |
| Password and a key as a second factor | `["pwd", "hwk"]` |
| Passkey alone | `["hwk", "mfa"]` |

The values follow RFC 8176: `hwk` is proof of possession of a hardware-secured key and `mfa` is multiple factors.

### 16.7 Refusals

Every sign-in failure here is the uniform refusal (section 4): no key for the user, a wrong or reused challenge, a bad signature, an unknown credential, a user who is not `active`, a throttled attempt. The reason goes to the audit trail only, on `warden.identity.sign_in` (with method `passkey` for passkey sign-in) and the `warden.identity.mfa.webauthn.*` actions. A signed-in user's own registration is told what failed instead, with a fixed message that never echoes the request: 400 `credential not accepted` or `the nickname is not valid`, and 409 for WebAuthn not configured, the credential limit, or an `sso_only` user. These are 400 and 409, not 401, so a client does not mistake them for losing the session. No credential material (public key, signature, client data, attestation or challenge) is ever logged or audited.

## 17. Capabilities: what a deployment can do

Some features depend on how the product deployed warden: mail needs a `MailSender`, each emailed link needs its template, passkeys need a relying party, and single sign-on needs to be enabled. A client reads the capabilities to disable or hide those controls up front, and to say why, instead of finding out from a refusal after the click. Every value is a boolean; no address, provider, issuer, domain or other setting is ever returned.

**The sign-in screen.** [`GET /auth/capabilities`](../contract/openapi.json) is anonymous and answers every caller the same way (it reads no bearer and no account), with `Cache-Control: no-store`:

| Field | When true | What the screen does when false |
|---|---|---|
| `password_reset` | A reset link can be mailed: a mail sender and `http.reset_password_link`. | Hide "Forgot password". `POST /auth/password-reset` still answers 202 and sends nothing. |
| `single_sign_on` | Single sign-on is enabled, with an issuer and a client id. | Hide the single sign-on button: `GET /auth/sso/start` would land on `?error=sso_failed`. |
| `passkey_sign_in` | Passkeys work here: a relying party id is known. | Hide "Sign in with a passkey" and skip conditional mediation: `POST /auth/passkey/options` would be the uniform refusal. |

Each of these is something the screen reveals anyway by showing or hiding the control, so the route tells an anonymous caller nothing new.

**Administration.** [`GET /admin/capabilities`](../contract/openapi.json), behind the user administration permission, answers six booleans:

| Field | When true | Disable when false |
|---|---|---|
| `mail_sender` | The product installed a mail sender. | Everything that mails; say "mail is not configured". |
| `invitations` | A sender and `http.accept_invitation_link`. | Invite and resend (otherwise 503 `mail is not configured`). |
| `password_reset` | A sender and `http.reset_password_link`. | Send a password reset link (otherwise 503). |
| `passkey_registration_link` | WebAuthn, a sender and `http.passkey_registration_link`. | Send a passkey registration link (otherwise 503, or 409 without WebAuthn). |
| `single_sign_on` | Single sign-on is enabled, with an issuer and a client id. | Inviting `sso_only` users is still allowed; they cannot accept until it is enabled. |
| `webauthn` | Passkeys and security keys work. | Registering keys and inviting a `passkey_only` user (otherwise 409 `WebAuthn is not configured`); a `passkey_only` user cannot sign in. |

To explain a disabled passkey registration link: with `mail_sender` false, mail is not configured; with `webauthn` false, WebAuthn is not configured; otherwise the link setting `http.passkey_registration_link` is missing. In Python, `await Identity.capabilities()` returns the same six fields as `IdentityCapabilities`.

**When it changes.** Mail, the link templates and the relying party are start-up configuration: those fields are fixed while the process runs, so read them once per page load. `single_sign_on` follows the run-time setting an administrator changes with [`PUT /admin/sso/settings`](../contract/openapi.json), through the same cache sign-in uses, so it can lag a change by up to `identity.policy_cache_seconds` on another process.

**The routes stay the authority.** Each field is the condition the route behind it checks, but the capabilities are advice for the screen: a route still refuses as before (its 503, 409 or the uniform refusal), and a client handles that refusal even when the capability said yes.

## 18. Password policies, watch lists and live feedback

A password policy says what a new password must be, how long it may be kept, and which lists of passwords it must not be on. Every place a password is set (a user created with a password, an administrator's set, a signed-in change, a reset link, an invitation accepted with a password, and the forced change below) goes through the one policy that applies to the user, so a client sees the same refusals everywhere. This section is for two readers: the product's front end, which shows the policy while a user types and handles the forced change, and the operator, who chooses the settings and runs the watch lists and the recheck.

Policies apply only to users who hold a password (`password_and_sso`). Users who sign in with single sign-on or a passkey only (`sso_only`, `passkey_only`) and API keys are not under a policy, and a passkey or single sign-on sign-in is never blocked by the state of a password (section 18.6).

### 18.1 Which policy applies to a user

An effective policy is chosen in this order:

1. **A pin.** An administrator can pin one policy on one user with [`PUT /admin/users/{user_id}/password-policy`](../contract/openapi.json) and remove it with [`DELETE /admin/users/{user_id}/password-policy`](../contract/openapi.json). A pin overrides the role mapping.
2. **Role priority.** Each policy other than the default has a priority (1 is the highest) and can be mapped from roles with [`PUT /admin/password-policy-roles/{role}`](../contract/openapi.json) and [`DELETE /admin/password-policy-roles/{role}`](../contract/openapi.json). When a user holds several roles that map to policies, the highest-priority policy wins. Only a role the product declares can be mapped, and a role the product no longer declares grants nothing, so its mapping has no effect. A role cannot be mapped to the default.
3. **The default.** Exactly one policy is the default. It covers every user whose roles map to no policy, has no priority, and cannot be deleted.

[`GET /admin/users/{user_id}/password-policy`](../contract/openapi.json) answers why a policy applies: `source` is `pin`, `role` (with the `role` that chose it) or `default`, with the policy's name, the user's current `tier`, when the password was set and when it expires, and whether a change is required and why. [`GET /admin/users/{user_id}`](../contract/openapi.json) carries the same status as `password`. To tell a user which rules they are under, show the policy description (section 18.3) rather than the policy's name: the description is what the user must meet, and it is per user.

A deployment with no policy gets a default on first use, seeded to behave as 0.1.0b18 did: the minimum length is `identity.password_min_length` (12 by default), with no class rule, no expiry, no history, no minimum age, the built-in common-password list checked, and nothing else enabled. Once a default is stored, the stored value governs and changing `identity.password_min_length` no longer changes it.

### 18.2 What a policy contains

Policies are created and changed at run time (section 18.9), not in configuration. Each holds:

| Setting | Meaning |
|---|---|
| `min_length`, `max_length` | Length in Unicode code points after NFC normalisation. The minimum is at least 8 and the maximum at most 1,024. |
| `min_classes` | How many character classes are needed, from 0 to 5: lowercase, uppercase, digit, other letters (such as Han or Arabic letters) and symbol (punctuation, symbols and the space separator). Classes follow Unicode general categories. |
| `max_repeat` | The longest run of one repeated character, or null for any. |
| `forbid_user_details` | Refuse a password that contains the user's email local part (the whole of it, and each run of letters and digits in it) or a word of their display name. Pieces shorter than three code points are ignored, and comparison ignores case. |
| `passphrase` | A password at least `min_length` code points long with at least `min_words` words (words are split on space, hyphen-minus, full stop and underscore) is a passphrase. With `relaxes_classes` true a passphrase may skip the class rule; every other rule still applies, as do the watch lists and history. |
| `tiers` | Change-period tiers, ordered strongest first (section 18.2.1). |
| `warning_days` | How many days before expiry sign-in warns, 0 to 365. |
| `history_count` | How many previous passwords may not be reused, 0 to 24. The current password counts as the newest. |
| `min_age_hours` | How long a password must be held before the user may change it again. |
| `include_builtin`, `watch_list_ids`, `hibp_enabled`, `hibp_on_unavailable` | The watch lists checked (section 18.7). |
| `fingerprint_enabled`, `end_sessions_on_match` | The sealed fingerprint and recheck (section 18.8). |
| `enforce_on_sign_in` | Require a change at sign-in when the password fails the policy's current rules (section 18.6). |

**18.2.1 Tiers and expiry.** A tier has a name, either "passphrase" or a minimum length and class count, and a maximum age in days (null means never). When a password is set, the first tier it meets, checked strongest first, is recorded with the resulting expiry. Only the tier's name and the expiry are stored, never the password's length or makeup. The last tier must be met by every password the rules accept, and a tier that an earlier tier always pre-empts is refused when the policy is saved, so every tier can be reached. A policy with no tiers never expires a password, and the seeded default has none. Expiry is counted from when the password was set, and a policy change takes effect at the user's next password sign-in, when the tier and expiry are recalculated from the same set time.

**18.2.2 The minimum age** applies only to a user's own change at [`POST /auth/password`](../contract/openapi.json). An administrator's set, a reset, an invitation and the forced change skip it: applied to a forced change it could never be completed, and applied to a reset it would lock out a user who forgot their password.

### 18.3 The policy description and checking in the browser

Four routes (section 18.4) answer with the policy the user's new password must meet:

```json
{
  "rules": {
    "version": 1,
    "normalisation": "NFC",
    "length_unit": "code_point",
    "min_length": 12,
    "max_length": 1024,
    "min_classes": 0,
    "classes": {
      "lowercase": ["Ll"],
      "uppercase": ["Lu", "Lt"],
      "digit": ["Nd"],
      "other_letter": ["Lo", "Lm"],
      "symbol": ["Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc", "Sk", "So", "Zs"]
    },
    "max_repeat": null,
    "forbid_user_details": false,
    "user_detail_min_length": 3,
    "passphrase": {"min_length": 20, "min_words": 4, "separators": [" ", "-", ".", "_"], "relaxes_classes": true},
    "tiers": [
      {"name": "passphrase", "passphrase": true, "min_length": 0, "min_classes": 0, "max_age_days": null},
      {"name": "standard", "passphrase": false, "min_length": 12, "min_classes": 0, "max_age_days": 90}
    ],
    "warning_days": 14
  },
  "history_count": 0
}
```

`passphrase` is null when the policy has none. The description is versioned (`version` is 1); a client that meets a version it does not know should fall back to the check route rather than guess.

A client evaluates it like this, so that it agrees with the server:

- Normalise the password to NFC (`text.normalize("NFC")`) and count code points, not UTF-16 units: `[...text].length` after normalising. An emoji counts once, though `String.length` counts it twice.
- A character's class is the `classes` entry whose Unicode general categories include its own category (a regular expression with `\p{Ll}` and the like gives the same answer). Marks, controls and other categories count towards length but belong to no class.
- `max_repeat` is the longest run of one identical code point.
- With `forbid_user_details`, lower-case the NFC text and test it for containing each token from the email local part and the display name (runs of letters and digits, and for the email the whole local part), keeping only tokens of at least `user_detail_min_length` code points.
- A passphrase has at least `passphrase.min_length` code points and `passphrase.min_words` words, splitting on `separators`.
- The tier is the first entry of `tiers` the password meets, or none.

**Proving a client agrees.** [`docs/contract/password-rule-vectors.json`](../contract/password-rule-vectors.json) holds 59 test cases generated from the server's rule engine: named policies in the description's own shape, and cases of a password, a policy name, an optional `user` (`email`, `display_name`) and the `expected` answer (`code_points`, `ok`, `passphrase`, `tier` and each rule's `code`, `passed` and `waived`). They cover every rule both ways, passphrase boundaries, tiers, combining marks and characters outside the Basic Multilingual Plane. A product runs every case through its browser code in its own tests; warden's tests fail if the file and the engine ever disagree, and run every case through the check route too. The server is always the authority: the browser's evaluation is for showing a checklist, never for deciding.

### 18.4 Live feedback: the four places

A password is set in four places that a screen can serve, and each has a pair of routes that use that place's own credential, so a screen can fetch the policy and check a candidate as the user types, before submitting:

| Place | Policy | Check | Credential sent |
|---|---|---|---|
| Signed-in change | [`GET /auth/password/policy`](../contract/openapi.json) | [`POST /auth/password/check`](../contract/openapi.json) `{"password"}` | The access token as the bearer, from a user who holds a password. |
| Invitation | [`POST /auth/invitations/accept/password-policy`](../contract/openapi.json) `{"token"}` | [`POST /auth/invitations/accept/password-check`](../contract/openapi.json) `{"token", "password"}` | The invitation link's token. |
| Reset link | [`POST /auth/password-reset/policy`](../contract/openapi.json) `{"token"}` | [`POST /auth/password-reset/check`](../contract/openapi.json) `{"token", "password"}` | The reset link's token. |
| Forced change | [`POST /auth/password-change/policy`](../contract/openapi.json) `{"challenge"}` | [`POST /auth/password-change/check`](../contract/openapi.json) `{"challenge", "password"}` | The `password_change_required` challenge (section 18.6). |

An invitation's policy is the one its staged roles resolve to, as if already granted, else the default. The submit routes are the ones the places already had: [`POST /auth/password`](../contract/openapi.json), [`POST /auth/password-reset/complete`](../contract/openapi.json), [`POST /auth/invitations/accept`](../contract/openapi.json) and [`POST /auth/password-change`](../contract/openapi.json).

**The answers.** The policy route answers the description above. The check route answers:

```json
{
  "ok": false,
  "results": [
    {"code": "min_length", "passed": false, "waived": false, "message": "Use at least 12 characters"},
    {"code": "max_length", "passed": true, "waived": false, "message": "Use at most 1024 characters"}
  ],
  "passphrase": false,
  "tier": null,
  "watch_list": {"reason": "This password is too common"},
  "watch_list_unavailable": false
}
```

`results` lists each rule the policy configures, in a fixed order, so a checklist can be drawn from it. `waived` is true when the class rule passed only because the password is a passphrase. `watch_list` is null or carries the list's own reason, never its id. `ok` is true only when every rule passed and no watch list refuses the password (a match, or, when the policy refuses while the range API is down, an unavailable answer). A request without a candidate string gets 400 only with a valid credential, and any bad credential gets the uniform refusal and reveals nothing, including whether a reset link was already used.

**Four properties a client can rely on.**

- **History is checked only on submit.** The check route never looks at history, so `ok` can be true for a password the submit route then refuses with `history` (or `min_age`). Always handle the submit refusal.
- **Nothing is stored, audited or used up.** A check does not consume the token or challenge, writes nothing and records no audit event, and answers `Cache-Control: no-store`.
- **They are throttled.** Each credential (the session, or the token or challenge) may make `10 x identity.sign_in_attempt_limit` calls per `identity.sign_in_window_seconds` (100 per 15 minutes by default), and each source address five times that (500). The policy routes share the same budget. A spent budget is the uniform refusal, the same answer as a bad credential. A product can tune the per-credential figure with `Identity(password_check_limit=...)`.
- **The server's range lookup is part of the check** when the policy enables it (section 18.7), so a check can be slower than a purely local rule.

**Debouncing (advice).** Evaluate the rules in the browser on every keystroke, since that needs no request, and call the check route only for what the browser cannot know (the watch lists). Wait for a pause in typing of about 400 milliseconds, send at most one request at a time, drop the answer to a request that a newer one has replaced, and do not check an empty password. Do not retry a refused or throttled check in a loop. Treat a failed check request as "unknown", not as failure: the submit route decides.

### 18.5 Refusals at submit

A password the policy refuses is a 400 with every failure named at once, and the link or challenge it was sent under stays usable:

```json
{
  "detail": "password not accepted",
  "failures": [
    {"code": "min_length", "message": "Use at least 12 characters"},
    {"code": "watch_list", "message": "This password is too common"}
  ]
}
```

The codes are:

| Code | Meaning | Message |
|---|---|---|
| `min_length`, `max_length` | Too short or too long. | "Use at least N characters", "Use at most N characters". |
| `min_classes` | Too few kinds of character. | "Use at least N kinds of character: lower case, upper case, digits, symbols and other letters". |
| `max_repeat` | A character repeats too often in a row. | "Repeat a character at most N times in a row". |
| `no_email`, `no_display_name` | Contains the user's email or name. | "Do not use your email address", "Do not use your name". |
| `watch_list` | On a watch list. | The list's own reason, for example "This password is too common" (built-in list) or "This password has appeared in a data breach" (range API). |
| `watch_list_unavailable` | The range API could not be asked and the policy refuses then. | "The password could not be checked against breached passwords; try again later". |
| `history` | One of the user's last N passwords. | "Choose a password you have not used recently". It never says which one matched. |
| `min_age` | Changed too recently (the user's own change only). | "Your password was changed too recently to change it again yet". |

A rule's message names the policy's own limit, so show it as the server gives it, or build your own from the code and the description. A wrong current password at [`POST /auth/password`](../contract/openapi.json) is the separate fixed 400 `password change refused`, which is not a policy refusal. A reset or invitation link that is not live is the uniform 401 (section 7) before the password is looked at, so a dead link with an unacceptable password is a 401, not a 400. Refusals are audited as `warden.identity.password.rejected` with the codes and the list's id only, never the password.

### 18.6 `password_change_required`: the forced change

A password sign-in can answer that the password must change before a session is issued. This happens when:

| `reason` | When |
|---|---|
| `expired` | The password reached its tier's maximum age. |
| `watch_list` | The password is on a watch list that applies. The answer also carries `watch_list_reason`, the list's reason, to show the user. |
| `administrator` | An administrator asked for a change at next sign-in ([`PUT /admin/users/{user_id}/password-change-required`](../contract/openapi.json)). An earlier reason stands. |
| `policy` | The password fails the current rules of a policy with `enforce_on_sign_in` on. Without it, a password that fails an edited policy simply carries on until it expires. |

The answer is 200 with

```json
{"status": "password_change_required", "challenge": "…", "expires_in": 300, "reason": "expired"}
```

in place of `signed_in`. It replaces a session wherever one would have been issued: after the password alone, after TOTP ([`POST /auth/totp/verify`](../contract/openapi.json)), a recovery code ([`POST /auth/recovery-code`](../contract/openapi.json)), a security key as a second factor, or a forced enrolment (then it also carries the recovery codes and key, which the user must still be shown). Add this status to the handling in section 2.

**The order: second factor first.** The password is checked and the flags are set at the password step, but they are revealed only where a session would be issued. A caller who has only the password sees `mfa_required` exactly as before and learns nothing about the password's state, and the second factor's challenge cannot be used to change the password. A wrong password, or a user who is not `active`, still gets the uniform refusal.

**Completing the change.** Send the challenge and the new password to [`POST /auth/password-change`](../contract/openapi.json) as `{"challenge", "new_password"}`. A success answers 200 with the session the sign-in would have issued, as `signed_in` with the same `amr` (so a password and TOTP sign-in keeps `["pwd", "otp"]`), and ends the user's other sessions. Meanwhile:

- The challenge is single use, even under concurrent submits, and lasts `identity.mfa_challenge_ttl_seconds` (300 seconds by default).
- A refused new password (the 400 of section 18.5) costs the challenge an attempt, and after `identity.mfa_max_failures` (5 by default) it stops working: the user signs in again. Use the live checks (section 18.4) so the submitted password is likely to pass.
- A user who is suspended after the challenge was issued gets nothing: the status is checked again at completion.
- The new password goes through the policy like any other, including history. The minimum age does not apply.
- The sign-in throttle for the user is not cleared until the change is complete.

**The expiry warning.** Within `warning_days` of expiry, the `signed_in` body of a password sign-in (including after TOTP, a recovery code or a security key) carries `password_expires_in_days`, a whole number of at least 1 (rounded up). Absent otherwise. Show a notice with a link to the change screen. A refresh does not carry it, so show the notice from the sign-in answer.

**Not blocked.** A passkey sign-in or a single sign-on sign-in is not affected by the password's state: those users are never sent to a password change.

**Policy changes.** A policy edit does not touch anyone until their next password sign-in, when the password is re-checked against the current rules (and watch lists) and its tier and expiry are recalculated from when it was set. A password set before 0.1.0b20 starts its expiry clock at its next sign-in. The administration routes report how many users a policy applies to ([`GET /admin/password-policies/{policy_id}/affected-users`](../contract/openapi.json)) and, for a proposed priority and role mapping, how many it would apply to ([`POST /admin/password-policies/affected-users`](../contract/openapi.json), which changes nothing).

### 18.7 Watch lists

A watch list is a set of passwords that must not be used, with the reason a user is shown. A policy checks, in this order and stopping at the first match:

1. **The built-in list**, when `include_builtin` is on (it is in the seeded default). It holds the SHA-1 digests of the 100,000 most frequent passwords of Mark Burnett's ten million password dataset, as published in SecLists (MIT licence), about 100,000 entries (99,999 distinct) and no plain text, with the reason "This password is too common". It is read-only and changes only with a warden release. It is the one behaviour change from 0.1.0b18: very common passwords are refused on the seeded default, and a user whose current password is on it must change it at their next password sign-in.
2. **Local lists** attached to the policy ([`PUT /admin/password-policies/{policy_id}/watch-lists/{list_id}`](../contract/openapi.json), [`DELETE /admin/password-policies/{policy_id}/watch-lists/{list_id}`](../contract/openapi.json)). A list is `manual` or `imported`, and has a `reason`:
   - A `manual` list takes **exact passwords** an administrator adds ([`POST /admin/watch-lists/{list_id}/entries`](../contract/openapi.json), removed with [`POST /admin/watch-lists/{list_id}/entries/removal`](../contract/openapi.json)), stored only as the SHA-1 of the NFC form. The password arrives over TLS and is hashed at once; it is never stored, logged, echoed or audited. It also takes **terms** (3 to 64 characters, stored after NFC and case folding), which match when a password contains one without regard to case ([`POST /admin/watch-lists/{list_id}/terms`](../contract/openapi.json) and [`POST /admin/watch-lists/{list_id}/terms/removal`](../contract/openapi.json)). Each call takes at most 100 and answers counts only.
   - An `imported` list holds SHA-1 hashes loaded from a file with the command line (below).
   - Lists are managed with [`GET /admin/watch-lists`](../contract/openapi.json), [`POST /admin/watch-lists`](../contract/openapi.json), [`GET /admin/watch-lists/{list_id}`](../contract/openapi.json), [`PUT /admin/watch-lists/{list_id}`](../contract/openapi.json) (rename or change the reason) and [`DELETE /admin/watch-lists/{list_id}`](../contract/openapi.json). A list that is attached to a policy cannot be deleted (409). A view shows counts, the last import and threshold and the attached policies, never entries, terms or hashes.
3. **The range API**, only when the policy sets `hibp_enabled`.

A password is looked up as typed and in NFC form. Terms are matched only against the password itself, so they work at set points and at sign-in but not in recheck (section 18.8).

**Importing a Have I Been Pwned list.** `warden passwords import --list NAME --file PATH [--threshold N] [--create --reason TEXT] [--actor NAME]` reads the downloader's format, one `HASH:count` per line (SHA-1, either line ending), streams it into the database and swaps it in within one transaction, so a failing line (reported by its number, never its content) leaves the list as it was and a sign-in running meanwhile sees the old list or the new one. `--create` makes the list (kind `imported`) when it is missing, with `--reason`. The command prints counts only and is audited as `warden.identity.watch_list.imported`. NTLM downloads are not supported.

**Sizes to expect.** Each hash is a 20-byte row keyed with its list, and Postgres adds row and index overhead on top, so budget several times the raw 20 bytes a hash. The full Pwned Passwords SHA-1 set is very large, on the order of a billion lines and tens of gigabytes of text as downloaded (these figures come from the service, not from warden, and grow; check the current ones at the source), so a full import needs a matching amount of database space and a long import. `--threshold N` keeps only hashes seen at least N times, which cuts a list sharply. The command prints the lines read and the hashes kept (and how many fell below the threshold), so import with a threshold, look at the figures, and raise or lower it until the size suits the database. A threshold needs the count on every line. Importing is a deliberate operator task; the range API (below) is the alternative that needs no storage.

**The range API.** With `hibp_enabled`, the policy asks a Pwned Passwords range endpoint (`passwords.hibp_range_url`, default `https://api.pwnedpasswords.com/range/`). It is the only request warden ever makes on a user's behalf to a third party, and it is made only for a policy that enables it; the seeded default makes none.

- **What is sent.** Only the first five hex characters of the password's SHA-1 (k-anonymity). The service answers with every suffix it knows under that prefix, and the comparison is made locally over the whole answer. The password, its full hash and the user are never sent, and nothing is cached between calls.
- **Padding.** warden asks for padded answers (`passwords.hibp_padding`, on by default), so the size of an answer reveals nothing, and ignores the zero-count padding entries.
- **A self-hosted mirror.** `passwords.hibp_range_url` may be any https URL (http is refused), so a deployment that does not want to reach the public service can point it at its own mirror. `passwords.hibp_timeout_seconds` (5 by default) bounds one request and `passwords.hibp_user_agent` sets the user agent.
- **When it cannot answer.** Any failure (a transport error, a status other than 200, an unreadable answer) is treated as unavailable, with a fixed error that names no URL or prefix. The policy's `hibp_on_unavailable` decides: `allow` (the default) lets the password through and audits `warden.identity.password.watch_list_unavailable`, `refuse` fails it with `watch_list_unavailable` (section 18.5). At sign-in a range API that cannot answer never stops anyone from signing in whatever the setting, and is audited; the refuse setting applies where a password is set.

### 18.8 The fingerprint and recheck

A watch list can gain a password after a user last signed in. Every password sign-in checks the password just proved against the policy's lists, but a user who does not sign in is not checked. To cover them, a policy may enable the **fingerprint** (`fingerprint_enabled`) and the product may run a **recheck**.

**What is stored.** With the fingerprint on, warden keeps the SHA-1 of the user's password (the Pwned Passwords form), sealed with AES-256-GCM under a key from konfig's secrets store, bound to the user's id so a value copied onto another user's row does not open. It is written when the password is set, or at the user's next sign-in for a password set before the policy enabled it, and removed when the policy no longer keeps one. History stores only Argon2id hashes, and nothing else about a password is kept: no column holds a password, its length or makeup, an unsealed digest or a hash prefix. Nothing logs or audits a password, hash, digest, prefix or fingerprint.

**The trade-off, plainly.** A fingerprint is a fast hash under a key. Anyone who holds both the database and the key can recover a fast SHA-1 of each fingerprinted password, which is much easier to crack than an Argon2id hash. That is why it is off in the seeded default, why a policy enables it only by choice, and why it is worth enabling only where finding exposed passwords between sign-ins matters more than that risk. Keep the key out of the database's backups and out of the database's administrators' reach.

**The key and its rotation.** `passwords.fingerprint_key_secret` names the konfig secret that holds the key, and `passwords.fingerprint_previous_key_secret` the previous key while rotating. Unset (the default), no policy may enable the fingerprint, and the policy routes refuse it. To rotate: put the new key in the current secret and the old one in the previous secret, then run recheck; values sealed with the previous key still open and are re-sealed with the current one as they are read (the recheck report counts them as `resealed`). Once nothing is sealed with the old key, the previous secret can be dropped. A configured secret that is not in the secrets store fails construction.

**Recheck.** `warden passwords recheck [--policy NAME] [--end-sessions-override off] [--actor NAME]` opens, in memory only, the sealed fingerprint of every user whose effective policy enables it and checks it against the policy's built-in list, attached lists and (when enabled) the range API, asking once per prefix in the run. On a match it requires a change (reason `watch_list`), ends the user's live sessions if the policy's `end_sessions_on_match` says so (`--end-sessions-override off` never ends one), and audits it. It prints counts only: passwords checked, matched, newly required to change, sessions ended, resealed, fingerprints that would not open, and range checks unavailable. Terms are not checked, because they need the password itself.

**Scheduling.** warden ships no scheduler. The product runs the command from its own scheduler (cron, a job runner, a deployment task), at an interval that suits how fast its lists change. The stock command cannot know which roles the product declares, so it counts every role that has a policy mapping; a product that wants exact declared-role semantics calls `warden.cli.main` from its own entry point with its `PermissionRegistry` (the `permissions` argument), or calls `Identity.password_recheck.run(actor=...)` from its own scheduler. Both commands print one fixed message and exit 1 when the database cannot be reached.

**The exposure report.** [`GET /admin/password-exposures`](../contract/openapi.json) lists the users required to change their password because of a watch-list match, by user id, with where it was found (`builtin`, `list`, `term` or `hibp`), the list's id and the policy that applies, with counts by list and by policy. It is paged as `GET /admin/users` is. A user drops out of it when they change their password, or when an administrator clears the requirement with [`DELETE /admin/users/{user_id}/password-change-required`](../contract/openapi.json), which is audited as `warden.identity.password.change_cleared`.

### 18.9 Administering policies

Every administration route is behind the permission the product gave `admin_router(password_policies=...)`, falling back to the user administration permission when that is not given. The routes are:

- policies: [`GET /admin/password-policies`](../contract/openapi.json), [`POST /admin/password-policies`](../contract/openapi.json), [`GET /admin/password-policies/{policy_id}`](../contract/openapi.json), [`PUT /admin/password-policies/{policy_id}`](../contract/openapi.json) and [`DELETE /admin/password-policies/{policy_id}`](../contract/openapi.json). A change sends the `version` it read and changes only the settings sent, answering 409 if the policy has changed since. A policy is shown as `WardenPasswordPolicyRecord` in the contract (the stored record), distinct from `WardenPasswordPolicy`, which is the live-feedback answer. Inconsistent settings are refused (400) with `errors` naming each field at fault and a fixed message. A delete is refused (409) for the default and for a policy pinned on any user, saying why;
- order: [`PUT /admin/password-policies/{policy_id}/priority`](../contract/openapi.json) moves a policy to a free priority (409 when taken, even under concurrent requests), and [`PUT /admin/password-policy-order`](../contract/openapi.json) reorders every policy but the default at once;
- the built-in list: [`PUT /admin/password-policies/{policy_id}/builtin-list`](../contract/openapi.json) includes or excludes it;
- impact: [`GET /admin/password-policies/{policy_id}/affected-users`](../contract/openapi.json) and [`POST /admin/password-policies/affected-users`](../contract/openapi.json), as in section 18.6.

Every change is audited under the `warden.identity.password_policy.*` and `warden.identity.watch_list.*` actions, with identifiers, rule codes and counts only.

### 18.10 What the NIST guidance says, and where warden's settings depart

NIST Special Publication 800-63B-4, *Digital Identity Guidelines: Authentication and Authenticator Management*, section 3.1.1.2 (Password Verifiers), is the current guidance on passwords: <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>. An operator should know where the defaults sit against it, and which settings leave it.

**What the default follows.**

- **Length over composition.** The guidance asks for a minimum length (15 characters when a password is the only factor, and at least 8 when it is part of multi-factor authentication), a permitted maximum of at least 64, Unicode accepted, each code point counted as one character, and nothing truncated. warden counts NFC-normalised code points, allows up to 1,024, accepts any Unicode text and never truncates. The seeded default's minimum of 12 meets the multi-factor figure, which suits the default `identity.require_mfa`; a deployment that allows a password alone should raise `min_length` to 15.
- **A blocklist, with the reason given.** The guidance requires comparing a new password against a list of commonly used, expected or compromised passwords, requiring a different one when it matches, and telling the user why. The built-in list, local lists and the range API do this, and a refusal carries the list's own reason.
- **Change on evidence of compromise.** The guidance says verifiers shall not require periodic change but shall force a change on evidence of compromise. A watch-list match (at a set point, at sign-in, or in recheck) forces a change with reason `watch_list`, and an administrator can force one.

**Where settings depart from it.** Each of these is off in the seeded default and is an operator's choice, so choose knowingly:

- **Scheduled change.** Tiers with a `max_age_days` expire passwords on a timetable, which the guidance says shall not be required. Leave `tiers` empty (or every `max_age_days` null) to follow it. Where a regulation or a customer demands expiry, tiers let a stronger password, or a passphrase, last longer.
- **Class rules.** `min_classes` is a composition rule, which the guidance says shall not be imposed. Leave it at 0 to follow it; a passphrase can waive it where it is used.
- **Other composition-like rules.** `max_repeat` and `forbid_user_details` are also off by default. The guidance asks that the blocklist comparison cover the entire password, not substrings; local list terms and the user-detail rule match substrings, so they too go beyond it.
- **History and minimum age.** Neither is among the guidance's requirements; they are operator choices and are off by default.
- **Enforcing a rule change at sign-in** (`enforce_on_sign_in`) forces a change when a password no longer meets edited rules. It is off by default; with it off, the old password carries on.

The settings exist because some deployments must meet other requirements. warden makes none of these departures unless an administrator turns them on.

### 18.11 A checklist for the product

- Fetch the policy and show a live checklist at all four places; evaluate locally, check the watch lists with a debounced call, and prove the evaluation with the vectors file.
- Handle `password_change_required` everywhere a session may be issued, and show the list's reason for `watch_list`.
- Show the expiry warning from `password_expires_in_days`.
- Handle the 400 `failures` list at submit, including `history` and `min_age`, which the check cannot see.
- Treat a throttled or failed check as unknown, not as a refusal of the password.
- Run `warden passwords recheck` on a schedule if any policy keeps fingerprints, and surface the exposure report to administrators.
