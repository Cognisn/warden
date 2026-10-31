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

[`POST /auth/sign-in`](../contract/openapi.json) takes `{"email", "password"}` and answers 200 with one of three `status` values:

| `status` | Meaning | Next step |
|---|---|---|
| `signed_in` | A session: `access_token`, `token_type` (`Bearer`), `expires_in`, `refresh_token`, `refresh_expires_in`. | Use the access token (section 3). |
| `mfa_required` | The password was right and the user has TOTP. The body carries a `challenge` and its `expires_in`. | Ask for a code and send it to [`POST /auth/totp/verify`](../contract/openapi.json) as `{"challenge", "code"}`, or a recovery code to [`POST /auth/recovery-code`](../contract/openapi.json). |
| `mfa_enrolment_required` | The password was right, the deployment requires a second factor (`identity.require_mfa`, on by default) and the user has none confirmed. The body carries a `challenge`. | Enrol under the challenge (section 5); confirming the enrolment signs the user in. |

Every other outcome (an unknown address, a wrong password, an `sso_only` user, a user who is not `active`, a throttled attempt) is the uniform refusal (section 4). Do not tell the user which; you cannot know.

A challenge is single-purpose and short-lived: it expires after `identity.mfa_challenge_ttl_seconds` (300 seconds by default) and is used up by the step it was issued for. After `identity.mfa_max_failures` wrong codes (5 by default) it stops working, so the user must sign in again. A TOTP code is six ASCII digits; any other text (including other scripts' digits) is refused like a wrong code. A code is accepted at most once per 30-second step, so a user who submits the same code twice gets the refusal the second time.

Every route that issues a session answers with the same `signed_in` body: password sign-in, TOTP verification, a recovery code, refresh, confirming an enrolment under a challenge, and the single sign-on handoff. A client can handle them with one function.

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

**Changing the password.** [`POST /auth/password`](../contract/openapi.json), with the access token as the bearer, takes `{"current_password", "new_password"}`. It answers 204 and ends the user's other sessions; the current one stays. A wrong current password, or a user with no password (`sso_only`), gets 400 `password change refused`; a new password shorter than `identity.password_min_length` (12 by default) gets a 400 naming the minimum.

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

**Accepting with a password.** [`POST /auth/invitations/accept`](../contract/openapi.json) takes `{"token", "password"}`. Success (200 `{"status": "accepted", "email"}`) activates the user and applies the staged roles, but does not sign them in: send them to sign-in next. A password that is too short (400) leaves the link usable, so let the user try again. An invitation whose method is `sso_only` answers 409 and leaves the link usable: accept it through single sign-on instead. A used, expired or revoked link is the uniform refusal.

**Accepting through single sign-on.** The accept-invitation screen submits the token to [`POST /auth/sso/start`](../contract/openapi.json) in the field `invitation`, as a top-level form submission (`application/x-www-form-urlencoded`) or a JSON body, so the token stays out of every URL. warden answers 303 to the provider; from there the flow is section 6. The provider's verified email must be the invited address (ignoring case); the callback then accepts the invitation and the completion screen's handoff signs the new user in. A mismatched identity leaves the invitation usable and lands on `?error=sso_failed`.

**Password reset.** [`POST /auth/password-reset`](../contract/openapi.json) (`{"email"}`) always answers 202 `{"status": "requested"}` before doing any work, whether or not the address has an account, so neither the answer nor its timing says. Show the same message whatever the address ("if an account exists, a link is on its way"). A link is mailed only to an `active` user whose method is `password_and_sso`, and earlier links stop working. It lasts `identity.reset_ttl_seconds` (1 hour by default). [`POST /auth/password-reset/complete`](../contract/openapi.json) takes `{"token", "new_password"}`, answers 204 and ends every session of the user. A password that is too short (400) leaves the link usable; a bad, used or expired link is the uniform refusal. An administrator can also send a link with [`POST /admin/users/{user_id}/password-reset`](../contract/openapi.json), which reports whether it was sent.

Each link works once, even under concurrent submits.

## 8. API keys

An administrator creates a key with [`POST /admin/api-keys`](../contract/openapi.json) (`user_id`, `name`, `scopes`, optional `expires_at`), lists keys with [`GET /admin/api-keys`](../contract/openapi.json) and revokes one with [`DELETE /admin/api-keys/{key_id}`](../contract/openapi.json). The answer to creation carries the key itself (`key`, beginning with `identity.api_key_prefix`, `wdn_` by default) exactly once; warden keeps only a hash and a short `hint`. Show it once and tell the holder to store it.

A program uses the key as a bearer token: `Authorization: Bearer wdn_...`. `require_user` and `require_permission` accept it on the product's routes and on the administration routes. Its permissions are its `scopes` intersected with its user's current permissions, so a key never exceeds its user. It is refused (the uniform refusal) once it expires or is revoked, and while its user is not `active`. The session routes, sign-out and change password, need an access token and refuse a key.

## 9. The sign-in throttle

Password sign-in is throttled per pair of identifier (the email as typed, ignoring case) and client address: once a pair has made `identity.sign_in_attempt_limit` attempts (10 by default) within `identity.sign_in_window_seconds` (15 minutes by default), further attempts get the uniform refusal without the password being checked. Unknown addresses are throttled alike, so throttling reveals nothing. Only issuing a session clears the count; a right password followed by an MFA challenge does not. A throttled user sees the same refusal as a wrong password: advise them to wait, or to reset their password, rather than retrying.

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
