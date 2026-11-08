# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0b18] - 2026-11-08

Eighteenth beta: capabilities, so a client can disable and explain unavailable features up front.

### Added

- Capabilities: a client can learn up front which optional features this deployment offers, to disable and explain them instead of finding out from a refusal. `await Identity.capabilities()` returns `IdentityCapabilities`, six booleans: `mail_sender`, `invitations` (a sender and `http.accept_invitation_link`), `password_reset` (a sender and `http.reset_password_link`), `passkey_registration_link` (WebAuthn, a sender and `http.passkey_registration_link`), `single_sign_on` (enabled, with an issuer and a client id, following the run-time setting through the cache sign-in uses) and `webauthn` (a relying party is known). Each is the exact condition its route checks, and a test per capability flips the condition and shows the answer and the route change together. `GET <auth>/capabilities` is anonymous, `no-store` and the same for every caller, and answers only `password_reset`, `single_sign_on` and `passkey_sign_in`; `GET <admin>/capabilities`, behind the user administration permission, answers all six. Neither returns any setting's value. Additive: no existing route, answer or refusal changes, and the 503s remain the authority. No new setting and no migration. The contract (`docs/contract/openapi.json`) and the client guide (section 17) describe them.
- The sample console reads both capability routes: the sign-in screen hides single sign-on, passkey sign-in and the forgotten-password form when they are unavailable, and the Users and Invitations screens disable invite, resend, send reset and send passkey registration link with a notice saying mail is not configured or which link setting is missing. `serve --without-mail` starts it with no mail sender to show the notices.

## [0.1.0b17] - 2026-11-07

Seventeenth beta: the passkey sign-in options route is throttled by source address.

### Changed

- `POST <auth>/passkey/options` is throttled by source address, with `identity.sign_in_attempt_limit` requests per `identity.sign_in_window_seconds` on a count of its own: once an address has used it up, the route gives the uniform refusal and issues no challenge, and the refusal is recorded on `warden.identity.sign_in` with method `passkey` and reason `options_throttled`. The count is separate from the passkey and password sign-in counts, and a passkey sign-in that issues a session clears it for its address. No new setting and no migration. The contract (`docs/contract/openapi.json`) and the client guide (section 16.3) describe it.

## [0.1.0b16] - 2026-11-07

Sixteenth beta: the WebAuthn credential list says which credentials sign in on their own as passkeys. Additive; no other change.

### Added

- `GET <auth>/webauthn/credentials` (and the credential in the registration, rename and link responses) gains a boolean `passkey`, and `WebAuthnCredential` gains a matching `passkey` property: true exactly when the credential is discoverable and was registered with user verification, the rule a discoverable sign-in applies. It is additive; existing fields are unchanged. No migration. The contract (`docs/contract/openapi.json`) and the client guide (section 16) describe it, and the sample console labels keys from it and drops its interim gap notice (question 29).

## [0.1.0b15] - 2026-11-07

Fifteenth beta: a TOTP key rotation test no longer depends on where a 30-second step boundary falls. No change to the library.

## [0.1.0b14] - 2026-11-07

Fourteenth beta: the sample console exercises passkeys and security keys. No change to the library.

### Added

- The sample console (`examples/console`, not part of the package) exercises passkeys and security keys through warden's routes: the account screen registers a key with a nickname, lists, renames and removes keys, and shows the refusal to remove the last second factor; sign-in offers a key beside the authenticator code when `mfa_required` lists `webauthn`, a key or an authenticator app in a forced enrolment, and **Sign in with a passkey** with conditional mediation in the email field's autofill; administration sets `passkey_only`, invites with it, resets every second factor and sends a passkey registration link, which the outbox shows and a new `/passkey` page completes (the example configuration sets `http.passkey_registration_link` to it); and an invitation can be accepted with a passkey. Recovery codes from link registration and invitation acceptance are shown once. The Content Security Policy is unchanged. `examples/console/README.md` describes the walk with a real YubiKey and with a synced passkey, and how to accept only YubiKeys with Yubico's attestation roots, and lists one interim gap (question 29: the list of a user's keys does not yet say which can sign in alone). Tests in `tests/examples` drive every new screen's routes with the test suite's software authenticator. warden's behaviour is unchanged.

## [0.1.0b13] - 2026-11-07

Thirteenth beta: a live check, in Chromium, that a real browser and warden's WebAuthn routes fit together. No change to the library.

### Added

- A live check that a real browser and warden's WebAuthn routes fit together (`tests/identity/webauthn/live/`, marked `integration` and skipped by default). Chromium, driven by Playwright with the DevTools WebAuthn domain's virtual authenticators (CTAP2, a USB security key without user verification and a platform passkey with resident keys and user verification), runs five flows against a test-only app over a testcontainers Postgres, with `localhost` as the relying party: a password then a security key as second factor; registering a passkey then signing in with it and no email; passkey sign-in refused by the browser when the authenticator cannot verify the user; a `passkey_only` invitation accepted with a passkey; and the administrator's reset then a registration link. Each flow checks what the page saw and what warden recorded. The page is served from the tests tree with no inline script. `playwright` (Apache-2.0) joins the `dev` extra only; it is not a runtime dependency. No change to the library.

## [0.1.0b12] - 2026-11-07

Twelfth beta: documentation for security keys and passkeys, in the client-behaviour guide, the design overview and the README. No change to the library.

### Added

- The client-behaviour guide gains section 16, security keys and passkeys (WebAuthn), for a product's front end: the browser calls and the Level 3 JSON helpers with a fallback, registering a key as a second factor (signed in and in a forced enrolment), `methods` on `mfa_required` and completing a sign-in with a key, passkey sign-in with conditional mediation and a button, `passkey_only` users, the administrator's registration link and passkey invitations, the relying party ID and origins, optional attestation roots (Yubico's root as the worked example, and that synced passkeys are refused when roots are set), the credential limit, user verification and `amr`, and the uniform refusals. It also notes that passkey sign-in is throttled by source address and by credential, so clients behind one shared address share the address budget.
- The design overview records WebAuthn: decision D18, the scope in section 3.1, the package layout, acceptance tests, delivery milestone M6a, the `fido2` dependency and its MPL-2.0 public suffix list as a named licence exception, and the WebAuthn Level 3 and RFC 8176 references.
- The README names passkeys and security keys.

## [0.1.0b11] - 2026-11-07

Eleventh beta: signing in with a passkey alone, the `passkey_only` sign-in method, the administrator's passkey registration link, and `passkey_only` invitations accepted by registering a passkey. Users without keys see no difference, except that a user holding keys can no longer be switched to `sso_only` until the administrator's reset removes them.

### Added

- Signing in with a passkey alone. `POST <auth>/passkey/options` returns the options for `navigator.credentials.get()`: a fresh, single-use challenge, user verification required and no `allowCredentials`, so the answer is the same for every caller, reveals nothing about any account and suits conditional mediation (autofill). `POST <auth>/passkey/sign-in` takes the browser's answer and issues the same `signed_in` answer as a password sign-in, with `amr` `["hwk", "mfa"]`, which satisfies a policy that requires a second factor: there is no second step. The user is found by the answer's user handle and credential id together. It is open to `password_and_sso` and `passkey_only` users whose credential is discoverable and was registered with user verification; a security key held only as a second factor cannot sign in alone. Every failure is the uniform refusal, the reason recorded on `warden.identity.sign_in` with method `passkey`. Passkey attempts are throttled by source address and, separately, by the credential id, each with `identity.sign_in_attempt_limit` per `identity.sign_in_window_seconds`.
- A `passkey_only` sign-in method (`SignInMethod.PASSKEY_ONLY`), set with `POST <admin>/users/{user_id}/sign-in-method` or on an invitation. Such a user signs in with a passkey and no other way: password sign-in is refused exactly as a wrong password is, and so is single sign-on; password reset (the public request and the administrator's) and change of password are refused as for `sso_only`. Setting `passkey_only` also answers `has_passkey`; when it is false, the user cannot sign in until they register a passkey from a link.
- The administrator's passkey registration link: `POST <admin>/users/{user_id}/passkey-registration` mails a single-use link (`http.passkey_registration_link`, lasting `identity.reset_ttl_seconds`) and answers 202 with when it expires; sending again stops the earlier link working. With it, `POST <auth>/passkey-registration/options` and `POST <auth>/passkey-registration` register a passkey (resident key and user verification required) and use the link up in one transaction, without signing in, answering with the passkey and, for a user who held none, fresh recovery codes. Refused for a user who is `sso_only` or not active. There is no self-service request. For a user who has lost every passkey: `DELETE <admin>/users/{user_id}/mfa`, then the link. A new mail kind, `MailKind.PASSKEY_REGISTRATION`, with a default template a product may replace (`PASSKEY_REGISTRATION` in `mail.template_package`).
- `passkey_only` invitations, accepted by registering a passkey: `POST <auth>/invitations/accept/passkey/options` and `POST <auth>/invitations/accept/passkey` register the passkey, activate the user with the staged roles and use the invitation up in one transaction, without signing in, answering with the passkey and fresh recovery codes. An answer that is not a passkey is a 400 and leaves the invitation usable. A `passkey_only` invitation offered a password is a 409 (`use a passkey to accept this invitation`) and through single sign-on is refused, both leaving it usable; another invitation offered a passkey is a 409 saying how to accept it. Inviting `passkey_only` without WebAuthn configured is a 409.
- Audit actions `warden.identity.passkey.link_sent` and `warden.identity.passkey.registered`; an invitation accepted by passkey records `warden.identity.invitation.accepted` with method `passkey` and the credential id. Details carry identifiers only.
- The Python API behind the routes: `Identity.begin_passkey_sign_in`, `passkey_sign_in`, `send_passkey_registration`, `begin_passkey_registration`, `finish_passkey_registration`, `begin_passkey_invitation`, `accept_invitation_with_passkey` and `Users.holds_passkey`, `Invitations.accept_with_passkey` and `passkey_invitee`, and `WebAuthn.begin_registration` and `finish_registration` gain `for_invitation`, which admits an invited user (and only one) for accepting a `passkey_only` invitation. `PasskeyInvitationAccepted`, `PasskeyLinkRefused`, `PasskeyLinkNotConfigured`, `PasskeyRegistration` and `SignInMethodConflict` are exported from `warden.identity`.
- The HTTP contract describes every new route and field, and the client-behaviour guide links each new route from section 5 until its full WebAuthn section arrives later in 0.1.0.

### Changed

- Switching a user to `sso_only` while they hold any security key or passkey is refused with a 409 (`SignInMethodConflict`) until the administrator's reset removes them, since an `sso_only` user holds none; the refusal is audited on `warden.identity.user.sign_in_method_changed`. Users without keys see no difference.
- A refused password sign-in, reset or reset link for a `passkey_only` user records the reason `passkey_only`.
- `InvitationMismatch` carries the invited user's `sign_in_method`.

## [0.1.0b10] - 2026-11-06

Tenth beta: security keys and passkeys (WebAuthn) as a second factor, peers of TOTP, with an administrator's reset of every second factor. Users without keys see no difference.

### Added

- Security keys and passkeys (WebAuthn) as a second factor, peers of TOTP. A signed-in user registers one with `POST <auth>/webauthn/registration` and `POST <auth>/webauthn/registration/confirm` (the browser's answer to `navigator.credentials.create()` and an optional nickname of 1 to 64 characters); so does a user in a forced enrolment, under the `mfa_enrolment_required` challenge, which completes their sign-in. Resident key and user verification are preferred, not required, and a credential that comes out discoverable with user verification is recorded as such. A user who signs in only through single sign-on cannot register one. The routes are part of `identity.auth_router()`, so a product mounts nothing new.
- Completing a password sign-in with a key: `POST <auth>/webauthn/verify/options` returns the options for `navigator.credentials.get()` for the `mfa_required` challenge, listing only that user's credentials, and `POST <auth>/webauthn/verify` takes the browser's answer and issues the session with `amr` `["pwd", "hwk"]`. It works under the challenge's attempt limit and single use, checks the user's status and sign-in method again as `/totp/verify` does, and refuses with the same uniform refusal, the reason going only to the audit trail. A signature counter that does not increase is refused and audited as a suspected clone.
- The `mfa_required` answer gains `methods`, the kinds of second factor the user holds (`["totp"]`, `["webauthn"]` or `["totp", "webauthn"]`). Existing clients are unaffected; `mfa_enrolment_required` is unchanged.
- A signed-in user lists their keys with `GET <auth>/webauthn/credentials` (id, nickname, when created and last used, AAGUID, backup eligibility and state, whether discoverable; never the public key), renames one with `PATCH <auth>/webauthn/credentials/{id}` and removes one with `DELETE <auth>/webauthn/credentials/{id}`. Removing the last second factor while the session policy requires one is refused with a 409 that says why; where none is required, removing the last factor also removes the recovery codes.
- An administrator's reset of every second factor: `Identity.reset_mfa(user_id, actor=..., source_ip=...)` and `DELETE <admin>/users/{user_id}/mfa`, behind the administration router's users permission. In one transaction it removes the TOTP enrolment, every security key and passkey and every recovery code, ends every session of the user, and records `warden.identity.mfa.reset` with counts (`totp_removed`, `webauthn_removed`, `recovery_codes_removed`, `sessions_ended`). It answers 204, also for a user with nothing enrolled, or 404 for no such user. `DELETE <admin>/users/{user_id}/totp` is unchanged and leaves keys in place.
- The administrator's view of a user (`GET <admin>/users/{user_id}`) gains `webauthn_credentials`, how many keys and passkeys the user holds.
- Audit actions `warden.identity.mfa.webauthn.registered`, `.renamed`, `.removed` and `.clone_suspected`, carrying warden's credential id and counts only; a sign-in with a key records `amr` and the credential id on `warden.identity.sign_in`, and a refused one records `warden.identity.mfa.verify` with method `webauthn`.
- The Python API behind the routes: `Identity.begin_webauthn_sign_in`, `verify_webauthn`, `begin_webauthn_registration`, `finish_webauthn_registration`, `list_webauthn`, `rename_webauthn`, `remove_webauthn` and `reset_mfa`, with `WebAuthnEnrolled`, `LastSecondFactorError` and `WebAuthnUnavailable` exported from `warden.identity`. `Identity.webauthn` is the relying party, and `Identity.webauthn_credentials` the credential store.
- Pruning removes expired WebAuthn ceremony challenges too: `Pruner` takes an optional `webauthn`, and `PruneReport` gains `webauthn_challenges`, counted in `total`.
- The HTTP contract (`docs/contract/openapi.json`) describes every new route and field, and the client-behaviour guide links each new route from section 5 until its full WebAuthn section arrives later in 0.1.0.

### Changed

- Any second factor, TOTP or a key, satisfies `require_mfa`, and a password sign-in by a user holding either answers `mfa_required`. Recovery codes are issued with a user's first second factor of either kind and cover every factor: a TOTP enrolment confirmed by a user who already holds a key answers an empty `recovery_codes` list, and the MFA-enrolled notice is sent only for the first factor. Users without keys see no difference.
- warden's default MFA-enrolled notice now reads "Two-step verification was set up on $email on $enrolled_at." in place of "An authenticator app was set up for two-step verification ...", so it is true of a security key too. Its kind, subject and variables are unchanged, and a product's own template is used as before.
- A deployment without a WebAuthn relying party (no `webauthn.rp_id` and a base URL on an IP address) builds `Identity` and serves every 0.1.0b8 route as before; the key routes then answer 409 `WebAuthn is not configured` to a signed-in user and the uniform refusal under a challenge.

## [0.1.0b9] - 2026-11-06

Ninth beta: the groundwork for passkeys and security keys (WebAuthn), as a Python service with its configuration and schema. No route uses it yet, and warden's behaviour is otherwise unchanged.

### Added

- A runtime dependency for passkeys and security keys (WebAuthn): `fido2` (`>=2.2.1,<3`, Yubico, BSD-2-Clause). It bundles the public suffix list under MPL-2.0, so `scripts/licence_audit.py` names it as a reviewed exception with its reason, as it does `certifi`. Its only dependency, `cryptography`, was already one of warden's, and warden imports none of its device (HID, NFC or smart card) modules.
- WebAuthn configuration, checked at start-up like every other section: `warden.webauthn` (`WebAuthnConfig`, exported from `warden.config`) holds the relying party id (`rp_id`, by default the host of `http.public_base_url`), its display name (`rp_name`), the allowed origins (`allowed_origins`, by default the origin of `http.public_base_url`; compared exactly, with no wildcard), the challenge lifetime (`challenge_ttl_seconds`, 300) and the browser's timeout hint (`client_timeout_seconds`, 240, at most the lifetime), the most credentials one user may register (`max_credentials_per_user`, 10), and optional trusted attestation roots (`attestation_roots`, PEM certificates, normally `secret://<name>`). The relying party id must be every allowed origin's host or a registrable suffix of it, by the public suffix list; a public suffix, an IP address or a wildcard fails at start-up, naming the field. `relying_party_id`, `relying_party_name` and `origins` give the values in effect. User verification is not a setting. A configuration that sets none of these loads exactly as before, including one whose base URL is a loopback IP address; WebAuthn is then unavailable until `rp_id` is set.
- `http.passkey_registration_link`, an optional template for the product's screen that registers a passkey from an administrator's emailed link, validated like `accept_invitation_link` (it must contain `{token}` and nothing else). Nothing uses it yet.
- One migration with the database schema for passkeys and security keys, in the `warden` schema only: `warden.webauthn_credentials` (each credential's owner, unique credential id, COSE public key and algorithm, signature counter, AAGUID, transports, backup eligibility and state, whether it is discoverable, whether the user was verified at registration, whether its attestation was verified, an optional nickname, and when it was created and last used), `warden.webauthn_user_handles` (each user's WebAuthn user handle, 64 random bytes, unique and never derived from the user id) and `warden.webauthn_challenges` (registration and sign-in challenges, held as hashes, each used up once). Their names are exported from `warden.db` (`WEBAUTHN_CREDENTIALS`, `WEBAUTHN_USER_HANDLES`, `WEBAUTHN_CHALLENGES` and `WEBAUTHN_TABLES`). The same migration lets `users.sign_in_method` hold `passkey_only` and a single-use token have the purpose `passkey_registration`, for passkey-only sign-in later in 0.1.0; nothing sets either yet. Its downgrade removes any passkey registration links and refuses while a user is `passkey_only`.
- The WebAuthn ceremonies as a Python service, `warden.identity.webauthn`, exported from `warden.identity`: `WebAuthn(config, db)` registers a passkey or security key for an active user (`begin_registration` and `finish_registration`), as a second factor (resident key and user verification preferred) or as a passkey (a discoverable credential with user verification required), and signs a user in with one (`begin_authentication` and `finish_authentication`), for a known user (the options list only that user's credentials) or discoverably (no credentials listed; the user is found by user handle and credential id together, and user verification is always required). Each response is checked for: a challenge issued for that ceremony and that user, unexpired and unused, used up by one guarded write in its own transaction before anything else is checked, so a response is accepted once however many times it is submitted at once; the client data's type; an origin equal to an allowed origin; no `crossOrigin`; the relying party id hash; user presence and, where required, user verification; on registration, an allowed algorithm (Ed25519, ES256 or RS256) and, with trusted roots configured, direct attestation whose certificate chain leads to one of them (self attestation and "none" are refused, and no attestation metadata is ever fetched); on sign-in, a credential the user holds, its signature, its backup eligibility, and the counter rule (a non-zero counter that does not increase is refused as a suspected clone). A user who is not active, or who signs in only through single sign-on, is refused at every step, as is a registration beyond `webauthn.max_credentials_per_user`, even when several finish at once. `WebAuthnCredentials` lists, counts, renames and removes a user's credentials, and sign-in updates a credential's counter, backup state and last use. Results (`WebAuthnOptions`, `WebAuthnRegistration`, `WebAuthnAssertion`, `WebAuthnCredential`) and refusals (`WebAuthnError`, with a `WebAuthnRefusal` reason) carry identifiers only, never a key, signature, challenge, client data or user handle, and nothing is logged. No route uses it yet and it records no audit event: the sign-in and enrolment routes that call it later in 0.1.0 do. warden's behaviour is otherwise unchanged.
- A software WebAuthn authenticator for warden's own tests (`tests/identity/webauthn/soft_authenticator.py`), building genuine responses from real ES256, Ed25519 and RS256 keys, with "none", self and certificate-chain attestation from a test CA, and every field a relying party checks open to tampering.

## [0.1.0b8] - 2026-11-02

Eighth beta: beta builds may be published to PyPI as pre-releases. warden's behaviour is unchanged.

### Changed

- Beta builds may now be published to PyPI as pre-releases, by tagging the stamp commit (`v0.1.0b8`) as for a release candidate; `docs/releasing.md` says so. Alpha builds are still never published. The workflow is unchanged: it already publishes whatever version the tag names, after a maintainer's approval.

## [0.1.0b7] - 2026-11-02

Seventh beta: the release workflow renamed for the PyPI trusted publisher. warden's behaviour is unchanged.

### Changed

- The release workflow is now `.github/workflows/publish.yml` (it was `release.yml`), the workflow name the PyPI trusted publisher for `cognisn-warden` is registered against. Its jobs and triggers are unchanged.

## [0.1.0b6] - 2026-10-31

Sixth beta: the README ready to be the PyPI project description. warden's behaviour is unchanged.

### Changed

- `README.md`, which is the PyPI project description, is ready for publication: it gives the beta status, the real requirements with the note that psycopg needs libpq (`psycopg[binary]` or a system libpq), an installation line (with `--pre` for a pre-release), and pointers to the client-behaviour guide and the HTTP contract. Every link is an absolute link to the repository's `main` branch, so none breaks on pypi.org; links to files that reach `main` only with 0.1.0 resolve from then. `tests/test_readme.py` fails on a relative link or image, or on the pre-release wording.

## [0.1.0b5] - 2026-10-31

Fifth beta: the release pipeline (trusted publishing to PyPI from a tag), distribution checks and metadata, and an sdist fix. warden's behaviour is unchanged.

### Added

- `tests/packaging` builds the sdist and the wheel from it, and fails if the wheel holds anything but the `warden` package and its metadata (with `py.typed`, `LICENSE` and `NOTICE`) or if the sdist holds an `examples` directory anywhere. The checks live in `.github/scripts/check_dist.py`, which CI and the release workflow run too, and each check is shown a distribution with the defect it exists to catch.
- CI runs two more jobs: `build` builds both distributions, runs `twine check --strict` and the distribution checks, installs the wheel into a clean environment and imports every public module from it; `examples` runs `mypy --strict` on the sample console.
- Distribution metadata: keywords, the project's source, documentation and security policy links, and the session and logging topic classifiers. The development status classifier is now Beta.
- The `dev` extra gains the build tools: `build` (MIT), `hatchling` (MIT) and `twine` (Apache-2.0). warden's runtime dependencies are unchanged.
- The release workflow, `.github/workflows/release.yml`. A version tag (`v0.1.0rc1`) builds the sdist and wheel, refuses a tag that does not name the package's version, runs `twine check --strict` and the distribution checks, installs the wheel into clean environments on Python 3.12 and 3.13 and imports every public module, then publishes to PyPI with trusted publishing from the protected `pypi` environment once a maintainer approves. A manual run publishes to TestPyPI from the `testpypi` environment. A push to any branch runs the same build and checks as a dry run and publishes nothing. No API token is used anywhere, and every action is pinned to a commit SHA.
- `docs/releasing.md`: how a version is stamped, tagged, approved, checked on PyPI and, for a final release, squash-merged to `main`, with what to do when something goes wrong and the one-time repository set-up.

### Changed

- `SECURITY.md` is ready for publication: it states what the policy covers (the published package, not the sample console), which versions receive security fixes, and how a fixed vulnerability is disclosed.

### Fixed

- The sdist no longer ships part of the sample console. Its include patterns were unanchored, so `README.md` also matched `examples/console/README.md`, and `tests` brought in `tests/examples`, whose tests cannot run without the sample. The patterns are now anchored to the project root and `tests/examples` is excluded. The wheel was not affected.

## [0.1.0b4] - 2026-10-31

Fourth beta: an administrator's TOTP reset, a fix for users locked out of password sign-in, with the client-behaviour guide's notes on what a product builds itself in 0.1.0.

### Added

- An administrator's TOTP reset, for a user who has lost both their authenticator and their recovery codes and was otherwise locked out of password sign-in for good. `Identity.reset_totp(user_id, actor=..., source_ip=...)` and the route `DELETE <admin>/users/{user_id}/totp` on the administration router, behind its users permission, answer 204 with no body, or 404 for no such user. In one transaction the reset removes the user's TOTP credential (confirmed or not) and every recovery code, ends every session of the user as a password reset does, and records one `warden.identity.mfa.reset` event (a new audit action) with the administrator as actor, the user as resource and only counts in its details (`totp_removed`, `recovery_codes_removed`, `sessions_ended`). The user's next password sign-in then answers `mfa_enrolment_required` where the session policy requires a second factor, and they enrol again. A reset of a user with nothing enrolled is a 204 too, still audited. The HTTP contract (`docs/contract/openapi.json`) and the client-behaviour guide describe the route. This is the only change in warden's behaviour.
- The client-behaviour guide's new section 15, on what a product builds itself in 0.1.0: its own who-am-I route over `require_user` and bootstrap command over `Identity.users` and `Identity.roles` (a `<auth>/me` route is planned for 0.2.0), routes over `Identity.policy` for the session policy, routes over `anchor`, `read_anchors` and `verify_anchors` for audit anchors, syslog settings read from the configuration at start-up, and `SSL_CERT_FILE` for single sign-on behind a private CA (a setting is planned for 0.2.0), with what that variable replaces. Section 5 says that a user cannot yet replace their own recovery codes.

### Changed

- The sample console (`examples/console`, not part of the package): its users screen has a **Reset TOTP** button that calls `DELETE <admin>/users/{user_id}/totp`, in place of the gap notice for question 6, and its README describes the reset and no longer lists it as a gap. The account screen says an administrator can reset a lost enrolment and that replacing one's own recovery codes is planned for 0.2.0.

## [0.1.0b3] - 2026-10-30

Third beta: the sample console under `examples/console`. warden's behaviour is unchanged.

### Added

- A sample console under `examples/console`, for local development only and not part of the package: a small FastAPI product that loads its `WardenConfig` through konfig, hands warden its own pool, declares sample permissions and roles with a resource-scope hook and product audit actions, and mounts every warden router under the configured prefixes. Its console (plain HTML, CSS and JavaScript modules, no build step, framework or CDN, a strict Content Security Policy, tokens held in memory only) exercises sign-in with TOTP and recovery codes, refresh and sign-out, single sign-on and break-glass, invitations and password reset through an in-memory outbox, users, roles, API keys, the session policy, single sign-on settings, and the audit trail with filters, CSV export, chain verification, anchors, syslog status and the published keys. `examples/console/README.md` gives the bootstrap steps and lists what warden's public surface does not yet provide. Tests in `tests/examples` run it against Postgres, and a tripwire fails if anything under `examples/` imports a private warden module or name. warden's behaviour is unchanged.
- An optional `examples` extra (`uvicorn`, BSD-3-Clause; `psycopg[binary]` and `psycopg-pool`, LGPL-3.0) for running the sample. warden's runtime dependencies are unchanged.
- The worktree recipe's `console` port (offset 40) for the sample console.

## [0.1.0b2] - 2026-10-30

Second beta: the HTTP contract and the client-behaviour guide, the audit verification types exported, and optional paging on the user list.

### Added

- The HTTP contract (milestone M6): `docs/contract/openapi.json`, the OpenAPI document of a reference app that mounts every warden router (sign-in, lifecycle, single sign-on, administration, single sign-on administration, audit, syslog and key publication) under the default prefixes. `scripts/export_openapi.py` writes it (`--check` reports drift), and `tests/test_openapi_contract.py` regenerates it and fails on any difference, so a route change shows in review. Every route now carries a summary, a description and its documented responses with their bodies, including the uniform refusal (status 401, `{"detail":"authentication failed"}`, `WWW-Authenticate: Bearer`); identity's request bodies, which identity's routes read themselves, are described too. This is documentation metadata only: no route's behaviour, status, headers or body changed, as the existing route tests show. The routers now carry OpenAPI tags (`warden: audit`, `warden: syslog`, `warden: key publication`), and the documentation models' component names begin with `Warden` (identity) so they do not collide with a product's own. The contract's `info.version` is the release series (`0.1`), so a pre-release stamp does not change it. Note that the document is generated by FastAPI, so a FastAPI upgrade that changes its output also fails the drift test until the document is regenerated.
- The client-behaviour guide, `docs/guide/clients.md`: what a product's client must do, from mounting the routers to sign-in and its statuses, access and refresh tokens (rotation, reuse and the grace window, serialising refreshes), the uniform refusal, TOTP enrolment and recovery codes, single sign-on (start, callback, the handoff and the completion screen, with the login cookie), invitation and reset links, API keys, the sign-in throttle, published keys, audit query, export and verification, and trusted proxies. It links every route to the contract, and a test fails if either names a route the other lacks. The design overview links both from the M6 milestone and the public API statement.
- `warden.audit` exports `AnchorStatus` and `BreakReason`, the literal types of `AnchorCheck.status` and `BrokenLink.reason`, so a product can type its handling of a verification report without importing `warden.audit.verify`. `audit_router`, `export` and `ExportFormat` stay in their modules, so `import warden.audit` still loads no FastAPI. The public surface snapshot carries both names.
- Optional paging on `GET <admin>/users` and `Users.list`: `limit` (1 to 1000 on the route, at least 1 in Python) and `after`, an opaque cursor over `created_at` and `id` from `Users.cursor(user)` or the route's `next`. Pages follow the list's order, oldest first with ties by id, and keep the `status` filter. With neither given, both return every user exactly as before, and the route's body is still `{"users": [...]}`; with either, the body also carries `next`, the cursor for the following page or null on the last. A malformed `limit` or cursor is a 400 with the route's fixed message, and a `UserError` in Python.

### Changed

- Upgrade note for 0.1.0a10, which did not say so: `sso.client_secret` became a string with a default (`warden.sso.client-secret`) instead of an optional value, so a configuration that sets it explicitly to null now fails at start-up, naming `warden.sso.client_secret`. Remove the key to use the default, or set the secret's name. A test now pins this.

### Deprecated

- The compatibility modules kept by 0.1.0a10: `warden.identity.schema`, `warden.identity.sso.schema`, and the table names re-exported by the lifecycle modules (`warden.identity.apikeys.API_KEYS`, `warden.identity.invitations.INVITATION_GRANTS` and `warden.identity.single_use.SINGLE_USE_TOKENS`). Import these names from `warden.db`. They keep working through 0.x and are removed in 1.0, as a named breaking change with an upgrade note. There is no warning at run time. The client-behaviour guide lists them in section 14.

## [0.1.0b1] - 2026-10-30

First beta: feature complete. The same code as 0.1.0a11, which passed the b1 gate: the full suite and checks, and the live syslog (UDP, TCP and TLS, plus a collector outage) and live single sign-on (sign-in, invitation and break-glass) checks. From this build the library takes fixes only.

## [0.1.0a11] - 2026-10-30

Eleventh pre-release: key publication, the last feature before 0.1.0b1.

### Added

- Key publication (design D14). `warden.jwks.keys_router(keys=...)` is a router the product mounts at `http.keys_prefix` (default `/keys`), so components outside the process can verify warden's access tokens and audit checkpoints without being able to sign. `GET <keys>/jwks.json` serves an RFC 7517 JWK Set of the keys that sign and verify live credentials (neither retired nor revoked); `GET <keys>/jwks-historical.json` adds retired keys, for verifying audit checkpoints. A revoked key is in neither. Each key is an RFC 8037 OKP key with exactly `kty`, `crv`, `x`, `kid`, `alg` (`EdDSA`) and `use` (`sig`); no private member is ever published. Both routes are unauthenticated and read-only, answer `application/jwk-set+json` with `Cache-Control: public, max-age=300` (a verifier that meets an unknown key id should fetch again), and record no audit event. Identity mounts nothing new by itself. The router lives in its own module, so importing `warden.keys` (as audit does) still loads no FastAPI; a tripwire fails if it does. `warden.jwks` is added to the public surface snapshot, and the root docstring names it.

## [0.1.0a10] - 2026-10-29

Tenth pre-release: the public import surface for 0.1.0b1, the single sign-on issuer kept verbatim, every schema name and lock key in `warden.db.schema`, and `Users.list`.

### Added

- The public import surface for 0.1.0b1. `warden.identity` now also exports the user lifecycle (`Invitations`, `Invitation`, `PendingInvitation`, `AcceptedInvitation`, `StagedGrant`, `InvitationError`, `InvitationMismatch`, `VerifiedIdentity`, `SubjectPin`; `PasswordResets`; the mail sender protocol and templates `MailSender`, `MailMessage`, `MailTemplate`, `MailKind`, `DEFAULT_TEMPLATES`, `MailError`, `MailDeliveryError`; `ApiKeys`, `ApiKey`, `NewApiKey`, `ApiKeyError`; `Pruner`, `PruneReport`), single sign-on (`SingleSignOn`, `LoginStart`, `ConfigurationReport`, `ConfigurationCheck`, `InvitationAcceptance`, `SSO_FAILURE_MESSAGE`, `SsoSettings`, `SsoSettingsStore`, `SsoSettingsError`, `SsoError`) and `Verification`, the result of `PasswordHasher.verify`. The provider presets stay in `warden.identity.sso.presets`, outside every identity module that signs anyone in. `warden` itself still exports only `__version__` and imports no subpackage (D11); its docstring names the subpackages. `tests/test_public_api.py` pins each public package's `__all__`, so a change to the public surface fails until the snapshot changes in the same commit. Design overview section 4 now describes the layout as built.

- `Users.list(status=None, conn=None)`: every user, oldest first with ties broken by id, optionally only those of one status, and inside a caller's transaction when given `conn`. `GET <admin>/users` now uses it instead of querying the table itself; its response is unchanged.
- A tripwire fails when a warden module imports, or reaches through a module for, another module's underscore-prefixed name. The single sign-on handoff and every sign-in route now build the signed-in body with one internal helper (`warden.identity.routers.tokens.token_body`) instead of the handoff importing the sign-in router's private function; the bodies are unchanged.

### Changed

- `sso.issuer_url` is kept exactly as configured, trailing slash included, in start-up configuration and in run-time settings. 0.1.0a9 removed a trailing slash, so exact issuer equality refused every provider whose issuer ends in `/` (`issuer_mismatch`). The issuer is still validated as before: https only, no credentials, query, fragment, spaces or control characters, checked with `fullmatch`. Discovery still fetches `<issuer without trailing slash>/.well-known/openid-configuration`, and the discovery document's `issuer` and the id_token's `iss` must equal the configured value character for character. Upgrade note: a deployment whose configured issuer differs from the provider's advertised issuer only by a trailing slash (which 0.1.0a9 accepted after stripping it) must configure the issuer exactly as the provider advertises it. Subjects pinned under the stripped form do not match an issuer configured with the slash.
- `sso.client_secret` defaults to `warden.sso.client-secret`, the name single sign-on already used when it was unset, and is no longer required while single sign-on is enabled. Single sign-on reads the name only from configuration. A secret missing from the store is still reported by the configuration test (`client_secret: missing`) and refused at sign-in (`client_secret_missing`). `http.public_base_url` still drops a trailing slash.
- Identity lifecycle's and single sign-on's schema names are defined in `warden.db.schema` and exported from `warden.db`, beside identity's: `SINGLE_USE_TOKENS` (from `warden.identity.single_use`), `INVITATION_GRANTS` (from `warden.identity.invitations`), `API_KEYS` (from `warden.identity.apikeys`), and `SSO_IDENTITIES`, `SSO_LOGIN_TRANSACTIONS`, `SSO_HANDOFF_CODES`, `SSO_TABLES`, `SSO_SETTING` and `SSO_SETTINGS_LOCK_KEY` (from `warden.identity.sso.schema`). The new `LIFECYCLE_TABLES` names lifecycle's three tables. The advisory lock key `0x7761_7264_656E_0201` (single sign-on settings) is recorded in the allocation table, and a test fails on any allocated key the table does not record or any module that repeats a schema name as its own literal. Values are unchanged. Upgrade note: import these names from `warden.db`; the old modules still re-export the same objects for now, but `warden.identity.sso.schema` and `warden.identity.schema` are compatibility shims only.

### Removed

- `warden.identity.sso.service.DEFAULT_CLIENT_SECRET_NAME`. Upgrade note: read the configured name from `config.sso.client_secret`; its default is `SsoConfig().client_secret`.

## [0.1.0a9] - 2026-10-28

Ninth pre-release: the invitation token is sealed in the single sign-on login transaction instead of a separate cookie, and `POST /sso/start` accepts a form or JSON body.

### Changed

- Invitations accepted through single sign-on now keep the token sealed in the login transaction instead of in a second cookie (a change to 0.1.0a8). `POST <auth>/sso/start` seals it with AES-256-GCM under a key derived with HKDF-SHA256 from the browser's login binding (the value in `__Secure-warden-sso`, which the database holds only as a hash), with the transaction's state hash as associated data. So someone who can read the database cannot open it, and a sealed value moved to another transaction does not open there. Neither the token nor its hash is stored in clear. At the callback, after the binding check, the token is opened with the browser's binding; a value that does not open is refused (`invitation_not_bound`, audited) and leaves the invitation usable. No server key is involved, so there is nothing new to configure or rotate.
- `POST <auth>/sso/start` reads `invitation` from a urlencoded form (`application/x-www-form-urlencoded`) or a JSON object (`application/json`), chosen by `Content-Type` (a change to 0.1.0a8, which took a form only). Any other type, or a missing, repeated, mistyped or malformed `invitation` (including a repeated JSON member), lands on the fixed failure as `invitation_malformed` before any transaction is stored. It still answers 303 to the provider, and the token still appears in no URL.
- Migration `7b2e9d4c1f08`, which follows `a6d3f0b8e21c`, replaces the `invitation_hash` column of `warden.sso_login_transactions` with `invitation_sealed` (exactly 71 bytes when set). Neither form can be converted into the other inside the database, so upgrading removes in-flight acceptances that carry a hash and downgrading removes those that carry a sealed token; their browsers land on the fixed failure and can start again. A plain sign-in's transaction is kept. Reversible.

### Removed

- The `__Secure-warden-sso-invitation` cookie, `INVITATION_COOKIE_NAME`, and the `invitation=` parameter of `SingleSignOn.complete()`, all introduced in 0.1.0a8. Upgrade note: a product that drives single sign-on without warden's router passes the invitation token only to `SingleSignOn.begin(invitation=...)`, stops setting and reading the invitation cookie, and calls `complete(...)` without `invitation=` (still with `invitations=`). Nothing here changes the 0.1.0a3 API, which had no invitation acceptance through single sign-on.

## [0.1.0a8] - 2026-10-28

Eighth pre-release: invitations accepted through single sign-on, joining the single sign-on callback to the identity lifecycle's acceptance service, with the live single sign-on suite extended to cover it.

### Added

- Invitation acceptance through single sign-on. The product's accept-invitation screen submits a form to `POST <auth>/sso/start` with the link's token in the field `invitation` (a top-level navigation, `application/x-www-form-urlencoded`, so the token stays out of every URL warden sends); warden answers 303 to the provider. The login transaction records only the token's SHA-256 hash, and the browser holds the token in a second cookie, `__Secure-warden-sso-invitation` (HttpOnly, Secure, SameSite=Lax, path `<auth prefix>/sso`, cleared at the callback). At the callback the cookie must match the transaction's hash; once the provider's identity is verified (`email_verified` true, and the domain in the allowed list), it goes to identity lifecycle's `accept_with_sso`, which requires the invited address (ignoring case) and decides method, status and the single consume. The subject is pinned and the handoff code stored inside the acceptance transaction, so the acceptance, the pin and the sign-in commit together or not at all; the browser lands like any SSO sign-in, and the handoff issues the new user's session with `amr` `["sso"]`. Both `password_and_sso` and `sso_only` invitations accept this way. An identity for another address, a disallowed or unverified email, or a subject already pinned to another user is refused and leaves the invitation usable; a user who is no longer invited is refused and the invitation used up (#154); of concurrent acceptances through single sign-on and a password, exactly one succeeds (#127). New refusal reasons under `warden.identity.sso.sign_in`: `invitation_malformed`, `invitation_not_bound`, `invitation_mismatch`, `invitation_refused` and `already_pinned`; lifecycle records its own reason under `warden.identity.invitation.accepted`.
- `SingleSignOn.begin(invitation=...)` and `SingleSignOn.complete(invitation=..., invitations=...)`, with the `InvitationAcceptance` protocol and `INVITATION_COOKIE_NAME`, for products that drive the flow without warden's router.
- Migration `a6d3f0b8e21c`, which follows `e3a9c5d17f42`, adds the nullable `invitation_hash` column (exactly 32 bytes when set) to `warden.sso_login_transactions`. Reversible.
- Live checks (marked `integration`): an invitation accepted through the stub provider, then a sign-in by subject (`tests/identity/sso/test_sso_invitation_live.py`); and, with the provider stopped, an invitation that fails through single sign-on and completes with a password (`tests/identity/sso/test_sso_break_glass_live.py`).

## [0.1.0a7] - 2026-10-28

Seventh pre-release: external anchoring of the audit chain. Signed head anchors forwarded to the SIEM, `warden audit anchor`, and verification of the chain against anchors exported from it.

### Added

- External anchoring of the audit chain (design D13). `warden.audit.anchor()` appends an ordinary chained row, action `warden.audit.anchor`, whose details carry the committed head (`head_id`, `head_hash`) and the time, signed with warden's Ed25519 key over `"warden.audit.anchor.v1\n" || canonical_json(payload)` with the key id. The syslog forwarder sends it like any row, so a SIEM holds a signed, timestamped head that nobody with only database access can recall. `min_rows=N` writes an anchor only once N rows have been appended since the last one; an empty trail is not anchored; the actor may be at most 64 characters (`MAX_ANCHOR_ACTOR`), so a forwarded anchor always fits the smallest syslog message cap whole. The format is specified in `docs/design/audit-chain.md` section 7.
- `warden.audit.read_anchors()` reads anchors back from a SIEM export, one record per line: NDJSON rows as `warden.audit.export` writes them, or RFC 5424 messages as the forwarder sends them under any SD-ID, with or without an octet count or a collector's prefix. Other lines are skipped; an anchor row whose anchor cannot be read is kept and reported as malformed.
- `warden.audit.verify_anchors()` verifies the chain and checks each external anchor against it in one snapshot, returning an `AnchorReport` that names, by line and `head_id` and never by row contents, an anchor that is malformed, has a bad signature, was signed by a revoked key (retired keys stay valid, through `verify_historical`), whose head row is missing (tail deletion, or rows removed without a checkpoint), or whose head row's hash differs (a rewrite, including one from genesis). An anchor whose head was purged is checked against the earliest valid checkpoint covering it, so anchors survive retention.
- `warden.audit.register_audit_actions()` also registers `warden.audit.anchor`.
- `warden audit anchor [--actor NAME] [--min-rows N]` writes an anchor, for the product's scheduler to run (warden ships none); the application's role is enough. `warden audit verify --anchors FILE` also checks the chain against the anchors in a SIEM export, exits 0 only if the chain verifies and every anchor matches or is covered by a checkpoint, and reports failing anchors by line and head row, never row contents. A connection failure prints the fixed audit message and exits 1; an unreadable anchors file exits 2 and a file without anchors exits 1, neither naming the path.

### Changed

- The audit recorder never truncates an anchor's details, as it already never truncated a retention checkpoint's: either, cut short, could not vouch for the chain.
- The tripwire that keeps warden from reading files or the environment directly now names one exemption: the anchors file an operator passes to `warden audit verify --anchors`, which is input data rather than configuration. A companion test fails unless the exemption matches exactly that one read.

## [0.1.0a6] - 2026-10-28

Sixth pre-release: OIDC single sign-on. The authorisation code flow with PKCE, cached discovery and JWKS, id_token validation with pyjwt, subject pinning for pre-provisioned users, run-time settings and administration routes, and a stub identity provider for live checks.

### Added

- OIDC single sign-on (`warden.identity.sso`), one provider per deployment. `Identity` builds a `SingleSignOn` as `identity.sso`; the product mounts `identity.sso_router()` under its auth prefix and `identity.sso_settings_router(authorise=...)` under its admin prefix.
- Discovery cached for `sso.discovery_cache_seconds`, whose `issuer` must equal the configured issuer exactly (no case folding, trailing-slash tolerance or prefix match), with every endpoint on https. The provider's JWKS is cached for `sso.jwks_cache_seconds`; a token naming an unknown key id forces a refetch at most once every `sso.jwks_refetch_min_seconds`. Only asymmetric signing keys are kept.
- The authorisation code flow with PKCE (S256), state and nonce. `GET /sso/start` stores a login transaction bound to a random value in an HttpOnly, Secure, SameSite=Lax cookie (`__Secure-warden-sso`, path `<auth prefix>/sso`) and sends the browser to the provider. `GET /sso/callback` uses the transaction up with one guarded write that also checks the cookie, redeems the code with the verifier, validates the id_token, matches the account, and sends the browser to `http.sso_completion_link` with only a one-time handoff code (`?code=`). The product's screen posts it with the cookie to `POST /sso/handoff` and gets the session's tokens in the response body, in the same shape as password sign-in. No token, verifier or secret ever appears in a URL, and the redirects carry `Referrer-Policy: no-referrer`.
- id_token validation with pyjwt: the algorithm must be in `sso.allowed_algorithms` and in the provider's advertised set, never `none` or HS*; the key comes from the JWKS by key id and is used only with its own algorithm; `iss`, `aud`, `azp` (required to be the client when there are several audiences, and checked whenever present), `exp` and `iat` (within `sso.clock_skew_seconds`) and `nonce` are each checked.
- Account matching for pre-provisioned users only. The first sign-in matches a verified email (`email_verified` must be `true`), ignoring case, and pins the provider's (issuer, subject) to the user; later sign-ins match by subject, and the email must still agree. A disagreeing subject or email is refused and audited. `sso.allowed_email_domains` is checked on every sign-in, and users who are not active (including invited users) get nothing. Two first sign-ins racing for one user pin one subject.
- Sessions issued through identity's session issuance with `amr` `["sso"]`, recorded as `warden.identity.sign_in`. Single sign-on never asks for a second factor, so `require_mfa`'s forced TOTP enrolment applies to password sign-in only.
- Run-time single sign-on settings. `sso.*` configuration supplies the defaults; an administrator may override `enabled`, `issuer_url`, `client_id`, `scopes`, `allowed_email_domains` and `provider_preset`, stored in `warden.settings` and validated by the configuration's rules. Turning single sign-on off ends every SSO session in the same transaction, and an advisory lock (`SSO_SETTINGS_LOCK_KEY`, 0x...0201) between that change and session issuance means no SSO session survives a concurrent disable.
- Administration routes: `GET` and `PUT /sso/settings`, `POST /sso/settings/reset`, `PUT /sso/client-secret` (written to konfig's secrets store under the name in `sso.client_secret`, default `warden.sso.client-secret`, and never returned), `POST /sso/test` (checks the settings, client secret, discovery, shared algorithms and JWKS; it signs nobody in and redeems nothing), and `DELETE /sso/users/{user_id}/pin`. The settings show the derived callback URI and setup guidance for each preset.
- Provider presets (`entra`, `google`, `okta`, `generic`) are labels for setup guidance only; a tripwire test fails if any identity module that signs anyone in reads the preset.
- Every refusal reaches the browser as the same redirect (`?error=sso_failed`; show `SSO_FAILURE_MESSAGE`), and a refused handoff gets the uniform 401. The reason is recorded only in the audit trail, as `warden.identity.sso.sign_in`. Other actions: `warden.identity.sso.subject_pinned`, `subject_unpinned`, `settings_changed`, `disabled`, `client_secret_set` and `configuration_tested`.
- `identity.sso.prune()` removes expired login transactions and handoff codes.
- Migration `e3a9c5d17f42`, which follows `c4a8e1f2d7b5`, creates `warden.sso_identities`, `sso_login_transactions` and `sso_handoff_codes`. Reversible.
- Runtime dependency `pyjwt[crypto]` (MIT), from the agreed set, for id_token validation.
- A stub OIDC provider for development workstations: navikt mock-oauth2-server (MIT) over TLS behind the sandbox's `idp` profile, published on loopback only, with its keystore written by `tests/identity/sso/live/make_certs.py`. Not part of the package.
- Live single sign-on checks against it (marked `integration`): the round trip (sign-in, a forged subject, a forged email and a disallowed domain refused) in `tests/identity/sso/test_sso_live.py`, and break-glass password sign-in with the provider stopped in `tests/identity/sso/test_sso_break_glass_live.py`.

### Changed

- `httpx` (BSD-3-Clause) is now a runtime dependency, used to reach the identity provider; it was a development dependency only. Its CA bundle `certifi` (MPL-2.0) is a named licence exception.

## [0.1.0a5] - 2026-10-28

Fifth pre-release: the identity lifecycle. Single-use tokens, invitations with a generic acceptance service, password reset, mail through a product-supplied sender, scoped API keys, administration routes and pruning.

### Added

- Identity lifecycle (milestone M4). `Identity` takes an optional `mail_sender` and gains `mailer`, `single_use`, `invitations`, `resets`, `api_keys` and `pruner`, with `prune()`, `pruning()`, `lifecycle_router()` and `admin_router()`.
- Single-use tokens (`warden.identity.single_use`) for invitation and password reset links: 32 random bytes, stored only as a SHA-256 hash, expiring, and used up by one guarded `UPDATE`, so of any number of concurrent submits exactly one succeeds (Termograph #127). `lock_live()` reads a live token under a row lock for decisions taken before the consume.
- Invitations (`identity.invitations`). `create()` writes a user in the `invited` status with no password, stages role grants (each optionally expiring; an administrator role cannot expire), issues an invitation link and mails it in one transaction, so a failed delivery leaves no user, grant or link behind. `resend()` mails a new link, revokes the old one and keeps the staged grants; if the mail fails the old link still works. `revoke()` deletes the invited user with one guarded `DELETE`, so it can never remove a user who accepted concurrently (#129). `pending()` lists invited users with their link's expiry and staged grants.
- Invitation acceptance is one service function with two entry points. `accept_with_password(token, password)` sets the password; `accept_with_sso(token, VerifiedIdentity(issuer, subject, email), pin=...)` takes an identity the caller has already verified with the identity provider, requires its email to be the invited address (ignoring case), and pins the subject through the caller's `pin(conn, user_id, issuer, subject)` inside the acceptance transaction. Under row locks on the user and then the link, a method mismatch (a password for an `sso_only` user, or another address) is refused before the link is touched and leaves it usable (`InvitationMismatch`); a user no longer in the invited status is refused and the link used up (#128, #154); otherwise the link is consumed, the user activated and the staged grants applied. Every outcome is audited under `warden.identity.invitation.*`.
- Password reset by emailed link (`identity.resets`). `request(email)` mails a single-use link to an active user who signs in with a password, revoking earlier links; for an unknown address, an `sso_only` user or an inactive user it sends nothing and records why in the audit trail. `complete(token, new_password)` sets the password and ends every session of the user; a link whose user has since become inactive or `sso_only` is refused and spent.
- Mail (`warden.identity.mail`): a `MailSender` protocol the product implements, and warden's invitation, password reset and MFA-enrolled messages as `string.Template` templates with plain-text and HTML parts. A product replaces them one at a time with `MailTemplate` attributes (`INVITATION`, `PASSWORD_RESET`, `MFA_ENROLLED`) of the module named by `mail.template_package`; every template is checked at start-up and may use only its own placeholders. Values have control characters replaced and are HTML-escaped in the HTML part. Expiry times are rendered from the link's own stored expiry, in UTC to the minute. A sender that raises is reported as `MailDeliveryError`, without the sender's detail. The MFA-enrolled notice is sent after an enrolment is confirmed; a failed delivery is logged and never undoes the enrolment.
- API keys (`identity.api_keys`): `<identity.api_key_prefix>` plus 32 random bytes, shown once and stored as a SHA-256 hash with a short hint; expiring within `identity.api_key_max_lifetime_days` (default: the maximum); revocable; scoped to registered permissions the user holds when the key is created. `require_user` and `require_permission` accept a key as a bearer token, with permissions equal to its scopes intersected with the user's current permissions, so a key never exceeds its user, and refuse it once the user is not active (#132). Every refusal is the uniform 401; the reason is audited as `warden.identity.api_key.authenticate`. `Principal.api_key_id` names the key (None for an access token); the session routes (sign-out, change password) accept access tokens only.
- Public lifecycle routes (`identity.lifecycle_router()`, mounted under the auth prefix): `POST /invitations/accept`, `POST /password-reset` (always 202, answered before the work is done, so neither the response nor its timing reveals whether an account exists) and `POST /password-reset/complete`.
- Administration routes (`identity.admin_router(permission=..., roles=..., invitations=..., api_keys=...)`, mounted under the admin prefix): users (list, show, status, sign-in method, send a reset link), roles (list, assign with optional expiry, revoke), invitations (list, create, resend, revoke) and API keys (list, create, revoke). Each area requires a permission the product names; every change is audited under `warden.identity.*` with the administrator as actor.
- Pruning (#134): `identity.prune()` deletes expired refresh tokens, single-use tokens and MFA challenges and ended sign-in throttle windows, returning a `PruneReport`; `identity.pruning(every_seconds=...)` runs it on a schedule for a block such as the product's lifespan. A used refresh token is kept until it expires, so reuse detection still works.
- Migration `c4a8e1f2d7b5`, which follows `b7e14a2c9d30`, creates `warden.single_use_tokens`, `warden.invitation_grants` and `warden.api_keys`. Reversible.

## [0.1.0a4] - 2026-10-28

Fourth pre-release: the shared contracts wave 2 builds on. Identity resolves the client address through the trusted proxies; shared lock keys and names move into `warden.db`; the configuration declares every forwarder, identity and wave 2 setting; warden's own audit actions live under `warden.`; the syslog SD-ID defaults to `warden@67382`; and the licence policy distinguishes strong from weak copyleft.

### Added

- A worktree recipe (`dev/worktree.json`) and sandbox Compose template (`dev/sandbox-compose.yml`) for development workstations: a development Postgres for manual checks, and the live syslog collector from `tests/syslogfwd/live` behind the `syslog` profile, each published on loopback only. Not part of the package.
- Lock keys and shared names in `warden.db` (`warden.db.schema`): `CHAIN_LOCK_KEY`, `ADMINISTRATOR_LOCK_KEY`, `POLICY_SETTING`, `POLICY_CHANNEL`, identity's table names and `IDENTITY_TABLES`. The schema module's docstring publishes the advisory lock key allocation (0x...00xx db and audit, 0x...01xx identity, 0x...02xx single sign-on), and a test scans every `*_LOCK_KEY` in `src/warden` and fails on a collision or a key outside the table. The old import locations (`warden.audit.chain`, `warden.identity.roles`, `warden.identity.policy`, `warden.identity.schema`) keep working.
- `SyslogConfig` carries every forwarder setting, mirroring `SyslogSettings`: `hostname`, `facility`, `max_message_bytes`, `start_from`, `grace_seconds`, `poll_seconds`, `standby_retry_seconds`, `batch_size`, `connect_timeout_seconds`, `send_timeout_seconds`, `backoff_initial_seconds`, `backoff_max_seconds`, and `tls_ca_secret` (the name of a konfig secret holding the collector's CA certificates). Each is validated at start-up. `SyslogSettings.from_config(config, secrets=...)` carries every field and reads `tls_ca_secret` through `secrets`; a test fails if a `SyslogSettings` field has no `SyslogConfig` counterpart.
- `IdentityConfig` fields for values identity hard-coded in 0.1.0a3, with those values as defaults: `totp_issuer` (default: the host of `http.public_base_url`), `mfa_challenge_ttl_seconds` (300), `mfa_max_failures` (5), `recovery_code_count` (10), `policy_cache_seconds` (30), `sign_in_attempt_limit` (10), `sign_in_window_seconds` (900), `totp_key_secret` (`warden.totp-key`) and `totp_previous_key_secret` (`warden.totp-key.previous`). `Identity` reads them; its `policy_max_age`, `sign_in_attempt_limit` and `sign_in_window_seconds` arguments now default to None and override the configuration only when given.
- Configuration the 0.1.0 single sign-on, identity lifecycle and mail work will use, declared now and provisional until 0.1.0b1: `identity.api_key_prefix` and `identity.api_key_max_lifetime_days`; `mail.template_package` and `mail.subject_prefix`; `sso.jwks_cache_seconds`, `sso.jwks_refetch_min_seconds`, `sso.login_transaction_ttl_seconds`, `sso.handoff_code_ttl_seconds`, `sso.allowed_algorithms` (default RS256, ES256 and PS256; only asymmetric algorithms, never `none` or HS*) and `sso.clock_skew_seconds`. Each is validated at start-up.
- `warden.config.COGNISN_PEN` (`67382`), Cognisn's IANA Private Enterprise Number, and `DEFAULT_SD_ID` (`warden@67382`) derived from it; `warden.config.MIN_RETENTION_DAYS` (365), no longer provisional.
- Dependabot (`.github/dependabot.yml`) proposes updated commit SHAs for the pinned GitHub Actions weekly, in the pinned form the pinned-actions tripwire accepts.

### Changed

- Identity takes the client address from the trusted-proxy resolver (`warden.proxy.resolve_client_ip` with `audit.trusted_proxies`) for audit records and the sign-in throttle key. Behind a reverse proxy it previously saw the proxy's address, so clients sharing a proxy shared one throttle count per identifier. `X-Forwarded-For` from a peer that is not a trusted proxy is ignored. Upgrade note: `warden.identity.http.client_ip()` now takes the trusted proxy networks as a second argument.
- The syslog SD-ID defaults to `warden@67382`, from Cognisn's registered enterprise number (design D12), in `SyslogConfig.sd_id` and `SyslogSettings.sd_id`. A product may still set any valid SD-ID; the documentation number 32473 is still refused. Start-up validation no longer requires `syslog.sd_id` when syslog is enabled. Upgrade note: a deployment that relied on `sd_id` being required now forwards with `warden@67382` unless it sets its own; update SIEM rules that match on the SD-ID.
- `audit.retention_days` defaults to None, keeping the audit trail for ever, and any value set must be at least 365 days; a lower value fails at start-up naming the field. Upgrade note: a configuration with a shorter period, which `warden audit purge` already refused, now fails when the configuration is loaded.
- `sso.client_secret` is the name of the konfig secret holding the OIDC client secret, not the secret itself (provisional until 0.1.0b1). Upgrade note: replace a value or `secret://` reference with the secret's name.
- Every audit action warden registers lives under `warden.`: identity's actions are renamed from `identity.*` to `warden.identity.*` (for example `warden.identity.sign_in`); `warden.audit.*` and `warden.syslog.test_sent` are unchanged. `ActionRegistry.register()` refuses a product action in the `warden.` namespace, so a product can neither shadow nor pre-empt one of warden's actions; warden registers its own through an internal path. Upgrade note: SIEM rules, filters and queries that match `identity.*` actions must match `warden.identity.*`; rows already recorded keep their old names. A product action named `warden.*` must be renamed.
- Licence policy: no strong copyleft (GPL, AGPL, SSPL, EUPL, OSL) in runtime dependencies, even as a named exception; weak copyleft (LGPL, MPL) only as a named, reviewed exception for an unmodified, separately installed package. `scripts/licence_audit.py` names psycopg (LGPL-3.0) and certifi (MPL-2.0, which httpx needs for single sign-on), each with its reason, and refuses any other copyleft package.
- The design overview records the rulings of October 2026: the enterprise number, audit retention, checkpoint anchoring in 0.1.0, syslog mutual TLS deferred, the `warden.` action namespace, the refused sign-in identifier and the licence policy.

### Removed

- `SyslogConfig.queue_size`, unused since forwarding moved to committed rows. Upgrade note: remove `syslog.queue_size` from the configuration; an unknown key fails at start-up.

### Fixed

- `warden keys rotate` no longer prints a traceback when it cannot reach the database. It prints a fixed message, without the host, database or user, and exits with code 1.

## [0.1.0a3] - 2026-10-26

Third pre-release: wave 1. The hash-chained audit trail with verification, retention, query, export and append-only grants; syslog forwarding from committed rows; and the identity core.

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
