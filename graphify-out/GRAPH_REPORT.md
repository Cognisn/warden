# Graph Report - warden  (2026-11-24)

## Corpus Check
- 347 files · ~375,057 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 7441 nodes · 24472 edges · 232 communities (211 shown, 21 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2174 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `f8ff2e61`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- httpx
- SyslogSettings
- FakeIdp
- AuditEvent
- record_audit
- KeyStore
- RecordingSender
- PasswordResets
- AuditRecorder
- h
- test_webauthn_mfa.py
- contract.py
- password_admin.py
- build_sso_settings_router
- test_audit_recorder.py
- test_webauthn_reset.py
- WebAuthn
- test_console_password_policy.py
- Database
- PasswordPolicies
- sso/service.py
- Invitations
- WebAuthnError
- anchor.py
- PasswordEnforcement
- UserError
- test_config_webauthn.py
- test_audit_chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- .update
- CI Workflows
- test_console_browser.py
- ActionRegistry
- client_ip
- test_identity_passwords.py
- test_syslog_forwarder.py
- rules.py
- current_code
- test_syslog_transport.py
- test_password_sign_in.py
- SyslogForwarder
- build_admin_router
- test_sso_sealing.py
- alembic
- WardenConfig
- test_webauthn_authentication.py
- test_audit_retention.py
- Cluster: syslog
- Mfa
- identity_support.py
- User
- test_distributions.py
- test_config_fields.py
- warden/cli.py
- soft_authenticator.py
- mail.py
- test_console_passkeys.py
- export_openapi.py
- typing
- PasswordStates
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- audit_rows
- current_revision
- test_sso_live.py
- webauthn_live_support.py
- PolicyStore
- test_identity_dependencies.py
- test_passkey_registration_link.py
- test_password_watch_lists.py
- test_password_feedback.py
- console_support.py
- test_password_admin_routes.py
- PolicySettings
- SignInMethod
- test_identity_admin_routes.py
- test_webauthn_migration.py
- hashlib
- test_key_publication.py
- test_sso_capabilities.py
- audit/__init__.py
- test_openapi_contract.py
- test_identity_migration.py
- test_sso_migration.py
- test_identity_sign_in.py
- test_sso_admin_routes.py
- Client-behaviour guide
- Cluster: warden design overview
- modules
- webauthn/service.py
- webauthn/challenges.py
- test_audit_verify.py
- main
- attestation.py
- test_db_schema.py
- totp.py
- test_sign_in_methods_sso.py
- test_sso_preset_label_only.py
- sys
- identity/__init__.py
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- make_user
- test_audit_source_ip_tripwire.py
- test_identity_lifecycle_routes.py
- password_policy/__init__.py
- new_totp_key
- check_dist.py
- test_cli.py
- Cluster: Audit hash chain specification
- test_sso_source_ip.py
- collector.py
- identity/conftest.py
- test_audit_grants.py
- grants.py
- Cluster: with
- config.py
- test_sso_issuer.py
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- publish.yml
- test_syslog_sd_id.py
- keys.py
- test_lifecycle_migration.py
- test_bump_version.py
- Sessions
- test_password_policy_migration.py
- test_password_set_points.py
- MemorySecrets
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- test_mfa_factors_webauthn.py
- pathlib
- sign_in_settings.py
- dependencies.py
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- test_password_cli.py
- SsoSettingsStore
- test_webauthn_live.py
- test_console_capabilities.py
- test_no_direct_environment.py
- Cluster: updates
- LiveBrowser
- test_a_purge_committing_during_verification_breaks_nothing
- test_audit_source_ip_routes.py
- test_identity_capabilities.py
- test_audit_router.py
- ceremony.js
- PasswordHistory
- Cluster: verify
- test_sign_in_methods_migration.py
- console/cli.py
- Cluster: rsyslog
- test_password_hibp.py
- Identity
- test_licence_audit.py
- test_console_gaps.py
- .register
- StreamCollector
- PasswordsConfig
- Cluster: examples/__init__.py
- test_browser_rules_vectors.py
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- test_cli_audit.py
- test_cli_audit_errors.py
- passwordrules.js
- BuiltinList
- test_config_passwords.py
- pytest
- test_console_source_ip.py
- test_sso_setup_guides.py
- password_support.py
- presets.py
- licence_audit.py
- throttle.py
- test_identity_key_publication.py
- test_cli_errors.py
- resolve_client_ip
- .connection
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- set_default
- _LazySecrets
- race
- resolve
- SsoSettings
- test_identity_totp_storage.py
- run_vectors.mjs
- build_console
- test_dependabot.py
- test_public_api.py
- warden sample console
- test_audit_chain_migration.py
- Single sign-on setup guides
- test_password_wiring.py
- keys_router
- AuditRow
- KonfigSecrets
- effective_method_sql
- test_database.py
- MemorySecrets
- The built-in common-password list
- .__init__
- .prune
- _Abort
- test_tls_fail_closed.py
- test_failed_sign_in_timing_is_unchanged_by_the_passwords_state
- test_readme.py
- console/__init__.py
- warden_audit
- warden_audit_router
- warden_audit_syslog
- warden_db
- warden_identity
- warden_identity_crypto
- warden_identity_http
- warden_identity_mail
- warden_identity_sso_provider
- warden_identity_sso_service
- warden_identity_webauthn
- .name
- .loose_text
- .see

## God Nodes (most connected - your core abstractions)
1. `Identity` - 746 edges
2. `Database` - 698 edges
3. `audit_rows()` - 239 edges
4. `RecordingSender` - 201 edges
5. `KeyStore` - 176 edges
6. `ActionRegistry` - 138 edges
7. `FakeIdp` - 135 edges
8. `AuditRecorder` - 134 edges
9. `AuditEvent` - 126 edges
10. `User` - 121 edges

## Surprising Connections (you probably didn't know these)
- `test_conflicting_registration_fails()` --calls--> `ActionRegistry`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/registry.py
- `test_registration_is_idempotent_for_an_identical_spec()` --calls--> `ActionRegistry`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/registry.py
- `test_summary_template_may_use_only_event_fields()` --calls--> `ActionRegistry`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/registry.py
- `test_unknown_action_lookup_fails()` --calls--> `ActionRegistry`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/registry.py
- `test_every_forwarder_setting_has_a_config_counterpart()` --uses--> `SyslogConfig`  [INFERRED]
  tests/test_config_fields.py → src/warden/config.py

## Import Cycles
- 3-file cycle: `src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/apikeys.py`
- 3-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 5-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`

## Hyperedges (group relationships)
- **Audit tamper-evidence mechanisms** — docs_design_audit_chain_audit_hash_chain, docs_design_audit_chain_retention_checkpoint, docs_design_audit_chain_anchor, docs_design_audit_chain_audit_database_roles, docs_design_overview_tamper_evidence [EXTRACTED 1.00]
- **Release and publication pipeline** — docs_releasing_bump_version, github_workflows_publish, docs_releasing_check_dist, docs_releasing_trusted_publishing, claude_integration_procedure [EXTRACTED 1.00]
- **Tripwire tests guarding architecture rules** — docs_design_overview_single_audit_writer, docs_design_overview_audit_independence, examples_console_readme_public_surface_tripwire, claude_mutation_checked_guards [INFERRED 0.85]

## Communities (232 total, 21 thin omitted)

### Community 0 - "httpx"
Cohesion: 0.05
Nodes (127): httpx, assert_refused(), expire_challenge_of(), give_passkey(), http_client(), passkey_app(), passkey_assertion(), passkey_authenticator() (+119 more)

### Community 1 - "SyslogSettings"
Cohesion: 0.04
Nodes (48): DatagramTransport, errno, socket, _local_hostname(), BaseModel, field_validator, Settings for the syslog forwarder. ``SyslogConfig`` in ``warden.config``…, This host's name, reduced to what an RFC 5424 HOSTNAME may carry. (+40 more)

### Community 2 - "FakeIdp"
Cohesion: 0.04
Nodes (85): jwt, jwt_algorithms, jwt_exceptions, Exception, Single sign-on refusals. ``SsoError.reason`` is a fixed category, recorded in…, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic() (+77 more)

### Community 3 - "AuditEvent"
Cohesion: 0.06
Nodes (29): AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., ActionSpec, _check_summary(), A registered action: dotted name, severity and summary template., The one-line summary for ``event``; absent fields render as ``-``., Register a product action. Re-registering an identical spec is a no-op. Actions… (+21 more)

### Community 4 - "record_audit"
Cohesion: 0.03
Nodes (72): Record ``event`` through the installed recorder. See ``AuditRecorder.record``., record_audit(), Principal, The signed-in user behind a request. For a request made with an API key,…, AuthenticationRefused, A credential was refused. ``reason`` is for the audit trail and tests only. It…, _Account, _ChangeDue (+64 more)

### Community 5 - "KeyStore"
Cohesion: 0.06
Nodes (52): KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., KeyStore, KeyStoreError, Any, AsyncConnection, Composable, Exception (+44 more)

### Community 6 - "RecordingSender"
Cohesion: 0.07
Nodes (72): A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, The product's mail sender, recording instead of sending. ``fail`` makes it…, RecordingSender, _accept(), FakePins (+64 more)

### Community 7 - "PasswordResets"
Cohesion: 0.18
Nodes (16): _Account, _Checked, PasswordResets, Any, AsyncConnection, NoReturn, SourceIp, UUID (+8 more)

### Community 8 - "AuditRecorder"
Cohesion: 0.12
Nodes (61): AnchorRecord, ExternalAnchor, An anchor written to the trail, and the id of the row that carries it., An anchor found in an export: its line, its own row id when known, and the…, AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors() (+53 more)

### Community 9 - "h"
Cohesion: 0.08
Nodes (128): apiKeysScreen(), capabilities(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames() (+120 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.12
Nodes (70): _amr(), _app(), _assertion(), _bearer(), _challenge(), http(), _key_sign_in(), _options() (+62 more)

### Community 11 - "contract.py"
Cohesion: 0.03
Nodes (173): fastapi_responses, MfaError, Exception, An MFA enrolment change was refused. Messages carry identifiers only., InvitationMismatch, The invitation is valid but was accepted the wrong way; it stays usable.…, FreshSecondFactorRequired, LastSecondFactorError (+165 more)

### Community 12 - "password_admin.py"
Cohesion: 0.06
Nodes (99): AffectedUsersProposalBody, BuiltinListBody, PasswordPolicyCreateBody, PasswordPolicyOrderBody, PasswordPolicyPinBody, PasswordPolicyPriorityBody, PasswordPolicyRoleBody, PasswordPolicyUpdateBody (+91 more)

### Community 13 - "build_sso_settings_router"
Cohesion: 0.13
Nodes (21): build_sso_settings_router(), actor_id(), display_name(), get_settings(), get_setup_guide(), guide(), put_client_secret(), put_settings() (+13 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.14
Nodes (31): Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any (+23 more)

### Community 15 - "test_webauthn_reset.py"
Cohesion: 0.19
Nodes (24): _admin(), _bearer(), http(), Any, AsyncClient, fixture, MonkeyPatch, Response (+16 more)

### Community 16 - "WebAuthn"
Cohesion: 0.11
Nodes (60): fido2_utils, The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, WebAuthn, One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, LogCaptureFixture, parametrize, UserFactory (+52 more)

### Community 17 - "test_console_password_policy.py"
Cohesion: 0.11
Nodes (37): bearer(), admin_token(), new_policy(), _passwords_source(), Any, AsyncClient, The sample console's password policy support: routes, the development clock,…, Every (method, path) a screen sends to a warden router, path parameters as… (+29 more)

### Community 18 - "Database"
Cohesion: 0.13
Nodes (58): Body, Database, warden's handle on the product's connection pool., accept(), acceptance_rows(), app(), _bodies(), config() (+50 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.08
Nodes (48): PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, ValueError, A password policy, or a change to one, was refused., No password policy has that id., The change clashes with the stored state: a stale version, a name or priority…, Delete history beyond the largest count any policy keeps; returns how many. (+40 more)

### Community 20 - "sso/service.py"
Cohesion: 0.06
Nodes (42): Single sign-on's subject pinning, run inside the acceptance transaction.…, SubjectPin, _challenge(), ConfigurationCheck, ConfigurationReport, _hash(), InvitationAcceptance, LoginStart (+34 more)

### Community 21 - "Invitations"
Cohesion: 0.08
Nodes (36): Complete, Method, MethodCheck, AcceptedInvitation, Invitation, InvitationError, Invitations, check() (+28 more)

### Community 22 - "WebAuthnError"
Cohesion: 0.13
Nodes (21): PublicKeyCredentialDescriptor, Exception, A WebAuthn ceremony or credential change was refused. ``user_id`` and…, Whether the refusal reports a credential that may have been copied., WebAuthnError, _parse(), Any, AsyncConnection (+13 more)

### Community 23 - "anchor.py"
Cohesion: 0.06
Nodes (63): base64, binascii, cryptography_hazmat_primitives_asymmetric_ed25519, Anchor, AnchorSigner, _b64url(), _b64url_decode(), _from_ndjson() (+55 more)

### Community 24 - "PasswordEnforcement"
Cohesion: 0.06
Nodes (33): SetPlace, AcceptedPassword, _match_details(), PasswordEnforcement, PasswordFailure, Any, AsyncConnection, datetime (+25 more)

### Community 25 - "UserError"
Cohesion: 0.11
Nodes (22): check_email(), Any, AsyncConnection, Composable, datetime, Exception, SourceIp, UUID (+14 more)

### Community 26 - "test_config_webauthn.py"
Cohesion: 0.11
Nodes (36): _certificate(), _parse(), Any, parametrize, Start-up validation of the WebAuthn settings (rulings P2, P3 and P7 of 6…, _refused(), _Secrets, test_a_malformed_passkey_registration_link_is_refused() (+28 more)

### Community 27 - "test_audit_chain.py"
Cohesion: 0.07
Nodes (45): JsonValue, address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields(), _number() (+37 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.10
Nodes (46): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+38 more)

### Community 29 - "test_config.py"
Cohesion: 0.11
Nodes (48): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, FakeSecrets, FakeSettings, _load(), Any, parametrize (+40 more)

### Community 30 - "json_response"
Cohesion: 0.08
Nodes (77): json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), build_auth_router(), begin_enrolment() (+69 more)

### Community 31 - ".update"
Cohesion: 0.17
Nodes (15): _plain(), Any, AsyncConnection, SourceIp, Who would be locked out without single sign-on, as the refusal; None if nobody., End every live session issued through single sign-on. Returns how many ended., The effective settings, read now on ``conn`` (no cache)., Override some fields: validated as a whole, audited, and, when this turns… (+7 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_console_browser.py"
Cohesion: 0.13
Nodes (20): code_for(), ConsoleBrowser, enrol_authenticator(), forced(), open_console(), plain(), Any, fixture (+12 more)

### Community 34 - "ActionRegistry"
Cohesion: 0.04
Nodes (105): IntEnum, The audit actions warden's own audit subsystem records., Register warden's audit actions. Idempotent., register_audit_actions(), _now(), datetime, The audit event model., Event severity, numbered as RFC 5424 syslog severities. (+97 more)

### Community 35 - "client_ip"
Cohesion: 0.10
Nodes (31): client_ip(), Network, Request, SourceIp, The client address, for audit events and the sign-in throttle key. Resolved by…, HandoffBody, A new session. Every route that issues one answers with this body., A new session after a forced enrolment, with the recovery codes, shown once. (+23 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.13
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.20
Nodes (39): ForwarderFactory, _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader() (+31 more)

### Community 38 - "rules.py"
Cohesion: 0.06
Nodes (75): Each rule's result and any watch-list match. Never history; stores and audits…, _bool(), _classes(), _detail_tokens(), evaluate(), _int(), _local_part(), _longest_run() (+67 more)

### Community 39 - "current_code"
Cohesion: 0.08
Nodes (58): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), identity_code(), The current code by the Identity's own clock (a test may have moved it)., _challenge() (+50 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.17
Nodes (32): frame(), open_transport(), Connect to the collector named in ``settings``; ``TransportError`` on failure., Frame ``message`` for a stream transport (RFC 6587)., Authority, authority(), _hostile_record(), Any (+24 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.17
Nodes (40): http(), _amr(), _complete(), identity(), _legacy_password(), _password_step(), Any, AsyncClient (+32 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.09
Nodes (16): Any, AsyncConnection, Task, Begin competing for the forwarder lock and, once held, forwarding., Stop forwarding, release the lock and close the transport. Idempotent., Switch to new settings; the next send opens a transport with them. Waits for an…, Try for the lock; lead until stopped or the session ends. True if it led., Read every notification as it arrives, so Postgres' queue never backs up. (+8 more)

### Community 43 - "build_admin_router"
Cohesion: 0.15
Nodes (41): _api_key(), _assignment(), build_admin_router(), assign_role(), capabilities(), create_key(), invite(), list_invitations() (+33 more)

### Community 44 - "test_sso_sealing.py"
Cohesion: 0.15
Nodes (26): cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's…, The token sealed in ``sealed``, or None if it does not open to one. (+18 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (12): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+4 more)

### Community 46 - "WardenConfig"
Cohesion: 0.16
Nodes (18): get_recorder(), _dsn(), warden's whole configuration: one object, validated once at start-up., WardenConfig, ``secrets`` is konfig's secrets store. It must hold the TOTP encryption key…, Identity lifecycle: mail, single-use tokens, invitations, password reset, API…, parametrize, Session policy: defaults from configuration, audited changes, cross-replica… (+10 more)

### Community 47 - "test_webauthn_authentication.py"
Cohesion: 0.17
Nodes (36): _enrolled(), Any, parametrize, UserFactory, UUID, Signing in with a passkey or security key: known-user and discoverable…, _refused(), test_a_counter_that_does_not_increase_is_a_suspected_clone() (+28 more)

### Community 48 - "test_audit_retention.py"
Cohesion: 0.12
Nodes (41): purge(), Exception, A purge was refused. The message carries row ids only., Delete audit rows older than ``retention_days`` behind a signed checkpoint., RetentionError, Verify the chain, from its first surviving row to ``through_id`` (or the head)., verify_chain(), Any (+33 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Mfa"
Cohesion: 0.11
Nodes (25): Challenge, _hash_token(), Mfa, Any, AsyncConnection, ChallengePurpose, SecondFactor, SourceIp (+17 more)

### Community 51 - "identity_support.py"
Cohesion: 0.06
Nodes (83): DB, age_sessions(), complete_sign_in(), direct_session(), enrol_totp(), fresh_totp_code(), UUID, Helpers shared by identity tests (imported as ``identity_support``). (+75 more)

### Community 52 - "User"
Cohesion: 0.10
Nodes (75): User, callback(), completion(), handoff(), provider_code(), Any, AsyncClient, Response (+67 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.13
Nodes (33): dist(), _load(), _only(), fixture, ModuleType, MonkeyPatch, parametrize, Path (+25 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.13
Nodes (30): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+22 more)

### Community 55 - "warden/cli.py"
Cohesion: 0.08
Nodes (48): BinaryIO, sqlalchemy_exc, AnchorError, Exception, An anchor could not be written. The message carries identifiers only., AnchorReport, The chain's own verification, and each external anchor checked against it., VerificationReport (+40 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.11
Nodes (28): CoseKey, cryptography_hazmat_primitives_asymmetric, cryptography_x509_oid, fido2, fido2_cose, ca(), make_webauthn(), factory() (+20 more)

### Community 57 - "mail.py"
Cohesion: 0.06
Nodes (54): Scope, with_headers(), html, Receive, Send, MailConfig, Mail settings. The product implements the sender., _check() (+46 more)

### Community 58 - "test_console_passkeys.py"
Cohesion: 0.16
Nodes (30): authenticator(), key_session(), A software authenticator that makes passkeys: discoverable, verifying the user., An access token for a user holding no second factor, as if signed in with a key., amr(), browser(), link_token(), outbox_message() (+22 more)

### Community 59 - "export_openapi.py"
Cohesion: 0.09
Nodes (24): build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), Any, AsyncConnection (+16 more)

### Community 60 - "typing"
Cohesion: 0.05
Nodes (76): asyncio, collections_abc, contextlib, csv, dataclasses, decimal, io, ipaddress (+68 more)

### Community 61 - "PasswordStates"
Cohesion: 0.06
Nodes (55): ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID, Forced-change challenges (ruling PW9). After a correct password and the second…, Use the challenge up; False if another request already did, or it lapsed. (+47 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.16
Nodes (23): _app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory (+15 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.08
Nodes (21): PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role, fixture, parametrize (+13 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.25
Nodes (13): ASGI middleware setting ``scope["client"]`` to the resolved client address., TrustedProxyMiddleware, _App, _noop(), Any, Trusted-proxy middleware: forwarded headers are believed only from configured…, One gate: only X-Forwarded-For, never Forwarded or X-Real-IP., _scope() (+5 more)

### Community 65 - "audit_rows"
Cohesion: 0.07
Nodes (51): audit_rows(), No password, digest, digest prefix or fingerprint reaches the audit trail, a…, app(), config(), Any, AsyncClient, FastAPI, fixture (+43 more)

### Community 66 - "current_revision"
Cohesion: 0.08
Nodes (43): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), current_revision(), downgrade(), heads() (+35 more)

### Community 67 - "test_sso_live.py"
Cohesion: 0.15
Nodes (25): os, accept_through_sso(), AsyncClient, parametrize, Live check: an invitation accepted through single sign-on, against the stub…, test_live_invitation_accepted_through_sso_then_sign_in_by_subject(), app(), browser_to_idp() (+17 more)

### Community 68 - "webauthn_live_support.py"
Cohesion: 0.10
Nodes (19): admin(), browser(), config(), fixture, The administrator's own client, signed in over the same live server., server(), _b64(), _b64url() (+11 more)

### Community 69 - "PolicyStore"
Cohesion: 0.12
Nodes (16): PolicyError, PolicyStore, Any, AsyncConnection, Event, SourceIp, ValueError, The effective session policy, cached per replica and invalidated over NOTIFY. (+8 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (22): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, Request (+14 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.15
Nodes (41): http_sign_in(), identity_of(), AsyncClient, Response, The Identity installed in the app an ASGI test client talks to., ``POST <prefix>/sign-in`` carried through the second factor over HTTP. The…, test_a_pinned_policy_is_the_one_described(), admin() (+33 more)

### Community 72 - "test_password_watch_lists.py"
Cohesion: 0.10
Nodes (38): StrEnum, WatchListKind, builtin(), _lines(), lists(), policies(), Any, fixture (+30 more)

### Community 73 - "test_password_feedback.py"
Cohesion: 0.11
Nodes (29): failing_transport(), handler(), listing_transport(), MockTransport, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., _counts() (+21 more)

### Community 74 - "console_support.py"
Cohesion: 0.12
Nodes (20): pool(), Any, client(), console(), make_console(), build(), Any, AsyncClient (+12 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.07
Nodes (70): The session from ``complete_sign_in``; fails if the password must change first., sign_in_tokens(), bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests. (+62 more)

### Community 76 - "PolicySettings"
Cohesion: 0.09
Nodes (29): PasswordRules, A policy's deterministic rules (PW3), passphrase setting (PW4) and tiers (PW5)., Raise ``PasswordPolicyError`` naming every inconsistent field., The versioned JSON shape a browser evaluates., PolicySettings, What an administrator sets on a policy: everything but its id, priority and…, The outcome of ``match``: the first match, and whether the range API could not…, Whether the password is refused: a match, or an unreachable API the policy… (+21 more)

### Community 77 - "SignInMethod"
Cohesion: 0.09
Nodes (38): The default sign-in method and the allowed second factors (cached briefly)., Set a user's own method; None has them follow the default. At once when the…, _LinkDue, _Outcome, Any, AsyncConnection, SourceIp, UUID (+30 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "hashlib"
Cohesion: 0.08
Nodes (29): hashlib, _key_id(), Encryption at rest for TOTP secrets. A TOTP secret lets anyone who holds it…, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., Seals and opens small secrets with the current (and, while rotating, previous)…, SecretBox, Fingerprints (+21 more)

### Community 81 - "test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "audit/__init__.py"
Cohesion: 0.05
Nodes (62): AwareDatetime, description, ExportFormat, max_length, pydantic, export(), Any, Record the export, then stream the matching rows in chain order. The export… (+54 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.20
Nodes (14): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+6 more)

### Community 86 - "test_sso_migration.py"
Cohesion: 0.27
Nodes (10): Connection, parametrize, UUID, Single sign-on's migration: its tables, their constraints, and a tested…, _tables(), test_a_subject_is_pinned_to_one_user(), test_a_user_has_at_most_one_pin(), test_constraints() (+2 more)

### Community 87 - "test_identity_sign_in.py"
Cohesion: 0.18
Nodes (24): statistics, _assert_refusal(), Any, AsyncClient, parametrize, Response, UserFactory, Password sign-in over HTTP: outcomes, uniform refusals, timing and rehashing. (+16 more)

### Community 88 - "test_sso_admin_routes.py"
Cohesion: 0.09
Nodes (40): sso_config(), app(), authorise(), config(), idp(), Any, AsyncClient, FastAPI (+32 more)

### Community 89 - "Client-behaviour guide"
Cohesion: 0.21
Nodes (14): warden changelog, Passkey sign-in and passkey_only method (0.1.0b11), WebAuthn security keys and passkeys as second factor (0.1.0b10), OIDC single sign-on with PKCE, pre-provisioned accounts, HTTP contract docs/contract/openapi.json, Trusted-proxy middleware, Administrator's MFA and TOTP reset, Client-behaviour guide (+6 more)

### Community 90 - "Cluster: warden design overview"
Cohesion: 0.11
Nodes (23): fido2 runtime dependency (0.1.0b9), Integration procedure (merge, re-chain, stamp), Migrations across parallel workstreams, Mutation-checked guard and tripwire tests, warden project working agreement (CLAUDE.md), Single-use credentials consumed by one guarded atomic write, Acceptance tests from Termograph hardening findings, Argon2id passwords with legacy PBKDF2 rehash (D15) (+15 more)

### Community 91 - "modules"
Cohesion: 0.19
Nodes (20): Pattern, _docstring_nodes(), identifiers(), module_name(), modules(), AST, Path, Helpers for tripwires that read warden's own source. (+12 more)

### Community 92 - "webauthn/service.py"
Cohesion: 0.09
Nodes (30): The signed-in user's security keys and passkeys, oldest first., Passkeys and security keys (WebAuthn): the ceremonies and the credential store.…, _extension_results(), StrEnum, The WebAuthn ceremonies: registering and signing in with passkeys and security…, What a credential is registered for., A successful sign-in with a credential., ``credProps.rk`` where the browser reports it. (+22 more)

### Community 93 - "webauthn/challenges.py"
Cohesion: 0.13
Nodes (19): enum, Ceremony, Challenges, ConsumedChallenge, _hash(), IssuedChallenge, Any, AsyncConnection (+11 more)

### Community 94 - "test_audit_verify.py"
Cohesion: 0.19
Nodes (21): ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id., A forger who recomputes the altered row's hash is caught at the next row., Swap every stored column of two rows except their ids. (+13 more)

### Community 95 - "main"
Cohesion: 0.20
Nodes (22): main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests.…, _export(), FakeSecrets, FakeSettings, Any, CaptureFixture, fixture (+14 more)

### Community 96 - "attestation.py"
Cohesion: 0.12
Nodes (14): AttestationObject, Certificate, cryptography_exceptions, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca() (+6 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.10
Nodes (11): _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range() (+3 more)

### Community 98 - "totp.py"
Cohesion: 0.12
Nodes (17): generate_recovery_codes(), generate_secret(), hash_recovery_code(), matching_step(), parse_code(), parse_recovery_code(), provisioning_uri(), TOTP (RFC 6238, HMAC-SHA1, six digits, 30-second steps) and recovery codes.… (+9 more)

### Community 99 - "test_sign_in_methods_sso.py"
Cohesion: 0.13
Nodes (34): Single sign-on cannot be turned off or cleared: someone signs in with it alone.…, SsoStillRequired, add_key(), app(), config(), enabled(), has_password(), idp() (+26 more)

### Community 100 - "test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (16): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations() (+8 more)

### Community 101 - "sys"
Cohesion: 0.09
Nodes (26): _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``., stamp() (+18 more)

### Community 102 - "identity/__init__.py"
Cohesion: 0.03
Nodes (91): argon2, argon2_exceptions, Creating the first administrator. warden's own CLI cannot do this, because the…, hmac, re, secrets, ApiKey, ApiKeyError (+83 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.06
Nodes (30): AuditConfig, _check_origin(), _check_secret_name(), _check_template(), _check_url(), DbConfig, HttpConfig, IdentityConfig (+22 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (28): _accept(), admin(), config(), http(), _invite(), _options(), Any, AsyncClient (+20 more)

### Community 106 - "make_user"
Cohesion: 0.15
Nodes (29): assert_strict_csp(), http_sign_in(), make_user(), AsyncClient, Response, ``POST /auth/sign-in`` carried through the second factor: the final response., A password sign-in carried through its second factor (always required since…, sign_in() (+21 more)

### Community 107 - "test_audit_source_ip_tripwire.py"
Cohesion: 0.19
Nodes (16): collections, _constants(), _is_warden(), _missing(), _owner(), expr, Tripwire: every warden audit event carries the client address, unless it has no…, The class and method, or the function, a call sits in (nested routes keep their… (+8 more)

### Community 108 - "test_identity_lifecycle_routes.py"
Cohesion: 0.20
Nodes (18): app(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory, Public lifecycle routes: accept an invitation, request and complete a password… (+10 more)

### Community 109 - "password_policy/__init__.py"
Cohesion: 0.08
Nodes (45): HibpUnavailable, Exception, Errors raised by password policies and watch lists. Messages carry field names,…, A watch list, or a change to one, was refused., No watch list has that id., The change clashes with the stored state: a list still attached to a policy., An import was refused or failed; the list is left as it was. ``line`` is the…, The breached-password range service could not be used. Always the same message:… (+37 more)

### Community 110 - "new_totp_key"
Cohesion: 0.10
Nodes (25): _decode(), new_totp_key(), Exception, Protocol, A TOTP key is missing or malformed. Names the secret, never its value., A fresh 256-bit key, encoded for the secrets store., Read the keys from konfig's secrets store; fails if the current key is…, SecretKeyError (+17 more)

### Community 111 - "check_dist.py"
Cohesion: 0.19
Nodes (16): argparse, email_parser, dist_problems(), import_problems(), main(), _metadata_version(), Path, Check warden's built distributions, and the installed package, before… (+8 more)

### Community 112 - "test_cli.py"
Cohesion: 0.22
Nodes (12): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: migrate and keys rotate., _settings(), test_invalid_configuration_fails_before_doing_anything(), test_keys_rotate_adds_a_key_and_prints_only_its_id() (+4 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (17): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+9 more)

### Community 114 - "test_sso_source_ip.py"
Cohesion: 0.15
Nodes (19): app(), authorise(), config(), idp(), Any, AsyncClient, FastAPI, fixture (+11 more)

### Community 115 - "collector.py"
Cohesion: 0.08
Nodes (13): Framing, ssl, BlackholeCollector, Event, SSLContext, StreamReader, StreamWriter, In-process syslog collectors for tests: stream (TCP or TLS), UDP and a… (+5 more)

### Community 116 - "identity/conftest.py"
Cohesion: 0.16
Nodes (20): app(), audit_registry(), client(), config(), identity(), keys(), mail(), make_user() (+12 more)

### Community 117 - "test_audit_grants.py"
Cohesion: 0.19
Nodes (15): age(), Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then…, _as(), MemorySecrets, _pool(), Any, parametrize, Append-only grants: the application role can only insert and read audit rows.… (+7 more)

### Community 118 - "grants.py"
Cohesion: 0.28
Nodes (15): append_only_grants(), _application(), _forwarder(), grants_sql(), _ident(), _purger(), Composable, Composed (+7 more)

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "config.py"
Cohesion: 0.15
Nodes (19): fido2_rpid, _base_origin(), _format_errors(), load_config(), parse_config(), Any, Protocol, Typed configuration, bound through konfig and validated at start-up. A product… (+11 more)

### Community 121 - "test_sso_issuer.py"
Cohesion: 0.13
Nodes (24): alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer(), Any (+16 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.17
Nodes (27): _assert_one_unforked_chain(), _event(), Any, fixture, The chained recorder: links, server-side order, the details cap, and…, Poll until backend ``pid`` waits on the chain's advisory lock., Row id order is commit order: the second inserter waits for the first's commit., A server default of REPEATABLE READ must not make warden's own writes conflict. (+19 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "publish.yml"
Cohesion: 0.13
Nodes (15): Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on, push (+7 more)

### Community 125 - "test_syslog_sd_id.py"
Cohesion: 0.12
Nodes (21): copy, Any, model_validator, Self, Build settings from the shared ``SyslogConfig``. ``secrets`` looks up a konfig…, Syslog forwarding: every field ``SyslogSettings`` needs.…, SyslogConfig, _config() (+13 more)

### Community 126 - "keys.py"
Cohesion: 0.14
Nodes (16): Ed25519PrivateKey, _b64url(), _b64url_decode(), key_id_for(), PublicKey, Ed25519 signing keys, identified by key id, with rotation (design D14). Private…, Generate a key and make it the signing key. Earlier keys keep verifying., The key that signs now: the newest unretired, unrevoked key. (+8 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (14): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+6 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.18
Nodes (16): importlib_util, init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch. (+8 more)

### Community 129 - "Sessions"
Cohesion: 0.10
Nodes (23): AccessClaims, _b64(), _hash(), _json(), Any, AsyncConnection, NoReturn, SourceIp (+15 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "test_password_set_points.py"
Cohesion: 0.13
Nodes (22): _administrator(), _change(), _codes(), _create(), _forced(), _hash(), _http_failures(), _invitation() (+14 more)

### Community 132 - "MemorySecrets"
Cohesion: 0.14
Nodes (21): make_config(), MemorySecrets, cli_secrets(), fp_identity(), fixture, MemorySecrets, test_keys_may_be_unexpiring_when_no_maximum_is_set(), test_the_configured_prefix_is_used() (+13 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "test_mfa_factors_webauthn.py"
Cohesion: 0.26
Nodes (23): _allow(), _challenge(), _keys(), _principal(), AsyncClient, UserFactory, UUID, Allowed second factors with security keys and passkeys (ruling CS14). The… (+15 more)

### Community 136 - "pathlib"
Cohesion: 0.06
Nodes (28): cryptography, cryptography_hazmat_primitives, cryptography_hazmat_primitives_serialization, pathlib, names(), path(), Browser scripts warden publishes, for a product to serve from its own static…, The file names of the scripts warden ships. (+20 more)

### Community 137 - "sign_in_settings.py"
Cohesion: 0.07
Nodes (34): check(), _factors(), _method(), PendingSignInMethod, _purpose(), datetime, StrEnum, ValueError (+26 more)

### Community 138 - "dependencies.py"
Cohesion: 0.15
Nodes (17): bearer_token(), Forbidden, installed_identity(), HTTPException, Protocol, Request, FastAPI dependencies: ``require_user``, ``require_permission`` and the…, A dependency requiring ``permission``; with ``scoped``, also the product's… (+9 more)

### Community 139 - "test_examples_public_surface.py"
Cohesion: 0.26
Nodes (12): ast, _private(), _private_path(), Path, Tripwire: the sample console uses only warden's public surface. The sample…, Every reach into a private warden module or name in ``source``., sample_sources(), test_nothing_under_examples_reaches_into_warden_internals() (+4 more)

### Community 140 - "console_router"
Cohesion: 0.16
Nodes (17): _anchor_report(), console_router(), anchor_head(), change_policy(), check_anchors(), import_sample(), move_clock(), recheck_passwords() (+9 more)

### Community 141 - "test_no_private_imports.py"
Cohesion: 0.36
Nodes (8): ImportFrom, _from_warden(), _private(), Tripwire: no warden module reaches into another module's private names. A…, Local names bound by an import from warden (modules or anything else)., test_no_module_reaches_into_another_modules_private_names(), _violations(), _warden_bindings()

### Community 142 - "test_password_policy_store.py"
Cohesion: 0.16
Nodes (27): Any, fixture, parametrize, UUID, The password policy store (rulings PW1, PW2 and PW11): policies, priorities,…, _settings(), _store(), test_a_change_notifies_in_its_own_transaction() (+19 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.09
Nodes (46): IssuedToken, _live_token(), LiveToken, Purpose, Any, AsyncConnection, datetime, StrEnum (+38 more)

### Community 144 - "test_password_cli.py"
Cohesion: 0.24
Nodes (22): _banned(), _entries(), FakeSettings, _policy(), Any, CaptureFixture, Path, UUID (+14 more)

### Community 145 - "SsoSettingsStore"
Cohesion: 0.15
Nodes (22): ValueError, A settings change was refused. The message names fields, never values., SsoSettingsError, SsoSettingsStore, config(), fixture, parametrize, UserFactory (+14 more)

### Community 146 - "test_webauthn_live.py"
Cohesion: 0.26
Nodes (21): credentials(), last_step(), live_sessions(), no_credential_material(), ok(), open_sign_in_challenges(), Any, AsyncClient (+13 more)

### Community 147 - "test_console_capabilities.py"
Cohesion: 0.29
Nodes (8): _admin(), _client(), Any, AsyncClient, The sample console asks warden what the deployment can do, and its screens…, test_with_a_sender_everything_that_mails_is_available(), test_without_a_sender_the_capabilities_say_so_and_the_503_stays(), test_without_the_link_setting_only_the_registration_link_is_unavailable()

### Community 148 - "test_no_direct_environment.py"
Cohesion: 0.31
Nodes (9): _enclosing_functions(), visit(), _findings(), AST, Tripwire: warden reads configuration only through konfig. No module under…, Each node's innermost enclosing function name, keyed by ``id(node)``., Every forbidden use, and whether it is the named exemption., test_each_exemption_covers_exactly_one_read() (+1 more)

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "LiveBrowser"
Cohesion: 0.16
Nodes (8): LiveBrowser, Any, BaseException, T, Chromium with one page, its DevTools session and its virtual authenticators., Run a coroutine on the browser's loop and wait for it from the test's loop., Fill the named fields, press the action's button and read what the page saw., TracebackType

### Community 151 - "test_a_purge_committing_during_verification_breaks_nothing"
Cohesion: 0.18
Nodes (7): _AfterFirstQuery, _HookedPool, MemorySecrets, Any, Delegates to a connection, running ``hook`` once after the checkpoint listing., test_a_purge_committing_during_verification_breaks_nothing(), purge_now()

### Community 152 - "test_audit_source_ip_routes.py"
Cohesion: 0.14
Nodes (32): FixtureRequest, work(), address(), admin(), app(), _bearer(), client(), _last_id() (+24 more)

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.18
Nodes (30): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, anonymous(), bearer(), deployment(), make(), member() (+22 more)

### Community 154 - "test_audit_router.py"
Cohesion: 0.16
Nodes (21): client(), exporter(), NoKeys, Any, AsyncClient, fixture, parametrize, Audit routers: list, export and verify, behind the product's own authorisation. (+13 more)

### Community 155 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.08
Nodes (30): PasswordHistory, Any, AsyncConnection, datetime, UUID, Password history (ruling PW6). Each password a user sets is kept as its…, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password. (+22 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "test_sign_in_methods_migration.py"
Cohesion: 0.21
Nodes (19): _method(), _pending(), Any, Conn, parametrize, UUID, The sign-in methods migration (rulings CS13 and CS16), with a tested downgrade.…, _refused() (+11 more)

### Community 159 - "console/cli.py"
Cohesion: 0.10
Nodes (41): create_administrator(), Create an active user with ``password`` holding the administrator role. Running…, _create_admin(), work(), _dsn(), _init(), main(), _parser() (+33 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "test_password_hibp.py"
Cohesion: 0.18
Nodes (19): _client(), LogCaptureFixture, parametrize, Request, Response, The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed…, Recorder, test_a_digest_must_be_twenty_bytes() (+11 more)

### Community 162 - "Identity"
Cohesion: 0.06
Nodes (78): Identity, FastAPI, warden's identity subsystem for one deployment., Make this Identity the one ``require_user`` and ``require_permission`` use., Run identity's background work (the session and password policy listeners) for…, Delete sign-in throttle records whose window has ended., _b64(), _parts() (+70 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "test_console_gaps.py"
Cohesion: 0.18
Nodes (7): Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., Question 39 was a defect in the admin route, fixed in warden 0.1.0., test_forbid_user_details_is_no_longer_a_gap(), test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap()

### Community 165 - ".register"
Cohesion: 0.16
Nodes (13): Algorithm, AttestationFormat, FLAG, PrivateKey, _new_key(), Any, AuthenticatorData, CollectedClientData (+5 more)

### Community 166 - "StreamCollector"
Cohesion: 0.17
Nodes (24): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), A TCP (or, with ``ssl``, TLS) collector that records raw bytes and frames., Stop listening and drop every open connection, as a stopped collector would., StreamCollector, _audit_rows() (+16 more)

### Community 167 - "PasswordsConfig"
Cohesion: 0.18
Nodes (8): AsyncBaseTransport, _FieldProblems, PasswordsConfig, model_validator, Self, Cross-field problems, each with a path relative to the failing model., Password policies: the fingerprint key and the breached-password range API.…, Whether a policy may enable the sealed fingerprint (ruling PW8).

### Community 169 - "test_browser_rules_vectors.py"
Cohesion: 0.18
Nodes (13): CompletedProcess, subprocess, node(), Path, The packaged browser rules against warden's test vectors.…, run(), test_every_vector_agrees_with_the_packaged_script(), test_the_runner_fails_when_a_rule_is_altered() (+5 more)

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "test_cli_audit.py"
Cohesion: 0.24
Nodes (14): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up() (+6 more)

### Community 173 - "test_cli_audit_errors.py"
Cohesion: 0.19
Nodes (14): _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path, The warden audit CLI without a database: connection failures and grants. (+6 more)

### Community 174 - "passwordrules.js"
Cohesion: 0.23
Nodes (15): classMatchers(), codePoints(), countClasses(), countWords(), detailTokens(), evaluate(), localPart(), longestRun() (+7 more)

### Community 175 - "BuiltinList"
Cohesion: 0.11
Nodes (23): console_settings(), functools, BuiltinList, _bundled(), bundled_list(), _check(), Path, The built-in common-password list (ruling PW12). A read-only list of common… (+15 more)

### Community 176 - "test_config_passwords.py"
Cohesion: 0.22
Nodes (18): _parse(), Any, parametrize, Start-up validation of the password settings (rulings PW2, PW7 and PW8 of 10…, _refused(), test_a_fingerprint_key_name_makes_the_fingerprint_available(), test_a_malformed_secret_name_is_refused(), test_a_previous_key_needs_a_current_key() (+10 more)

### Community 177 - "pytest"
Cohesion: 0.16
Nodes (13): pytest, dsn(), migrated_dsn(), pg_admin_url(), fixture, Shared fixtures. Database tests use a real Postgres through testcontainers., A fresh, empty database for one test., Fixtures for password policy tests: identity's audit actions are registered, as… (+5 more)

### Community 178 - "test_console_source_ip.py"
Cohesion: 0.33
Nodes (13): client(), headers(), Any, AsyncClient, fixture, Response, The sample console's own routes pass the client address, as a product should…, _recorded() (+5 more)

### Community 179 - "test_sso_setup_guides.py"
Cohesion: 0.22
Nodes (11): guide(), parametrize, Single sign-on setup guides: structured, numbered steps per provider preset…, settings(), test_an_unknown_preset_falls_back_to_generic(), test_every_copy_back_names_a_real_setting(), test_every_placeholder_a_step_uses_is_declared_and_filled(), test_every_preset_has_ordered_steps() (+3 more)

### Community 180 - "password_support.py"
Cohesion: 0.21
Nodes (13): bearer(), codes(), lifecycle_app(), pin_policy(), Any, AsyncClient, FastAPI, Response (+5 more)

### Community 181 - "presets.py"
Cohesion: 0.21
Nodes (12): CopyBack, GuideStep, PresetGuide, Provider presets: setup guidance for an administrator, and nothing else.…, The steps for ``preset`` with the instance's values filled in. ``callback_uri``…, A value to copy from the provider's console into a warden setting., One step as written: ``text`` holds ``{placeholder}`` tokens., A step with its placeholders filled in. (+4 more)

### Community 182 - "licence_audit.py"
Cohesion: 0.23
Nodes (14): packaging_requirements, packaging_utils, audit(), classify(), data_problems(), installed(), main(), _one() (+6 more)

### Community 183 - "throttle.py"
Cohesion: 0.06
Nodes (36): PasswordPruning, Pruner, PruneReport, Identifier, Protocol, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., What the pruner needs from password policies. (+28 more)

### Community 184 - "test_identity_key_publication.py"
Cohesion: 0.29
Nodes (13): PyJWK, _access_token(), _b64(), _decode(), keys_client(), _published_key(), Any, AsyncClient (+5 more)

### Community 185 - "test_cli_errors.py"
Cohesion: 0.24
Nodes (8): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1(), test_migrate_connection_failure_prints_a_fixed_message_and_exits_1()

### Community 186 - "resolve_client_ip"
Cohesion: 0.18
Nodes (12): _address(), Any, Network, _Scope, Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``., The client address, given the peer and every ``X-Forwarded-For`` value in order., resolve_client_ip(), _trusted() (+4 more)

### Community 187 - ".connection"
Cohesion: 0.32
Nodes (5): AbstractAsyncContextManager, Any, AsyncConnection, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - "set_default"
Cohesion: 0.24
Nodes (10): Clock, A settable clock for ``Identity(clock=...)``: real time plus an offset., Replace the default policy's settings (keeping its name)., set_default(), clock(), fixture, test_a_password_just_short_of_its_expiry_signs_in(), test_the_minimum_age_limits_only_the_users_own_change() (+2 more)

### Community 191 - "_LazySecrets"
Cohesion: 0.29
Nodes (4): _LazySecrets, Any, AsyncConnection, konfig ``Secrets``, constructed only if a command actually needs a secret.

### Community 192 - "race"
Cohesion: 0.09
Nodes (32): Any, race(), Run ``calls`` as concurrent tasks released together by a barrier. Every task…, _admins(), UserFactory, Role assignments: audited, expiring, and never leaving no administrator., Two administrators demoting each other at once: exactly one demotion succeeds., test_an_administrator_role_cannot_expire() (+24 more)

### Community 193 - "resolve"
Cohesion: 0.22
Nodes (7): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PW1: the pin, else the highest-priority mapped and declared role, else the…, resolve(), test_resolution_order_is_pin_then_highest_priority_role_then_default()

### Community 194 - "SsoSettings"
Cohesion: 0.25
Nodes (4): _from_config(), UUID, The effective settings, cached for ``max_age`` seconds., SsoSettings

### Community 195 - "test_identity_totp_storage.py"
Cohesion: 0.36
Nodes (8): MemorySecrets, UserFactory, TOTP secrets are sealed at rest, bound to their user, and survive key rotation., _row(), test_a_secret_copied_to_another_user_does_not_open(), test_identity_refuses_to_start_without_a_totp_key(), test_rotation_keeps_enrolments_working_and_reseals(), test_the_stored_secret_is_sealed()

### Community 196 - "run_vectors.mjs"
Cohesion: 0.22
Nodes (8): api, context, failures, fields, here, root, seen, vectors

### Community 197 - "build_console"
Cohesion: 0.04
Nodes (58): actor(), build_console(), Console, _mount_pages(), FastAPI, Request, The sample console's application: how a product wires warden into FastAPI. Read…, Build the console over the product's open pool and konfig's secrets store.… (+50 more)

### Community 198 - "test_dependabot.py"
Cohesion: 0.24
Nodes (7): _blocks(), Dependabot keeps the pinned GitHub Actions current. Pinning every action to a…, test_dependabot_watches_github_actions_weekly(), Tripwire: every GitHub Action is pinned to a full commit SHA. A tag such as…, _references(), test_every_action_is_pinned_to_a_commit_sha(), test_workflows_reference_actions()

### Community 199 - "test_public_api.py"
Cohesion: 0.11
Nodes (10): importlib, packaging_version, warden: identity and audit for Python web applications. The public API lives in…, reset(), Packaging: one version source, typed marker, distribution metadata., parametrize, The public import surface, fixed as a snapshot. warden's public API is whatever…, test_every_exported_name_resolves_once() (+2 more)

### Community 200 - "warden sample console"
Cohesion: 0.29
Nodes (8): Product-declared permissions and roles (D5), Rotating refresh-token families with reuse detection, What the product builds itself in 0.1.0, Serialised refresh with reuse grace window, check_dist.py distribution checks, Console gaps (questions 7 to 11), warden sample console, Sample console HTML shell

### Community 201 - "test_audit_chain_migration.py"
Cohesion: 0.60
Nodes (5): _columns(), _constraints(), The audit chain migration: reversible, and refuses rows it cannot chain., test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(), test_head_includes_the_chain_revision()

### Community 202 - "Single sign-on setup guides"
Cohesion: 0.25
Nodes (7): Getting the steps, Google, Microsoft Entra ID, Okta, Other OpenID Connect provider, Single sign-on setup guides, What every guide shares

### Community 203 - "test_password_wiring.py"
Cohesion: 0.29
Nodes (7): Any, Identity gains the password policy services at construction, with no I/O. Wave…, test_a_configured_fingerprint_key_must_be_in_the_secrets_store(), test_construction_writes_nothing_and_the_seeded_default_refuses_a_common_password(), test_prune_trims_history_and_expired_change_challenges(), test_running_also_listens_for_password_policy_changes(), test_the_services_are_attributes_built_at_construction()

### Community 204 - "keys_router"
Cohesion: 0.25
Nodes (9): _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter, Response (+1 more)

### Community 205 - "AuditRow"
Cohesion: 0.05
Nodes (41): BreakReason, _b64url(), _b64url_decode(), Checkpoint, HistoricalVerifier, _int(), MalformedCheckpoint, Any (+33 more)

### Community 206 - "KonfigSecrets"
Cohesion: 0.33
Nodes (3): KonfigSecrets, Any, konfig's ``Secrets``, typed as the store warden expects (``get`` and ``set``).

### Community 207 - "effective_method_sql"
Cohesion: 0.40
Nodes (5): effective_method_sql(), pending_method_sql(), Composable, The method in force for the users row named ``users`` in a query, as SQL.…, The method a pending change moves the ``users`` row to, or NULL, as SQL.

### Community 208 - "test_database.py"
Cohesion: 0.46
Nodes (7): _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 213 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends an acceptance transaction without committing it.

### Community 214 - "test_tls_fail_closed.py"
Cohesion: 0.46
Nodes (7): _findings(), _is_cert_required(), _is_true(), expr, Tripwire: nothing in warden turns TLS verification off. Fails on any use of…, test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 216 - "test_readme.py"
Cohesion: 0.43
Nodes (5): README.md is the PyPI project description, so it must render there without…, _targets(), test_every_link_is_absolute(), test_link_check_refuses_relative_link_and_image(), test_readme_has_links()

## Knowledge Gaps
- **124 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+119 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2108 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **21 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `httpx`, `record_audit`, `KeyStore`, `RecordingSender`, `test_webauthn_mfa.py`, `contract.py`, `password_admin.py`, `build_sso_settings_router`, `test_webauthn_reset.py`, `WebAuthn`, `Database`, `sso/service.py`, `Invitations`, `PasswordEnforcement`, `UserError`, `test_identity_totp_reset.py`, `json_response`, `client_ip`, `rules.py`, `current_code`, `test_password_sign_in.py`, `WardenConfig`, `test_webauthn_authentication.py`, `Mfa`, `identity_support.py`, `User`, `mail.py`, `export_openapi.py`, `PasswordStates`, `test_identity_apikeys.py`, `PermissionRegistry`, `audit_rows`, `test_sso_live.py`, `webauthn_live_support.py`, `PolicyStore`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_feedback.py`, `test_password_admin_routes.py`, `PolicySettings`, `SignInMethod`, `test_identity_admin_routes.py`, `hashlib`, `test_sso_capabilities.py`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `webauthn/service.py`, `test_sign_in_methods_sso.py`, `identity/__init__.py`, `test_passkey_invitation.py`, `test_identity_lifecycle_routes.py`, `new_totp_key`, `test_sso_source_ip.py`, `identity/conftest.py`, `test_sso_issuer.py`, `Cluster: test_identity_client_address.py`, `Sessions`, `test_password_set_points.py`, `MemorySecrets`, `test_mfa_factors_webauthn.py`, `sign_in_settings.py`, `dependencies.py`, `console_router`, `SingleUseTokens`, `test_password_cli.py`, `SsoSettingsStore`, `test_webauthn_live.py`, `test_audit_source_ip_routes.py`, `test_identity_capabilities.py`, `PasswordHistory`, `console/cli.py`, `password_support.py`, `throttle.py`, `test_identity_key_publication.py`, `set_default`, `race`, `test_identity_totp_storage.py`, `build_console`, `test_password_wiring.py`, `test_failed_sign_in_timing_is_unchanged_by_the_passwords_state`?**
  _High betweenness centrality (0.128) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `httpx`, `SyslogSettings`, `AuditEvent`, `KeyStore`, `RecordingSender`, `PasswordResets`, `AuditRecorder`, `test_webauthn_mfa.py`, `contract.py`, `test_audit_recorder.py`, `test_webauthn_reset.py`, `WebAuthn`, `PasswordPolicies`, `sso/service.py`, `PasswordEnforcement`, `UserError`, `test_identity_totp_reset.py`, `test_syslog_forwarder.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `WardenConfig`, `test_webauthn_authentication.py`, `test_audit_retention.py`, `identity_support.py`, `User`, `warden/cli.py`, `soft_authenticator.py`, `export_openapi.py`, `typing`, `PasswordStates`, `test_identity_apikeys.py`, `PermissionRegistry`, `audit_rows`, `test_sso_live.py`, `PolicyStore`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_watch_lists.py`, `test_password_feedback.py`, `test_password_admin_routes.py`, `PolicySettings`, `test_identity_admin_routes.py`, `test_key_publication.py`, `audit/__init__.py`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `webauthn/service.py`, `webauthn/challenges.py`, `test_audit_verify.py`, `attestation.py`, `test_sign_in_methods_sso.py`, `identity/__init__.py`, `test_passkey_invitation.py`, `test_identity_lifecycle_routes.py`, `password_policy/__init__.py`, `new_totp_key`, `test_sso_source_ip.py`, `identity/conftest.py`, `test_audit_grants.py`, `test_sso_issuer.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `keys.py`, `Sessions`, `test_password_set_points.py`, `MemorySecrets`, `test_mfa_factors_webauthn.py`, `sign_in_settings.py`, `test_password_policy_store.py`, `SingleUseTokens`, `test_password_cli.py`, `SsoSettingsStore`, `test_webauthn_live.py`, `test_a_purge_committing_during_verification_breaks_nothing`, `test_audit_source_ip_routes.py`, `test_identity_capabilities.py`, `test_audit_router.py`, `PasswordHistory`, `Identity`, `StreamCollector`, `BuiltinList`, `throttle.py`, `.connection`, `race`, `SsoSettings`, `test_identity_totp_storage.py`, `build_console`, `test_password_wiring.py`, `test_database.py`, `.__init__`, `test_failed_sign_in_timing_is_unchanged_by_the_passwords_state`?**
  _High betweenness centrality (0.120) - this node is a cross-community bridge._
- **Why does `KeyStore` connect `KeyStore` to `httpx`, `Sessions`, `MemorySecrets`, `AuditRecorder`, `console_router`, `test_a_purge_committing_during_verification_breaks_nothing`, `test_identity_capabilities.py`, `Identity`, `current_code`, `test_password_sign_in.py`, `WardenConfig`, `test_audit_retention.py`, `identity_support.py`, `warden/cli.py`, `test_identity_key_publication.py`, `export_openapi.py`, `typing`, `PermissionRegistry`, `race`, `audit_rows`, `test_identity_totp_storage.py`, `build_console`, `PolicyStore`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_feedback.py`, `test_password_wiring.py`, `keys_router`, `PolicySettings`, `test_key_publication.py`, `test_identity_sign_in.py`, `test_failed_sign_in_timing_is_unchanged_by_the_passwords_state`, `identity/__init__.py`, `new_totp_key`, `identity/conftest.py`, `test_audit_grants.py`, `Cluster: test_identity_client_address.py`, `keys.py`?**
  _High betweenness centrality (0.028) - this node is a cross-community bridge._
- **Are the 62 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 62 INFERRED edges - model-reasoned connections that need verification._
- **Are the 94 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 94 INFERRED edges - model-reasoned connections that need verification._
- **Are the 167 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 167 INFERRED edges - model-reasoned connections that need verification._
- **What connects `STATUSES`, `METHODS`, `POLICY_FIELDS` to the rest of the system?**
  _124 weakly-connected nodes found - possible documentation gaps or missing edges._