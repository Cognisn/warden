# Graph Report - warden  (2026-11-11)

## Corpus Check
- 326 files · ~338,586 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 6836 nodes · 22261 edges · 226 communities (203 shown, 23 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2048 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d00a357f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- syslog/__init__.py
- test_sso_provider.py
- AuditEvent
- record_audit
- KeyStore
- race
- reset.py
- Database
- h
- test_webauthn_mfa.py
- contract.py
- build_password_admin_router
- test_syslog_sd_id.py
- test_audit_recorder.py
- test_webauthn_reset.py
- WebAuthn
- test_console_password_policy.py
- test_sso_invitations.py
- PasswordPolicies
- SingleSignOn
- Invitations
- .finish_registration
- test_audit_anchor_format.py
- PasswordEnforcement
- Users
- identity/conftest.py
- test_audit_chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- SsoSettingsStore
- CI Workflows
- test_audit_retention.py
- format_message
- certs.py
- test_identity_passwords.py
- test_syslog_forwarder.py
- rules.py
- current_code
- test_syslog_transport.py
- test_password_sign_in.py
- SyslogForwarder
- admin.py
- test_sso_sealing.py
- alembic
- warden/cli.py
- test_webauthn_authentication.py
- SyslogSettings
- Cluster: syslog
- Mfa
- test_identity_prune.py
- User
- test_distributions.py
- test_config_fields.py
- AuditRow
- soft_authenticator.py
- Mailer
- PolicySettings
- build_reference_app
- typing
- password_policy/__init__.py
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- test_audit_export.py
- current_revision
- httpx
- test_webauthn_live.py
- Sessions
- test_identity_dependencies.py
- test_passkey_registration_link.py
- Anchor
- test_password_rule_vectors.py
- DevClock
- test_password_admin_routes.py
- test_identity_throttle.py
- load_cursor
- test_identity_admin_routes.py
- test_webauthn_migration.py
- SecretBox
- test_key_publication.py
- test_sso_capabilities.py
- test_audit_router.py
- test_openapi_contract.py
- test_identity_migration.py
- migrate.py
- test_identity_sign_in.py
- test_sso_admin_routes.py
- Cluster: Client-behaviour guide
- Cluster: warden design overview
- Cluster: modules()
- WebAuthnCredentials
- Challenges
- test_audit_verify.py
- test_cli_audit_anchor.py
- attestation.py
- test_db_schema.py
- WatchLists
- resolve_client_ip
- test_sso_preset_label_only.py
- MailMessage
- Roles
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- test_console_passkeys.py
- test_syslog_routes.py
- audit_rows
- test_password_watch_lists.py
- test_password_builtin.py
- check_dist.py
- main
- Cluster: Audit hash chain specification
- test_password_feedback.py
- collector.py
- test_identity_mfa_mail.py
- test_audit_grants.py
- grants.py
- Cluster: with
- parse_config
- test_sso_issuer.py
- ActionRegistry
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- .__init__
- test_passkey_options_throttle.py
- test_lifecycle_migration.py
- test_bump_version.py
- build_console
- test_password_policy_migration.py
- RecordingSender
- MemorySecrets
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- passkey_support.py
- _FieldProblems
- .prune
- identity/__init__.py
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- test_password_cli.py
- well_formed
- BuiltinList
- test_console_capabilities.py
- test_no_direct_environment.py
- Cluster: updates
- HttpConfig
- _AfterFirstQuery
- test_database.py
- test_identity_capabilities.py
- test_tls_fail_closed.py
- ceremony.js
- PasswordHistory
- Cluster: verify
- format_expiry
- KonfigSecrets
- Cluster: rsyslog
- test_password_hibp.py
- Identity
- test_licence_audit.py
- pathlib
- PasswordsConfig
- SecurityHeaders
- pytest
- Cluster: examples/__init__.py
- ._accept
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- test_cli_audit.py
- test_cli_audit_errors.py
- test_packaging.py
- BaseModel
- test_config_passwords.py
- FakeIdp
- neutralise
- test_audit_chain_migration.py
- JwkSet
- bundled_list
- licence_audit.py
- SignInThrottle
- _Section
- test_cli_errors.py
- _clip
- ConnectionSource
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- password_support.py
- _LazySecrets
- test_identity_roles.py
- test_console_password_rules.py
- build
- .sso_settings_router
- .configured
- Notes
- _Invalid
- .__init__
- AnchorSigner
- resolve
- notes_router
- _audit
- .cursor
- registry
- test_identity_totp_storage.py
- matching_step
- The built-in common-password list
- test_a_key_registered_while_switching_to_sso_only_never_leaves_both
- _Abort
- .password_subject
- _Prioritised
- package
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

## God Nodes (most connected - your core abstractions)
1. `Identity` - 622 edges
2. `Database` - 609 edges
3. `audit_rows()` - 199 edges
4. `RecordingSender` - 180 edges
5. `KeyStore` - 173 edges
6. `ActionRegistry` - 135 edges
7. `AuditRecorder` - 133 edges
8. `AuditEvent` - 123 edges
9. `FakeIdp` - 122 edges
10. `_Doc` - 109 edges

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
- 3-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 3-file cycle: `src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/apikeys.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`
- 5-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`

## Hyperedges (group relationships)
- **Audit tamper-evidence mechanisms** — docs_design_audit_chain_audit_hash_chain, docs_design_audit_chain_retention_checkpoint, docs_design_audit_chain_anchor, docs_design_audit_chain_audit_database_roles, docs_design_overview_tamper_evidence [EXTRACTED 1.00]
- **Release and publication pipeline** — docs_releasing_bump_version, github_workflows_publish, docs_releasing_check_dist, docs_releasing_trusted_publishing, claude_integration_procedure [EXTRACTED 1.00]
- **Tripwire tests guarding architecture rules** — docs_design_overview_single_audit_writer, docs_design_overview_audit_independence, examples_console_readme_public_surface_tripwire, claude_mutation_checked_guards [INFERRED 0.85]

## Communities (226 total, 23 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.16
Nodes (41): passkey_assertion(), passkey_sign_in(), AsyncClient, _admin(), _amr(), _last_sign_in_failure(), _passkey_user(), Any (+33 more)

### Community 1 - "syslog/__init__.py"
Cohesion: 0.05
Nodes (31): DatagramTransport, errno, socket, Syslog forwarding of committed audit rows (RFC 5424 over UDP, TCP or TLS)., BaseModel, Whether the test message reached the transport, and if not, why (a fixed…, Send one test message over a fresh connection with the forwarder's settings., send_test_message() (+23 more)

### Community 2 - "test_sso_provider.py"
Cohesion: 0.05
Nodes (79): jwt, jwt_algorithms, jwt_exceptions, Exception, Single sign-on refusals. ``SsoError.reason`` is a fixed category, recorded in…, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic() (+71 more)

### Community 3 - "AuditEvent"
Cohesion: 0.06
Nodes (36): AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., The one-line summary for ``event``; absent fields render as ``-``., ApiKeyError, ApiKeys, _hash(), Any (+28 more)

### Community 4 - "record_audit"
Cohesion: 0.04
Nodes (68): Record ``event`` through the installed recorder. See ``AuditRecorder.record``., record_audit(), Principal, The signed-in user behind a request. For a request made with an API key,…, AuthenticationRefused, Exception, A credential was refused. ``reason`` is for the audit trail and tests only. It…, Challenge (+60 more)

### Community 5 - "KeyStore"
Cohesion: 0.04
Nodes (67): Ed25519PrivateKey, KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., _b64url(), _b64url_decode(), key_id_for(), KeyStore, KeyStoreError (+59 more)

### Community 6 - "race"
Cohesion: 0.08
Nodes (54): InvitationError, An administrative invitation change was refused. Messages carry no values., A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, race(), Run ``calls`` as concurrent tasks released together by a barrier. Every task… (+46 more)

### Community 7 - "reset.py"
Cohesion: 0.06
Nodes (45): html, _check(), _is_control(), _load(), MailDeliveryError, MailError, MailTemplate, _neutralise() (+37 more)

### Community 8 - "Database"
Cohesion: 0.11
Nodes (63): AnchorRecord, ExternalAnchor, An anchor written to the trail, and the id of the row that carries it., An anchor found in an export: its line, its own row id when known, and the…, AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors() (+55 more)

### Community 9 - "h"
Cohesion: 0.07
Nodes (144): apiKeysScreen(), capabilities(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames() (+136 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.11
Nodes (71): enrol_totp(), Enrol and confirm TOTP for ``user``; returns the secret. Confirmation claims…, _amr(), _app(), _assertion(), _bearer(), _challenge(), http() (+63 more)

### Community 11 - "contract.py"
Cohesion: 0.03
Nodes (159): PasswordAdvice, PasswordRejected, A new password was refused; ``failures`` names every reason. The message lists…, What the description routes answer: the policy's rules and its history count., Public sign-in routes. The product mounts them under…, AffectedUsersProposalBody, BuiltinListBody, ChallengeBody (+151 more)

### Community 12 - "build_password_admin_router"
Cohesion: 0.08
Nodes (68): build_password_admin_router(), actor(), add_entries(), add_terms(), affected(), attach_list(), attached_to(), attachment() (+60 more)

### Community 13 - "test_syslog_sd_id.py"
Cohesion: 0.11
Nodes (26): format_test_message(), _header_field(), datetime, A NOTICE message with MSGID ``test``, for checking the path to the collector., A header field: PRINTUSASCII only, at most ``limit`` characters, never empty., _timestamp(), Any, model_validator (+18 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.14
Nodes (29): Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any (+21 more)

### Community 15 - "test_webauthn_reset.py"
Cohesion: 0.19
Nodes (24): _admin(), _bearer(), http(), Any, AsyncClient, fixture, MonkeyPatch, Response (+16 more)

### Community 16 - "WebAuthn"
Cohesion: 0.11
Nodes (61): fido2_utils, The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, LogCaptureFixture, parametrize (+53 more)

### Community 17 - "test_console_password_policy.py"
Cohesion: 0.11
Nodes (16): _passwords_source(), The sample console's password policy support: routes, the development clock,…, Every (method, path) a screen sends to a warden router, path parameters as…, test_an_imported_list_explains_the_file_the_threshold_and_the_command_line(), test_the_built_in_list_is_said_to_need_no_loading_on_both_screens(), test_the_console_settings_carry_the_range_api_and_built_in_list_facts(), test_the_console_settings_default_to_the_public_range_api(), test_the_console_settings_say_whether_the_fingerprint_key_is_configured() (+8 more)

### Community 18 - "test_sso_invitations.py"
Cohesion: 0.11
Nodes (59): Body, functools, Started, accept(), acceptance_rows(), app(), _bodies(), config() (+51 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.08
Nodes (41): PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, A password policy, or a change to one, was refused., No password policy has that id., The change clashes with the stored state: a stale version, a name or priority…, Delete history beyond the largest count any policy keeps; returns how many., _check_priority() (+33 more)

### Community 20 - "SingleSignOn"
Cohesion: 0.09
Nodes (27): _challenge(), _hash(), InvitationAcceptance, _PinRefused, Any, AsyncConnection, Exception, NoReturn (+19 more)

### Community 21 - "Invitations"
Cohesion: 0.14
Nodes (16): Method, Invitations, _Invitee, Any, AsyncConnection, datetime, NoReturn, SourceIp (+8 more)

### Community 22 - ".finish_registration"
Cohesion: 0.13
Nodes (21): PublicKeyCredentialDescriptor, _extension_results(), _parse(), Any, AsyncConnection, AuthenticatorData, CollectedClientData, T (+13 more)

### Community 23 - "test_audit_anchor_format.py"
Cohesion: 0.15
Nodes (30): cryptography_hazmat_primitives_asymmetric_ed25519, The anchors in an export from a SIEM, one record per line, numbered from 1. Two…, read_anchors(), _anchor(), _ndjson(), Any, parametrize, Anchors: the signed payload, its domain separation, and reading anchors back… (+22 more)

### Community 24 - "PasswordEnforcement"
Cohesion: 0.08
Nodes (26): SetPlace, _match_details(), PasswordEnforcement, PasswordFailure, Any, AsyncConnection, datetime, NoReturn (+18 more)

### Community 25 - "Users"
Cohesion: 0.19
Nodes (14): Any, AsyncConnection, Composable, datetime, UUID, User records in ``warden.users``., Create a user. The email address must be unique, ignoring case. A password is…, Users oldest first (ties by id), optionally only those of one status. Without… (+6 more)

### Community 26 - "identity/conftest.py"
Cohesion: 0.14
Nodes (22): app(), audit_registry(), client(), config(), db(), identity(), keys(), mail() (+14 more)

### Community 27 - "test_audit_chain.py"
Cohesion: 0.07
Nodes (45): JsonValue, address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields(), _number() (+37 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.10
Nodes (45): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+37 more)

### Community 29 - "test_config.py"
Cohesion: 0.06
Nodes (84): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, FakeSecrets, FakeSettings, _load(), Any, parametrize (+76 more)

### Community 30 - "json_response"
Cohesion: 0.04
Nodes (126): bearer_token(), MfaError, An MFA enrolment change was refused. Messages carry identifiers only., client_ip(), json_response(), Any, Network, Request (+118 more)

### Community 31 - "SsoSettingsStore"
Cohesion: 0.08
Nodes (32): _from_config(), _plain(), Any, AsyncConnection, The effective settings, cached for ``max_age`` seconds., The effective settings, read now on ``conn`` (no cache)., Override some fields: validated as a whole, audited, and, when this turns…, Drop every override, returning to configuration. (+24 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_audit_retention.py"
Cohesion: 0.10
Nodes (44): purge(), Exception, A purge was refused. The message carries row ids only., Delete audit rows older than ``retention_days`` behind a signed checkpoint., RetentionError, Verify the chain, from its first surviving row to ``through_id`` (or the head)., verify_chain(), Any (+36 more)

### Community 34 - "format_message"
Cohesion: 0.23
Nodes (29): AuditRecord, format_message(), The RFC 5424 message for ``record``, at most ``settings.max_message_bytes``…, One committed audit row, as the forwarder reads it., _oversized(), _parse(), Any, parametrize (+21 more)

### Community 35 - "certs.py"
Cohesion: 0.12
Nodes (16): cryptography, cryptography_hazmat_primitives, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, main(), Write a throwaway CA and a TLS keystore for the stub identity provider. python…, Issued, _key_pem() (+8 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.13
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.20
Nodes (39): ForwarderFactory, _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader() (+31 more)

### Community 38 - "rules.py"
Cohesion: 0.06
Nodes (64): _bool(), _classes(), _detail_tokens(), evaluate(), Evaluation, _int(), _local_part(), _longest_run() (+56 more)

### Community 39 - "current_code"
Cohesion: 0.11
Nodes (46): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), _challenge(), _enrolled(), _fresh_code() (+38 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.14
Nodes (35): frame(), open_transport(), Connect to the collector named in ``settings``; ``TransportError`` on failure., Frame ``message`` for a stream transport (RFC 6587)., Authority, A TCP (or, with ``ssl``, TLS) collector that records raw bytes and frames., Stop listening and drop every open connection, as a stopped collector would., StreamCollector (+27 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.14
Nodes (49): Clock, http(), A settable clock for ``Identity(clock=...)``: real time plus an offset., Replace the default policy's settings (keeping its name)., set_default(), _amr(), clock(), _complete() (+41 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.09
Nodes (16): Any, AsyncConnection, Task, Begin competing for the forwarder lock and, once held, forwarding., Stop forwarding, release the lock and close the transport. Idempotent., Switch to new settings; the next send opens a transport with them. Waits for an…, Try for the lock; lead until stopped or the session ends. True if it led., Read every notification as it arrives, so Postgres' queue never backs up. (+8 more)

### Community 43 - "admin.py"
Cohesion: 0.05
Nodes (86): ApiKey, A stored key, without its secret., InvitationMismatch, The invitation is valid but was accepted the wrong way; it stays usable.…, LastAdministratorError, Exception, A role change was refused. Messages carry identifiers only., The change would leave no active administrator. (+78 more)

### Community 44 - "test_sso_sealing.py"
Cohesion: 0.15
Nodes (26): cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's…, The token sealed in ``sealed``, or None if it does not open to one. (+18 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (11): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+3 more)

### Community 46 - "warden/cli.py"
Cohesion: 0.07
Nodes (54): BinaryIO, sqlalchemy_exc, AnchorError, Exception, An anchor could not be written. The message carries identifiers only., AnchorReport, The chain's own verification, and each external anchor checked against it., VerificationReport (+46 more)

### Community 47 - "test_webauthn_authentication.py"
Cohesion: 0.17
Nodes (36): _enrolled(), Any, parametrize, UserFactory, UUID, Signing in with a passkey or security key: known-user and discoverable…, _refused(), test_a_counter_that_does_not_increase_is_a_suspected_clone() (+28 more)

### Community 48 - "SyslogSettings"
Cohesion: 0.13
Nodes (21): BaseModel, field_validator, Everything the forwarder, formatter and transports need., SyslogSettings, _lines_with(), Any, parametrize, Path (+13 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Mfa"
Cohesion: 0.12
Nodes (21): SecondFactor, _hash_token(), Mfa, Any, AsyncConnection, ChallengePurpose, UUID, Re-seal every secret not sealed with the current key; returns how many. Run… (+13 more)

### Community 51 - "test_identity_prune.py"
Cohesion: 0.18
Nodes (16): _count(), _expire_all(), _fixtures(), Any, MonkeyPatch, UserFactory, Pruning (#134): expired refresh and single-use tokens, MFA challenges, throttle…, Move every row of ``table`` into the past, keeping its own constraints. (+8 more)

### Community 52 - "User"
Cohesion: 0.11
Nodes (70): User, callback(), completion(), handoff(), provider_code(), Any, AsyncClient, Response (+62 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.13
Nodes (33): dist(), _load(), _only(), fixture, ModuleType, MonkeyPatch, parametrize, Path (+25 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.13
Nodes (30): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+22 more)

### Community 55 - "AuditRow"
Cohesion: 0.05
Nodes (42): BreakReason, _b64url(), _b64url_decode(), Checkpoint, HistoricalVerifier, _int(), MalformedCheckpoint, Any (+34 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.07
Nodes (40): Algorithm, AttestationFormat, CoseKey, cryptography_x509_oid, fido2, fido2_cose, FLAG, PrivateKey (+32 more)

### Community 57 - "Mailer"
Cohesion: 0.26
Nodes (22): MailConfig, Mail settings. The product implements the sender. Provisional until 0.1.0b1., Mailer, MailKind, StrEnum, Renders warden's messages and hands them to the product's sender., parametrize, Mail: the sender protocol, warden's templates and the product's overrides. No… (+14 more)

### Community 58 - "PolicySettings"
Cohesion: 0.11
Nodes (25): PolicySettings, What an administrator sets on a policy: everything but its id, priority and…, The outcome of ``match``: the first match, and whether the range API could not…, Whether the password is refused: a match, or an unreachable API the policy…, The first watch list ``password`` is on under ``policy``; whether the API…, As ``match``, for a fingerprint's digest: every check but terms, which need the…, _settings_of(), WatchListCheck (+17 more)

### Community 59 - "build_reference_app"
Cohesion: 0.12
Nodes (12): build_reference_app(), contract_version(), _NoDatabase, _product_authorisation(), Any, AsyncConnection, FastAPI, Every warden router, mounted under the default prefixes. (+4 more)

### Community 60 - "typing"
Cohesion: 0.03
Nodes (150): argon2, argon2_exceptions, asyncio, base64, binascii, collections, collections_abc, contextlib (+142 more)

### Community 61 - "password_policy/__init__.py"
Cohesion: 0.03
Nodes (100): importlib, Protocol, SecretStore, The built-in common-password list (ruling PW12). A read-only list of common…, ChangeChallenge, _hash(), PasswordChangeChallenges, Any (+92 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.16
Nodes (23): _app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory (+15 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.08
Nodes (23): PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role, fixture, parametrize (+15 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.25
Nodes (13): ASGI middleware setting ``scope["client"]`` to the resolved client address., TrustedProxyMiddleware, _App, _noop(), Any, Trusted-proxy middleware: forwarded headers are believed only from configured…, One gate: only X-Forwarded-For, never Forwarded or X-Real-IP., _scope() (+5 more)

### Community 65 - "test_audit_export.py"
Cohesion: 0.20
Nodes (20): csv_lines(), _csv_record(), escape_cell(), ndjson_lines(), One JSON object per line., ``value``, made safe to open in a spreadsheet., A header line, then one CSV record per row., _collect() (+12 more)

### Community 66 - "current_revision"
Cohesion: 0.10
Nodes (35): current_revision(), heads(), migrate(), The chain's head revisions. A healthy chain has exactly one., Upgrade the database at ``dsn`` to ``revision`` in one transaction., The revision the database is at, or ``None`` if none is applied., _sqlalchemy_url(), dsn() (+27 more)

### Community 67 - "httpx"
Cohesion: 0.10
Nodes (35): httpx, os, Helpers shared by single sign-on tests (imported as ``sso_support``)., sso_config(), app(), config(), Any, FastAPI (+27 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.06
Nodes (47): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+39 more)

### Community 69 - "Sessions"
Cohesion: 0.05
Nodes (39): PolicyError, PolicyStore, Any, AsyncConnection, Event, ValueError, Whether ``listen()`` currently holds a LISTEN on the policy channel., Forget the cached policy; the next ``current()`` re-reads it. (+31 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (22): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, Request (+14 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.17
Nodes (39): UUID, Change the sign-in method behind the services' back (no rule applies)., set_method(), set_status(), admin(), config(), _credential_count(), http() (+31 more)

### Community 72 - "Anchor"
Cohesion: 0.17
Nodes (16): Anchor, _b64url(), _b64url_decode(), _from_ndjson(), _int(), MalformedAnchor, Any, ValueError (+8 more)

### Community 73 - "test_password_rule_vectors.py"
Cohesion: 0.16
Nodes (18): normalise(), NFC, as every rule and the watch-list terms see the password., How a term is stored and compared: NFC, then case folded., term_form(), build(), _case(), Any, The rule test cases behind ``docs/contract/password-rule-vectors.json``. The… (+10 more)

### Community 74 - "DevClock"
Cohesion: 0.08
Nodes (24): Console, The built console: the app and the warden objects behind it., DevClock, The real time plus a settable whole-day offset., Outbox, Any, A ``MailSender`` holding the last ``limit`` messages, newest last., The kept messages, newest first, as the outbox page shows them. (+16 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.07
Nodes (68): bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests., app(), client() (+60 more)

### Community 76 - "test_identity_throttle.py"
Cohesion: 0.19
Nodes (18): _fail(), UserFactory, Sign-in throttling per (identifier, source address)., Otherwise a password holder gets unlimited challenges, and so unlimited code…, Barriered concurrent attempts: no more than the limit reach password…, An attacker elsewhere cannot lock the user out., Throttling must not reveal whether an account exists., test_a_password_alone_does_not_reset_the_count_when_mfa_follows() (+10 more)

### Community 77 - "load_cursor"
Cohesion: 0.16
Nodes (15): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+7 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "SecretBox"
Cohesion: 0.08
Nodes (29): _decode(), _key_id(), new_totp_key(), Exception, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., A TOTP key is missing or malformed. Names the secret, never its value., A fresh 256-bit key, encoded for the secrets store. (+21 more)

### Community 81 - "test_key_publication.py"
Cohesion: 0.07
Nodes (44): PyJWK, _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter (+36 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "test_audit_router.py"
Cohesion: 0.05
Nodes (69): AwareDatetime, csv, description, ExportFormat, io, max_length, Outcome, export() (+61 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.20
Nodes (14): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+6 more)

### Community 86 - "migrate.py"
Cohesion: 0.13
Nodes (22): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), downgrade(), migrate_connection(), Connection (+14 more)

### Community 87 - "test_identity_sign_in.py"
Cohesion: 0.19
Nodes (23): statistics, _assert_refusal(), Any, AsyncClient, parametrize, Response, UserFactory, Password sign-in over HTTP: outcomes, uniform refusals, timing and rehashing. (+15 more)

### Community 88 - "test_sso_admin_routes.py"
Cohesion: 0.16
Nodes (23): app(), authorise(), config(), idp(), Any, AsyncClient, FastAPI, fixture (+15 more)

### Community 89 - "Cluster: Client-behaviour guide"
Cohesion: 0.13
Nodes (23): warden changelog, Passkey sign-in and passkey_only method (0.1.0b11), WebAuthn security keys and passkeys as second factor (0.1.0b10), OIDC single sign-on with PKCE, pre-provisioned accounts, HTTP contract docs/contract/openapi.json, Product-declared permissions and roles (D5), Rotating refresh-token families with reuse detection, Trusted-proxy middleware (+15 more)

### Community 90 - "Cluster: warden design overview"
Cohesion: 0.11
Nodes (23): fido2 runtime dependency (0.1.0b9), Integration procedure (merge, re-chain, stamp), Migrations across parallel workstreams, Mutation-checked guard and tripwire tests, warden project working agreement (CLAUDE.md), Single-use credentials consumed by one guarded atomic write, Acceptance tests from Termograph hardening findings, Argon2id passwords with legacy PBKDF2 rehash (D15) (+15 more)

### Community 91 - "Cluster: modules()"
Cohesion: 0.19
Nodes (20): Pattern, _docstring_nodes(), identifiers(), module_name(), modules(), AST, Path, Helpers for tripwires that read warden's own source. (+12 more)

### Community 92 - "WebAuthnCredentials"
Cohesion: 0.23
Nodes (11): credential_from_row(), Any, AsyncConnection, UUID, The user's credential, or None if they hold no credential with that id., Set or clear the nickname; None if the user holds no such credential., Remove one of the user's credentials; whether it existed., Remove every credential the user holds; how many there were. (+3 more)

### Community 93 - "Challenges"
Cohesion: 0.17
Nodes (12): Ceremony, Challenges, ConsumedChallenge, _hash(), IssuedChallenge, Any, AsyncConnection, StrEnum (+4 more)

### Community 94 - "test_audit_verify.py"
Cohesion: 0.19
Nodes (21): ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id., A forger who recomputes the altered row's hash is caught at the next row., Swap every stored column of two rows except their ids. (+13 more)

### Community 95 - "test_cli_audit_anchor.py"
Cohesion: 0.20
Nodes (20): _export(), FakeSecrets, FakeSettings, Any, CaptureFixture, fixture, Path, The warden CLI: audit anchor, and audit verify --anchors, against a real… (+12 more)

### Community 96 - "attestation.py"
Cohesion: 0.13
Nodes (13): AttestationObject, Certificate, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca(), _issued_by() (+5 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.10
Nodes (11): _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range() (+3 more)

### Community 98 - "WatchLists"
Cohesion: 0.12
Nodes (24): ValueError, Errors raised by password policies and watch lists. Messages carry field names,…, A watch list, or a change to one, was refused., No watch list has that id., An import was refused or failed; the list is left as it was. ``line`` is the…, WatchListError, WatchListImportError, WatchListNotFound (+16 more)

### Community 99 - "resolve_client_ip"
Cohesion: 0.18
Nodes (12): _address(), Any, Network, _Scope, Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``., The client address, given the peer and every ``X-Forwarded-For`` value in order., resolve_client_ip(), _trusted() (+4 more)

### Community 100 - "test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (16): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations() (+8 more)

### Community 101 - "MailMessage"
Cohesion: 0.18
Nodes (7): MailMessage, MailSender, Protocol, One rendered message, ready for the product's sender., Implemented by the product. Raise to report that a message was not delivered., FailingSender, RecordingSender

### Community 102 - "Roles"
Cohesion: 0.15
Nodes (14): lock_administrators(), Any, AsyncConnection, datetime, UUID, Role assignments in ``warden.role_assignments``., The user's unexpired role names., Every assignment the user holds, expired ones included. (+6 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.11
Nodes (11): AuditConfig, _check_secret_name(), _check_url(), IdentityConfig, field_validator, ValueError, A konfig secret name: letters, digits, '.', '_', '/' and '-'., Validate an absolute http(s) URL; plain http only for loopback hosts. The value… (+3 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (30): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+22 more)

### Community 106 - "test_console_passkeys.py"
Cohesion: 0.08
Nodes (76): assert_strict_csp(), authenticator(), bearer(), make_user(), Any, AsyncClient, Response, Helpers shared by the sample console's tests (imported as ``console_support``). (+68 more)

### Community 107 - "test_syslog_routes.py"
Cohesion: 0.24
Nodes (18): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), _audit_rows(), authorise(), _client(), collector() (+10 more)

### Community 108 - "audit_rows"
Cohesion: 0.14
Nodes (25): audit_rows(), AsyncClient, parametrize, UserFactory, test_an_invitation_completes_with_a_password_while_sso_fails(), test_password_sign_in_works_while_sso_fails(), test_the_provider_is_stopped(), app() (+17 more)

### Community 109 - "test_password_watch_lists.py"
Cohesion: 0.10
Nodes (38): StrEnum, WatchListKind, builtin(), _lines(), lists(), policies(), Any, fixture (+30 more)

### Community 110 - "test_password_builtin.py"
Cohesion: 0.32
Nodes (10): _digests(), parametrize, Path, The built-in common-password list (ruling PW12): sorted SHA-1 digests, loaded…, test_a_listed_digest_is_found_and_others_are_not(), test_a_malformed_file_is_refused(), test_an_empty_list_matches_nothing(), test_the_bundled_list_ships() (+2 more)

### Community 111 - "check_dist.py"
Cohesion: 0.11
Nodes (25): argparse, email_parser, dist_problems(), import_problems(), main(), _metadata_version(), Path, Check warden's built distributions, and the installed package, before… (+17 more)

### Community 112 - "main"
Cohesion: 0.22
Nodes (14): main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests.…, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: migrate and keys rotate., _settings() (+6 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (17): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+9 more)

### Community 114 - "test_password_feedback.py"
Cohesion: 0.11
Nodes (29): failing_transport(), handler(), listing_transport(), MockTransport, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., _counts() (+21 more)

### Community 115 - "collector.py"
Cohesion: 0.08
Nodes (13): Framing, ssl, BlackholeCollector, Event, SSLContext, StreamReader, StreamWriter, In-process syslog collectors for tests: stream (TCP or TLS), UDP and a… (+5 more)

### Community 116 - "test_identity_mfa_mail.py"
Cohesion: 0.40
Nodes (9): _confirmed_at(), UserFactory, The MFA-enrolled notice: sent once enrolment is confirmed, never at its expense., _signed_in(), test_a_failed_notice_does_not_undo_the_enrolment(), test_a_signed_in_enrolment_sends_the_notice(), test_a_wrong_code_sends_nothing(), test_an_enrolment_under_a_challenge_sends_the_notice() (+1 more)

### Community 117 - "test_audit_grants.py"
Cohesion: 0.19
Nodes (15): age(), Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then…, _as(), MemorySecrets, _pool(), Any, parametrize, Append-only grants: the application role can only insert and read audit rows.… (+7 more)

### Community 118 - "grants.py"
Cohesion: 0.28
Nodes (15): append_only_grants(), _application(), _forwarder(), grants_sql(), _ident(), _purger(), Composable, Composed (+7 more)

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "parse_config"
Cohesion: 0.16
Nodes (16): reference_config(), _format_errors(), load_config(), parse_config(), Any, Protocol, What warden needs from konfig's ``Settings``., What warden needs from konfig's ``Secrets``. (+8 more)

### Community 121 - "test_sso_issuer.py"
Cohesion: 0.13
Nodes (24): alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer(), Any (+16 more)

### Community 122 - "ActionRegistry"
Cohesion: 0.04
Nodes (78): IntEnum, The audit actions warden's own audit subsystem records., Register warden's audit actions. Idempotent., register_audit_actions(), Event severity, numbered as RFC 5424 syslog severities., Severity, ActionRegistry, ActionSpec (+70 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 125 - ".__init__"
Cohesion: 0.18
Nodes (5): PasswordHasher, Argon2id hashing with legacy PBKDF2 verification. The defaults are…, An Argon2id hash of ``password``., Spend the time one Argon2id verification takes, for a user who has no hash.…, ``secrets`` is konfig's secrets store. It must hold the TOTP encryption key…

### Community 126 - "test_passkey_options_throttle.py"
Cohesion: 0.21
Nodes (28): assert_refused(), passkey_options(), Response, The uniform refusal, byte for byte., other_key(), A key no credential holds, for signatures that must not verify., _challenges(), elsewhere() (+20 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (14): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+6 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.18
Nodes (16): importlib_util, init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch. (+8 more)

### Community 129 - "build_console"
Cohesion: 0.06
Nodes (53): actor(), build_console(), _mount_pages(), FastAPI, Request, Build the console over the product's open pool and konfig's secrets store.…, A FastAPI dependency for warden's audit, syslog and SSO routes. Those routes…, create_administrator() (+45 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "RecordingSender"
Cohesion: 0.08
Nodes (46): The product's mail sender, recording instead of sending. ``fail`` makes it…, RecordingSender, parametrize, UserFactory, Password reset by emailed link: refusal paths, single use (#127), sessions…, #127 for reset tokens., _reasons(), test_a_failed_send_leaves_no_link() (+38 more)

### Community 132 - "MemorySecrets"
Cohesion: 0.14
Nodes (22): make_config(), MemorySecrets, Any, cli_secrets(), fp_identity(), fixture, MemorySecrets, test_keys_may_be_unexpiring_when_no_maximum_is_set() (+14 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "passkey_support.py"
Cohesion: 0.10
Nodes (36): expire_challenge_of(), give_passkey(), http_client(), passkey_app(), passkey_config(), Any, FastAPI, Helpers shared by the passkey tests (imported as ``passkey_support``). An… (+28 more)

### Community 136 - "_FieldProblems"
Cohesion: 0.36
Nodes (4): _FieldProblems, model_validator, Self, Cross-field problems, each with a path relative to the failing model.

### Community 137 - ".prune"
Cohesion: 0.40
Nodes (3): AbstractAsyncContextManager, Delete expired tokens, MFA and WebAuthn challenges, and ended throttle windows., Run ``prune`` every ``every_seconds`` for a block, such as the product's…

### Community 138 - "identity/__init__.py"
Cohesion: 0.04
Nodes (62): enum, NewApiKey, A key just created. ``key`` is shown once and never stored., Forbidden, installed_identity(), HTTPException, Protocol, Request (+54 more)

### Community 139 - "test_examples_public_surface.py"
Cohesion: 0.26
Nodes (12): ast, _private(), _private_path(), Path, Tripwire: the sample console uses only warden's public surface. The sample…, Every reach into a private warden module or name in ``source``., sample_sources(), test_nothing_under_examples_reaches_into_warden_internals() (+4 more)

### Community 140 - "console_router"
Cohesion: 0.15
Nodes (15): _anchor_report(), console_router(), anchor_head(), change_policy(), check_anchors(), import_sample(), move_clock(), reset_policy() (+7 more)

### Community 141 - "test_no_private_imports.py"
Cohesion: 0.36
Nodes (8): ImportFrom, _from_warden(), _private(), Tripwire: no warden module reaches into another module's private names. A…, Local names bound by an import from warden (modules or anything else)., test_no_module_reaches_into_another_modules_private_names(), _violations(), _warden_bindings()

### Community 142 - "test_password_policy_store.py"
Cohesion: 0.16
Nodes (27): Any, fixture, parametrize, UUID, The password policy store (rulings PW1, PW2 and PW11): policies, priorities,…, _settings(), _store(), test_a_change_notifies_in_its_own_transaction() (+19 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.16
Nodes (27): Purpose, StrEnum, Delete expired tokens, whatever their state; returns how many., Tokens in ``warden.single_use_tokens``. Every method works in the caller's…, SingleUseTokens, The token in a sent message's link (the test links end ``?t=<token>``)., _consume(), _issue() (+19 more)

### Community 144 - "test_password_cli.py"
Cohesion: 0.24
Nodes (22): _banned(), _entries(), FakeSettings, _policy(), Any, CaptureFixture, Path, UUID (+14 more)

### Community 145 - "well_formed"
Cohesion: 0.15
Nodes (18): IssuedToken, _live_token(), LiveToken, Any, AsyncConnection, datetime, TypeGuard, UUID (+10 more)

### Community 146 - "BuiltinList"
Cohesion: 0.22
Nodes (7): BuiltinList, _bundled(), _check(), Path, Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled…, _read(), Traversable

### Community 147 - "test_console_capabilities.py"
Cohesion: 0.29
Nodes (8): _admin(), _client(), Any, AsyncClient, The sample console asks warden what the deployment can do, and its screens…, test_with_a_sender_everything_that_mails_is_available(), test_without_a_sender_the_capabilities_say_so_and_the_503_stays(), test_without_the_link_setting_only_the_registration_link_is_unavailable()

### Community 148 - "test_no_direct_environment.py"
Cohesion: 0.31
Nodes (9): _enclosing_functions(), visit(), _findings(), AST, Tripwire: warden reads configuration only through konfig. No module under…, Each node's innermost enclosing function name, keyed by ``id(node)``., Every forbidden use, and whether it is the named exemption., test_each_exemption_covers_exactly_one_read() (+1 more)

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "HttpConfig"
Cohesion: 0.09
Nodes (19): _base_origin(), _check_origin(), _check_template(), HttpConfig, _is_domain(), Validate a UI link template: a path or URL using exactly ``placeholders``., Where the product exposes warden (design D9). Mount prefixes are where the…, The OIDC redirect URI, derived so it cannot disagree with the mount. (+11 more)

### Community 151 - "_AfterFirstQuery"
Cohesion: 0.33
Nodes (4): _AfterFirstQuery, _HookedPool, Any, Delegates to a connection, running ``hook`` once after the checkpoint listing.

### Community 152 - "test_database.py"
Cohesion: 0.46
Nodes (7): _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.18
Nodes (30): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, anonymous(), bearer(), deployment(), make(), member() (+22 more)

### Community 154 - "test_tls_fail_closed.py"
Cohesion: 0.46
Nodes (7): expr, _findings(), _is_cert_required(), _is_true(), Tripwire: nothing in warden turns TLS verification off. Fails on any use of…, test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 155 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.15
Nodes (22): PasswordHistory, Any, AsyncConnection, datetime, UUID, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password., Whether ``password`` matches any of the user's last ``count`` passwords. (+14 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "format_expiry"
Cohesion: 0.25
Nodes (6): format_expiry(), datetime, A time for a message: UTC, to the minute, such as ``4 November 2026 at 03:07…, Render one message to ``email``. Datetime values are formatted with…, Render and deliver one message; returns what was sent., test_format_expiry_is_utc_to_the_minute()

### Community 159 - "KonfigSecrets"
Cohesion: 0.33
Nodes (3): KonfigSecrets, Any, konfig's ``Secrets``, typed as the store warden expects (``get`` and ``set``).

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "test_password_hibp.py"
Cohesion: 0.20
Nodes (18): _client(), LogCaptureFixture, parametrize, Request, Response, The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed…, Recorder, test_a_digest_must_be_twenty_bytes() (+10 more)

### Community 162 - "Identity"
Cohesion: 0.05
Nodes (77): Identity, FastAPI, The signed-in user's security keys and passkeys, oldest first., warden's identity subsystem for one deployment., Make this Identity the one ``require_user`` and ``require_permission`` use., Run identity's background work (the session and password policy listeners) for…, Delete sign-in throttle records whose window has ended., Any (+69 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "pathlib"
Cohesion: 0.07
Nodes (24): pathlib, Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., Question 39 was a defect in the admin route, fixed in warden 0.1.0., test_forbid_user_details_is_no_longer_a_gap(), test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap() (+16 more)

### Community 165 - "PasswordsConfig"
Cohesion: 0.22
Nodes (5): AsyncBaseTransport, PasswordsConfig, Password policies: the fingerprint key and the breached-password range API.…, Whether a policy may enable the sealed fingerprint (ruling PW8)., test_a_transport_error_is_the_same_fixed_error()

### Community 166 - "SecurityHeaders"
Cohesion: 0.22
Nodes (6): Scope, ASGI middleware adding the policy and related headers to every HTTP answer., SecurityHeaders, with_headers(), Receive, Send

### Community 167 - "pytest"
Cohesion: 0.08
Nodes (27): pytest, _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``. (+19 more)

### Community 169 - "._accept"
Cohesion: 0.16
Nodes (12): Complete, MethodCheck, AcceptedInvitation, check(), complete(), PasskeyRegistration, Protocol, The WebAuthn registration, run inside the acceptance transaction. Called with… (+4 more)

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "test_cli_audit.py"
Cohesion: 0.24
Nodes (14): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up() (+6 more)

### Community 173 - "test_cli_audit_errors.py"
Cohesion: 0.18
Nodes (15): copy, _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path (+7 more)

### Community 174 - "test_packaging.py"
Cohesion: 0.22
Nodes (3): packaging_version, warden: identity and audit for Python web applications. The public API lives in…, Packaging: one version source, typed marker, distribution metadata.

### Community 175 - "BaseModel"
Cohesion: 0.25
Nodes (8): AuditEventPage, AuditEventView, BrokenLinkView, ChainVerification, BaseModel, The verification report (documentation only)., One audit row, as listed and as exported in NDJSON (documentation only)., A page of events, newest first (documentation only).

### Community 176 - "test_config_passwords.py"
Cohesion: 0.22
Nodes (18): _parse(), Any, parametrize, Start-up validation of the password settings (rulings PW2, PW7 and PW8 of 10…, _refused(), test_a_fingerprint_key_name_makes_the_fingerprint_available(), test_a_malformed_secret_name_is_refused(), test_a_previous_key_needs_a_current_key() (+10 more)

### Community 177 - "FakeIdp"
Cohesion: 0.12
Nodes (18): FakeIdp, Any, AsyncClient, MockTransport, Request, Response, app(), config() (+10 more)

### Community 178 - "neutralise"
Cohesion: 0.29
Nodes (7): neutralise(), Match, Replace every control character in ``value`` with a visible ``\\xNN`` escape., _replacement(), test_neutralise_leaves_ordinary_text_alone(), test_neutralise_replaces_c1_controls_and_unicode_line_separators(), test_neutralise_replaces_every_c0_control_and_del()

### Community 179 - "test_audit_chain_migration.py"
Cohesion: 0.60
Nodes (5): _columns(), _constraints(), The audit chain migration: reversible, and refuses rows it cannot chain., test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(), test_head_includes_the_chain_revision()

### Community 180 - "JwkSet"
Cohesion: 0.40
Nodes (5): JwkSet, OkpJwk, BaseModel, One published key, an RFC 8037 OKP JSON Web Key (documentation only)., An RFC 7517 JWK Set (documentation only).

### Community 181 - "bundled_list"
Cohesion: 0.50
Nodes (4): console_settings(), bundled_list(), The bundled list, shared by every ``Identity`` in the process so it loads once., test_one_bundled_list_is_shared_by_the_process()

### Community 182 - "licence_audit.py"
Cohesion: 0.23
Nodes (14): packaging_requirements, packaging_utils, audit(), classify(), data_problems(), installed(), main(), _one() (+6 more)

### Community 183 - "SignInThrottle"
Cohesion: 0.06
Nodes (32): PasswordPruning, Pruner, PruneReport, Identifier, Protocol, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., What the pruner needs from password policies. (+24 more)

### Community 184 - "_Section"
Cohesion: 0.50
Nodes (4): DbConfig, BaseModel, Database settings. At runtime warden uses the product's pool, never this DSN., _Section

### Community 185 - "test_cli_errors.py"
Cohesion: 0.24
Nodes (8): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1(), test_migrate_connection_failure_prints_a_fixed_message_and_exits_1()

### Community 187 - "ConnectionSource"
Cohesion: 0.18
Nodes (8): ConnectionSource, AbstractAsyncContextManager, Any, AsyncConnection, Protocol, Anything that lends async connections; ``psycopg_pool.AsyncConnectionPool``…, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - "password_support.py"
Cohesion: 0.21
Nodes (13): bearer(), codes(), lifecycle_app(), pin_policy(), Any, AsyncClient, FastAPI, Response (+5 more)

### Community 191 - "_LazySecrets"
Cohesion: 0.22
Nodes (7): _LazySecrets, _OneConnection, Any, AsyncConnection, A connection source lending a single connection, for one CLI command., konfig ``Secrets``, constructed only if a command actually needs a secret., _rotate()

### Community 192 - "test_identity_roles.py"
Cohesion: 0.25
Nodes (13): _admins(), UserFactory, Role assignments: audited, expiring, and never leaving no administrator., Two administrators demoting each other at once: exactly one demotion succeeds., test_an_administrator_role_cannot_expire(), test_an_expired_assignment_grants_nothing(), test_an_inactive_administrator_does_not_count(), test_assign_and_revoke_are_audited() (+5 more)

### Community 193 - "test_console_password_rules.py"
Cohesion: 0.26
Nodes (11): answers(), cases(), node(), Any, fixture, parametrize, TempPathFactory, The browser's password rules against warden's test vectors. The checklist in… (+3 more)

### Community 195 - ".sso_settings_router"
Cohesion: 0.18
Nodes (6): APIRouter, Invitation acceptance and password reset; mount under…, Administration routes; mount under ``config.http.admin_prefix``. ``permission``…, The public sign-in routes; mount under ``config.http.auth_prefix``., The single sign-on routes; mount under ``config.http.auth_prefix`` too., Single sign-on administration; mount under ``config.http.admin_prefix``.…

### Community 197 - "Notes"
Cohesion: 0.18
Nodes (7): Note, Notes, create_note(), NoteScope, Any, The in-memory note store., The product's resource-scope hook (warden's ``ResourceScopeHook``). warden…

### Community 198 - "_Invalid"
Cohesion: 0.67
Nodes (3): _Invalid, Exception, A policy body refused, with each field at fault and a fixed message.

### Community 200 - "AnchorSigner"
Cohesion: 0.24
Nodes (5): AnchorSigner, _KeyLike, Protocol, What anchoring needs from the key store: ``KeyStore`` fits., _SignatureLike

### Community 201 - "resolve"
Cohesion: 0.22
Nodes (7): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PW1: the pin, else the highest-priority mapped and declared role, else the…, resolve(), test_resolution_order_is_pin_then_highest_priority_role_then_default()

### Community 202 - "notes_router"
Cohesion: 0.38
Nodes (6): notes_router(), delete_note(), found(), update_note(), APIRouter, ``/notes`` routes; the sample mounts them under ``/api``.

### Community 203 - "_audit"
Cohesion: 0.33
Nodes (6): _audit(), IPv4Address, IPv6Address, Request, The client address (already resolved by the trusted-proxy middleware), if it is…, _source()

### Community 206 - "test_identity_totp_storage.py"
Cohesion: 0.36
Nodes (8): MemorySecrets, UserFactory, TOTP secrets are sealed at rest, bound to their user, and survive key rotation., _row(), test_a_secret_copied_to_another_user_does_not_open(), test_identity_refuses_to_start_without_a_totp_key(), test_rotation_keeps_enrolments_working_and_reseals(), test_the_stored_secret_is_sealed()

### Community 207 - "matching_step"
Cohesion: 0.50
Nodes (4): matching_step(), parse_code(), ``code`` if it is exactly six ASCII digits, otherwise None., The step within the window whose code is ``code``, or None. Every candidate is…

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 213 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends an acceptance transaction without committing it.

### Community 219 - "package"
Cohesion: 0.67
Nodes (3): package(), fixture, Install a throwaway template package under a unique name.

## Knowledge Gaps
- **110 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+105 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1934 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **23 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `build_console`, `AuditEvent`, `record_audit`, `KeyStore`, `MemorySecrets`, `reset.py`, `race`, `.prune`, `identity/__init__.py`, `contract.py`, `console_router`, `test_webauthn_mfa.py`, `passkey_support.py`, `SingleUseTokens`, `test_password_cli.py`, `WebAuthn`, `test_sso_invitations.py`, `test_webauthn_reset.py`, `SingleSignOn`, `RecordingSender`, `PasswordEnforcement`, `test_identity_capabilities.py`, `Users`, `identity/conftest.py`, `test_identity_totp_reset.py`, `json_response`, `SsoSettingsStore`, `rules.py`, `current_code`, `test_password_sign_in.py`, `admin.py`, `warden/cli.py`, `test_webauthn_authentication.py`, `FakeIdp`, `Mfa`, `test_identity_prune.py`, `User`, `SignInThrottle`, `Mailer`, `PolicySettings`, `build_reference_app`, `typing`, `password_policy/__init__.py`, `password_support.py`, `PermissionRegistry`, `test_identity_apikeys.py`, `test_identity_roles.py`, `.sso_settings_router`, `httpx`, `Sessions`, `test_identity_dependencies.py`, `test_webauthn_live.py`, `test_passkey_registration_link.py`, `test_password_admin_routes.py`, `test_identity_throttle.py`, `test_identity_admin_routes.py`, `test_identity_totp_storage.py`, `SecretBox`, `test_key_publication.py`, `test_sso_capabilities.py`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `MailMessage`, `Roles`, `test_passkey_invitation.py`, `audit_rows`, `test_password_feedback.py`, `test_identity_mfa_mail.py`, `test_sso_issuer.py`, `Cluster: test_identity_client_address.py`, `.__init__`, `test_passkey_options_throttle.py`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `KeyStore`, `race`, `reset.py`, `test_webauthn_mfa.py`, `test_audit_recorder.py`, `test_webauthn_reset.py`, `WebAuthn`, `test_sso_invitations.py`, `PasswordEnforcement`, `identity/conftest.py`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `test_audit_retention.py`, `test_syslog_forwarder.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `warden/cli.py`, `test_webauthn_authentication.py`, `SyslogSettings`, `test_identity_prune.py`, `User`, `soft_authenticator.py`, `PolicySettings`, `build_reference_app`, `typing`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `httpx`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_admin_routes.py`, `test_identity_throttle.py`, `test_identity_admin_routes.py`, `SecretBox`, `test_key_publication.py`, `test_audit_router.py`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `WebAuthnCredentials`, `Challenges`, `test_audit_verify.py`, `attestation.py`, `Roles`, `field_validator`, `test_passkey_invitation.py`, `test_syslog_routes.py`, `audit_rows`, `test_password_watch_lists.py`, `test_password_feedback.py`, `test_identity_mfa_mail.py`, `test_audit_grants.py`, `test_sso_issuer.py`, `ActionRegistry`, `Cluster: test_identity_client_address.py`, `.__init__`, `test_passkey_options_throttle.py`, `build_console`, `RecordingSender`, `MemorySecrets`, `passkey_support.py`, `identity/__init__.py`, `test_password_policy_store.py`, `SingleUseTokens`, `test_password_cli.py`, `BuiltinList`, `test_database.py`, `test_identity_capabilities.py`, `PasswordHistory`, `Identity`, `SignInThrottle`, `ConnectionSource`, `_LazySecrets`, `test_identity_roles.py`, `.__init__`, `test_identity_totp_storage.py`?**
  _High betweenness centrality (0.100) - this node is a cross-community bridge._
- **Why does `AuditEvent` connect `AuditEvent` to `syslog/__init__.py`, `record_audit`, `reset.py`, `Database`, `contract.py`, `build_password_admin_router`, `test_audit_recorder.py`, `PasswordPolicies`, `SingleSignOn`, `Invitations`, `PasswordEnforcement`, `Users`, `test_audit_chain.py`, `SsoSettingsStore`, `test_audit_retention.py`, `test_syslog_forwarder.py`, `SyslogSettings`, `Mfa`, `AuditRow`, `typing`, `password_policy/__init__.py`, `Sessions`, `Anchor`, `_audit`, `test_audit_router.py`, `test_audit_verify.py`, `WatchLists`, `Roles`, `test_syslog_routes.py`, `test_audit_grants.py`, `ActionRegistry`?**
  _High betweenness centrality (0.027) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Are the 93 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 93 INFERRED edges - model-reasoned connections that need verification._
- **Are the 152 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 152 INFERRED edges - model-reasoned connections that need verification._
- **Are the 134 inferred relationships involving `KeyStore` (e.g. with `build_console()` and `Console`) actually correct?**
  _`KeyStore` has 134 INFERRED edges - model-reasoned connections that need verification._