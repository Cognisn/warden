# Graph Report - warden  (2026-11-10)

## Corpus Check
- 319 files · ~316,301 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 6707 nodes · 21764 edges · 224 communities (206 shown, 18 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2036 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d9e32612`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- typing
- FakeIdp
- ApiKeys
- AuthenticationRefused
- KeyStore
- RecordingSender
- test_identity_tokens.py
- AuditRecorder
- h
- test_webauthn_mfa.py
- contract.py
- password_admin.py
- passkey_support.py
- test_audit_recorder.py
- syslog/__init__.py
- WebAuthn
- AuditEvent
- Database
- PasswordPolicies
- ._refuse
- Invitations
- WebAuthn Ceremonies
- test_audit_anchor_format.py
- record_audit
- invitations.py
- test_webauthn_reset.py
- test_audit_chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- SsoSettings
- CI Workflows
- test_audit_retention.py
- ActionRegistry
- test_identity_key_publication.py
- test_identity_passwords.py
- test_syslog_forwarder.py
- test_password_rules.py
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
- mail.py
- test_password_recheck.py
- build_reference_app
- identity/__init__.py
- password_policy/__init__.py
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- MemorySecrets
- current_revision
- pytest
- test_webauthn_live.py
- Sessions
- test_identity_dependencies.py
- test_passkey_registration_link.py
- SecurityHeaders
- sso.py
- test_passkey_options_throttle.py
- test_password_admin_routes.py
- roles.py
- client_ip
- test_identity_admin_routes.py
- test_webauthn_migration.py
- SecretBox
- Cluster: test_key_publication.py
- test_sso_capabilities.py
- AuditQuery
- test_openapi_contract.py
- test_identity_migration.py
- migrate.py
- audit_rows
- test_sso_admin_routes.py
- Cluster: Client-behaviour guide
- Cluster: warden design overview
- Cluster: modules()
- pathlib
- test_audit_router.py
- verify_chain
- main
- attestation.py
- test_db_schema.py
- watchlists.py
- SingleSignOn
- Cluster: test_sso_preset_label_only.py
- .register
- test_syslog_sd_id.py
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- test_console_passkeys.py
- test_syslog_routes.py
- Cluster: test_identity_lifecycle_routes.py
- WatchLists
- WardenConfig
- check_dist.py
- Cluster: test_cli.py
- Cluster: Audit hash chain specification
- test_password_feedback.py
- collector.py
- CheckpointSigner
- test_audit_grants.py
- grants.py
- Cluster: with
- parse_config
- test_identity_mfa_mail.py
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- test_public_api.py
- keys_router
- test_lifecycle_migration.py
- test_bump_version.py
- build_console
- test_password_policy_migration.py
- http
- ._accept
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- test_readme.py
- _FieldProblems
- AnchorSigner
- webauthn/service.py
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- Fingerprints
- well_formed
- BuiltinList
- test_password_cli.py
- test_no_direct_environment.py
- Cluster: updates
- config.py
- test_a_purge_committing_during_verification_breaks_nothing
- test_database.py
- test_identity_capabilities.py
- Cluster: test_tls_fail_closed.py
- SsoSettingsStore
- PasswordHistory
- Cluster: verify
- test_watch_list_admin_routes.py
- console/cli.py
- Cluster: rsyslog
- HibpRangeClient
- Identity
- test_licence_audit.py
- register_syslog_actions
- lifecycle.py
- audit_router
- sys
- Cluster: examples/__init__.py
- rules.py
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- test_cli_audit.py
- test_cli_audit_errors.py
- test_config_passwords.py
- race
- identity
- fake_idp.py
- test_audit_export.py
- .__init__
- PasswordRules
- PolicySettings
- licence_audit.py
- throttle.py
- require_permission
- copy
- password_support.py
- ConnectionSource
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- test_password_rule_vectors.py
- _LazySecrets
- resolve
- .from_description
- Notes
- InvitationAcceptance
- Refused
- notes_router
- _Invalid
- _PinRefused
- test_identity_totp_storage.py
- BaseModel
- test_nothing_secret_is_recorded_logged_or_raised
- _Abort
- test_inviting_an_existing_address_is_refused
- The built-in common-password list
- JwkSet
- _NoDatabase
- ._ordered
- .where
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

## Communities (224 total, 18 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.14
Nodes (47): passkey_assertion(), passkey_sign_in(), AsyncClient, UUID, Change the sign-in method behind the services' back (no rule applies)., set_method(), set_status(), _admin() (+39 more)

### Community 1 - "typing"
Cohesion: 0.03
Nodes (104): collections, collections_abc, contextlib, dataclasses, decimal, Console, The sample console's application: how a product wires warden into FastAPI. Read…, The built console: the app and the warden objects behind it. (+96 more)

### Community 2 - "FakeIdp"
Cohesion: 0.06
Nodes (64): Discovery, JwksCache, ProviderHttp, ProviderMetadata, AsyncClient, The provider's metadata, cached per issuer., Fetch and check the metadata, bypassing the cache., The provider's signing keys, by key id. (+56 more)

### Community 3 - "ApiKeys"
Cohesion: 0.12
Nodes (18): ApiKey, ApiKeys, _hash(), NewApiKey, Any, datetime, NoReturn, SourceIp (+10 more)

### Community 4 - "AuthenticationRefused"
Cohesion: 0.04
Nodes (60): Principal, The signed-in user behind a request. For a request made with an API key,…, AuthenticationRefused, Exception, A credential was refused. ``reason`` is for the audit trail and tests only. It…, Challenge, _Account, _credential_id() (+52 more)

### Community 5 - "KeyStore"
Cohesion: 0.05
Nodes (67): Ed25519PrivateKey, KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., _b64url(), _b64url_decode(), key_id_for(), KeyStore, KeyStoreError (+59 more)

### Community 6 - "RecordingSender"
Cohesion: 0.10
Nodes (52): A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, The product's mail sender, recording instead of sending. ``fail`` makes it…, RecordingSender, _accept(), FakePins (+44 more)

### Community 7 - "test_identity_tokens.py"
Cohesion: 0.15
Nodes (33): _b64(), _parts(), AsyncClient, parametrize, UserFactory, Access tokens and refresh families., Token verification uses KeyStore.verify, never verify_historical., #131: a replayed refresh token is detected through its family. (+25 more)

### Community 8 - "AuditRecorder"
Cohesion: 0.11
Nodes (62): AnchorRecord, ExternalAnchor, An anchor written to the trail, and the id of the row that carries it., An anchor found in an export: its line, its own row id when known, and the…, AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors() (+54 more)

### Community 9 - "h"
Cohesion: 0.09
Nodes (102): apiKeysScreen(), capabilities(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames() (+94 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.11
Nodes (71): enrol_totp(), Enrol and confirm TOTP for ``user``; returns the secret. Confirmation claims…, _amr(), _app(), _assertion(), _bearer(), _challenge(), http() (+63 more)

### Community 11 - "contract.py"
Cohesion: 0.04
Nodes (90): Public sign-in routes. The product mounts them under…, ChallengeBody, ChangePasswordBody, CodeBody, _Doc, EnrolmentBody, EnrolmentConfirmBody, HandoffBody (+82 more)

### Community 12 - "password_admin.py"
Cohesion: 0.06
Nodes (95): AffectedUsersProposalBody, BuiltinListBody, PasswordPolicyCreateBody, PasswordPolicyOrderBody, PasswordPolicyPinBody, PasswordPolicyPriorityBody, PasswordPolicyRoleBody, PasswordPolicyUpdateBody (+87 more)

### Community 13 - "passkey_support.py"
Cohesion: 0.10
Nodes (36): expire_challenge_of(), give_passkey(), http_client(), passkey_app(), passkey_config(), Any, FastAPI, Helpers shared by the passkey tests (imported as ``passkey_support``). An… (+28 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.13
Nodes (31): Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any (+23 more)

### Community 15 - "syslog/__init__.py"
Cohesion: 0.05
Nodes (31): DatagramTransport, errno, socket, Syslog forwarding of committed audit rows (RFC 5424 over UDP, TCP or TLS)., BaseModel, Whether the test message reached the transport, and if not, why (a fixed…, Send one test message over a fresh connection with the forwarder's settings., send_test_message() (+23 more)

### Community 16 - "WebAuthn"
Cohesion: 0.11
Nodes (61): fido2_utils, The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, LogCaptureFixture, parametrize (+53 more)

### Community 17 - "AuditEvent"
Cohesion: 0.06
Nodes (31): AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., AuditChainConflict, Any, AsyncConnection, Exception, Record ``event`` and return its row id. With ``conn``, the row is written… (+23 more)

### Community 18 - "Database"
Cohesion: 0.11
Nodes (61): Body, Database, warden's handle on the product's connection pool., ``check_limit`` is the password check budget per credential (by default…, Started, accept(), acceptance_rows(), app() (+53 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.08
Nodes (44): PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, A password policy, or a change to one, was refused., No password policy has that id., The change clashes with the stored state: a stale version, a name or priority…, Delete history beyond the largest count any policy keeps; returns how many., _check_priority() (+36 more)

### Community 20 - "._refuse"
Cohesion: 0.16
Nodes (16): _challenge(), _hash(), Any, AsyncConnection, NoReturn, SourceIp, UUID, Start a sign-in; with ``invitation`` (the link's token), an invitation… (+8 more)

### Community 21 - "Invitations"
Cohesion: 0.13
Nodes (17): Invitation, InvitationError, Invitations, _Invitee, Any, AsyncConnection, datetime, UUID (+9 more)

### Community 22 - "WebAuthn Ceremonies"
Cohesion: 0.11
Nodes (25): PublicKeyCredentialDescriptor, Exception, A WebAuthn ceremony or credential change was refused. ``user_id`` and…, Whether the refusal reports a credential that may have been copied., WebAuthnError, _extension_results(), _parse(), Any (+17 more)

### Community 23 - "test_audit_anchor_format.py"
Cohesion: 0.09
Nodes (47): cryptography_hazmat_primitives_asymmetric_ed25519, Anchor, _b64url(), _b64url_decode(), _from_ndjson(), _int(), MalformedAnchor, Any (+39 more)

### Community 24 - "record_audit"
Cohesion: 0.05
Nodes (62): SetPlace, Record ``event`` through the installed recorder. See ``AuditRecorder.record``., record_audit(), AcceptedPassword, PasswordAdvice, PasswordEnforcement, PasswordFailure, PasswordFeedback (+54 more)

### Community 25 - "invitations.py"
Cohesion: 0.12
Nodes (27): Invitations: an invited user, staged role grants, and a single-use link.…, _link_refusal(), Why a user may not have a passkey registration link, or None (ruling P8)., check_email(), Any, AsyncConnection, Composable, datetime (+19 more)

### Community 26 - "test_webauthn_reset.py"
Cohesion: 0.19
Nodes (24): _admin(), _bearer(), http(), Any, AsyncClient, fixture, MonkeyPatch, Response (+16 more)

### Community 27 - "test_audit_chain.py"
Cohesion: 0.09
Nodes (36): JsonValue, address_text(), canonical_json(), cap_details(), _encode(), _number(), Any, IPv4Address (+28 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.09
Nodes (48): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+40 more)

### Community 29 - "test_config.py"
Cohesion: 0.06
Nodes (84): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, FakeSecrets, FakeSettings, _load(), Any, parametrize (+76 more)

### Community 30 - "json_response"
Cohesion: 0.08
Nodes (73): bearer_token(), json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), build_auth_router() (+65 more)

### Community 31 - "SsoSettings"
Cohesion: 0.15
Nodes (14): _from_config(), _plain(), Any, AsyncConnection, The effective settings, cached for ``max_age`` seconds., The effective settings, read now on ``conn`` (no cache)., Override some fields: validated as a whole, audited, and, when this turns…, Drop every override, returning to configuration. (+6 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_audit_retention.py"
Cohesion: 0.11
Nodes (39): purge(), _purge_prefix(), Any, AsyncConnection, datetime, Exception, A purge was refused. The message carries row ids only., Delete audit rows older than ``retention_days`` behind a signed checkpoint. (+31 more)

### Community 34 - "ActionRegistry"
Cohesion: 0.09
Nodes (50): ActionRegistry, The set of actions this deployment records., Register a product action. Re-registering an identical spec is a no-op. Actions…, The spec for ``action``; ``KeyError`` if it was never registered., AuditRecord, _clip(), format_message(), build() (+42 more)

### Community 35 - "test_identity_key_publication.py"
Cohesion: 0.26
Nodes (14): jwt, PyJWK, _access_token(), _b64(), _decode(), keys_client(), _published_key(), Any (+6 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.13
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.14
Nodes (48): ForwarderFactory, dsn(), migrated_dsn(), pg_admin_url(), pool(), Any, fixture, Shared fixtures. Database tests use a real Postgres through testcontainers. (+40 more)

### Community 38 - "test_password_rules.py"
Cohesion: 0.18
Nodes (24): _failed(), parametrize, The password rule engine (rulings PW3, PW4 and PW5): pure, deterministic, no…, _rules(), test_a_combining_mark_that_does_not_compose_counts_but_belongs_to_no_class(), test_a_description_of_another_version_is_refused(), test_a_passphrase_may_waive_the_class_rule_but_nothing_else(), test_a_relaxed_passphrase_lowers_the_catch_all_class_requirement() (+16 more)

### Community 39 - "current_code"
Cohesion: 0.10
Nodes (49): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), _challenge(), _enrolled(), _fresh_code() (+41 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.14
Nodes (35): frame(), open_transport(), Connect to the collector named in ``settings``; ``TransportError`` on failure., Frame ``message`` for a stream transport (RFC 6587)., Authority, A TCP (or, with ``ssl``, TLS) collector that records raw bytes and frames., Stop listening and drop every open connection, as a stopped collector would., StreamCollector (+27 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.14
Nodes (46): Clock, A settable clock for ``Identity(clock=...)``: real time plus an offset., Replace the default policy's settings (keeping its name)., set_default(), _amr(), clock(), _complete(), identity() (+38 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.06
Nodes (31): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+23 more)

### Community 43 - "admin.py"
Cohesion: 0.07
Nodes (69): _api_key(), _assignment(), _BadRequest, build_admin_router(), assign_role(), capabilities(), create_key(), invite() (+61 more)

### Community 44 - "test_sso_sealing.py"
Cohesion: 0.15
Nodes (26): cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's…, The token sealed in ``sealed``, or None if it does not open to one. (+18 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (11): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+3 more)

### Community 46 - "warden/cli.py"
Cohesion: 0.08
Nodes (47): BinaryIO, sqlalchemy_exc, Register warden's audit actions. Idempotent., register_audit_actions(), AnchorError, Exception, An anchor could not be written. The message carries identifiers only., PurgeResult (+39 more)

### Community 47 - "test_webauthn_authentication.py"
Cohesion: 0.17
Nodes (36): _enrolled(), Any, parametrize, UserFactory, UUID, Signing in with a passkey or security key: known-user and discoverable…, _refused(), test_a_counter_that_does_not_increase_is_a_suspected_clone() (+28 more)

### Community 48 - "SyslogSettings"
Cohesion: 0.12
Nodes (22): BaseModel, field_validator, Everything the forwarder, formatter and transports need., SyslogSettings, _lines_with(), Any, parametrize, Path (+14 more)

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
Nodes (70): An opaque cursor for ``list(after=...)``: the users listed after ``user``., User, callback(), completion(), handoff(), provider_code(), Any, AsyncClient (+62 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.13
Nodes (33): dist(), _load(), _only(), fixture, ModuleType, MonkeyPatch, parametrize, Path (+25 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.14
Nodes (29): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+21 more)

### Community 55 - "AuditRow"
Cohesion: 0.08
Nodes (30): BreakReason, _b64url(), _b64url_decode(), Checkpoint, _int(), MalformedCheckpoint, Any, ValueError (+22 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.13
Nodes (25): CoseKey, fido2, fido2_cose, ca(), make_webauthn(), factory(), Any, fixture (+17 more)

### Community 57 - "mail.py"
Cohesion: 0.07
Nodes (49): html, MailConfig, Mail settings. The product implements the sender. Provisional until 0.1.0b1., _check(), format_expiry(), _is_control(), _load(), MailDeliveryError (+41 more)

### Community 58 - "test_password_recheck.py"
Cohesion: 0.18
Nodes (17): _config(), fp_identity(), Any, fixture, Request, Response, Range, range_api() (+9 more)

### Community 59 - "build_reference_app"
Cohesion: 0.17
Nodes (9): build_reference_app(), contract_version(), _product_authorisation(), FastAPI, Every warden router, mounted under the default prefixes., Stands in for the product's dependency, which refuses or returns an actor id., The contract's version: the release series, so pre-release stamps leave it…, reference_config() (+1 more)

### Community 60 - "identity/__init__.py"
Cohesion: 0.04
Nodes (71): argon2, argon2_exceptions, asyncio, base64, binascii, cryptography_exceptions, Creating the first administrator. warden's own CLI cannot do this, because the…, hashlib (+63 more)

### Community 61 - "password_policy/__init__.py"
Cohesion: 0.06
Nodes (56): _match_details(), Require a change (the first reason stands) and audit it; whether newly required., ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID (+48 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.14
Nodes (26): ApiKeyError, Exception, An API key change was refused. Messages carry no values., _app(), _bearer(), client(), AsyncClient, FastAPI (+18 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.08
Nodes (21): permissions(), The product's permission registry and role sets., PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role (+13 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.12
Nodes (26): _address(), Any, Network, _Scope, Trusted-proxy middleware: the real client address behind a reverse proxy. A…, Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``., The client address, given the peer and every ``X-Forwarded-For`` value in order., ASGI middleware setting ``scope["client"]`` to the resolved client address. (+18 more)

### Community 65 - "MemorySecrets"
Cohesion: 0.16
Nodes (19): make_config(), MemorySecrets, Any, cli_secrets(), fp_identity(), fixture, MemorySecrets, test_keys_may_be_unexpiring_when_no_maximum_is_set() (+11 more)

### Community 66 - "current_revision"
Cohesion: 0.11
Nodes (31): current_revision(), heads(), migrate(), The chain's head revisions. A healthy chain has exactly one., Upgrade the database at ``dsn`` to ``revision`` in one transaction., The revision the database is at, or ``None`` if none is applied., _columns(), _constraints() (+23 more)

### Community 67 - "pytest"
Cohesion: 0.07
Nodes (45): httpx, os, pytest, Helpers shared by identity tests (imported as ``identity_support``)., app(), config(), Any, AsyncClient (+37 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.06
Nodes (47): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+39 more)

### Community 69 - "Sessions"
Cohesion: 0.06
Nodes (36): PolicyError, PolicyStore, Any, AsyncConnection, Event, ValueError, Whether ``listen()`` currently holds a LISTEN on the policy channel., Forget the cached policy; the next ``current()`` re-reads it. (+28 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (22): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, Request (+14 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.20
Nodes (34): admin(), config(), _credential_count(), http(), _identity(), _link(), _options(), Any (+26 more)

### Community 72 - "SecurityHeaders"
Cohesion: 0.22
Nodes (6): Scope, ASGI middleware adding the policy and related headers to every HTTP answer., SecurityHeaders, with_headers(), Receive, Send

### Community 73 - "sso.py"
Cohesion: 0.18
Nodes (20): fastapi_responses, _body_field(), build_sso_router(), callback(), clear_cookie(), failed(), handoff(), land() (+12 more)

### Community 74 - "test_passkey_options_throttle.py"
Cohesion: 0.21
Nodes (28): assert_refused(), passkey_options(), Response, The uniform refusal, byte for byte., other_key(), A key no credential holds, for signatures that must not verify., _challenges(), elsewhere() (+20 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.11
Nodes (44): bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests., app(), client() (+36 more)

### Community 76 - "roles.py"
Cohesion: 0.12
Nodes (22): LastAdministratorError, lock_administrators(), Any, AsyncConnection, datetime, Exception, UUID, Roles and permissions (design D5). The product registers its permissions and… (+14 more)

### Community 77 - "client_ip"
Cohesion: 0.11
Nodes (25): client_ip(), Network, Request, SourceIp, The client address, for audit events and the sign-in throttle key. Resolved by…, build_sso_settings_router(), actor_id(), get_settings() (+17 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "SecretBox"
Cohesion: 0.09
Nodes (26): _decode(), _key_id(), new_totp_key(), Exception, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., A TOTP key is missing or malformed. Names the secret, never its value., A fresh 256-bit key, encoded for the secrets store. (+18 more)

### Community 81 - "Cluster: test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "AuditQuery"
Cohesion: 0.16
Nodes (25): ExportFormat, export(), Record the export, then stream the matching rows in chain order. The export…, AuditQuery, iter_events(), list_events(), BaseModel, Every matching row in chain (id) order, from one consistent snapshot. (+17 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.19
Nodes (15): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+7 more)

### Community 86 - "migrate.py"
Cohesion: 0.12
Nodes (23): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), downgrade(), migrate_connection(), Connection (+15 more)

### Community 87 - "audit_rows"
Cohesion: 0.20
Nodes (24): statistics, audit_rows(), _assert_refusal(), Any, AsyncClient, parametrize, Response, UserFactory (+16 more)

### Community 88 - "test_sso_admin_routes.py"
Cohesion: 0.16
Nodes (24): sso_config(), app(), authorise(), config(), idp(), Any, AsyncClient, FastAPI (+16 more)

### Community 89 - "Cluster: Client-behaviour guide"
Cohesion: 0.13
Nodes (23): warden changelog, Passkey sign-in and passkey_only method (0.1.0b11), WebAuthn security keys and passkeys as second factor (0.1.0b10), OIDC single sign-on with PKCE, pre-provisioned accounts, HTTP contract docs/contract/openapi.json, Product-declared permissions and roles (D5), Rotating refresh-token families with reuse detection, Trusted-proxy middleware (+15 more)

### Community 90 - "Cluster: warden design overview"
Cohesion: 0.11
Nodes (23): fido2 runtime dependency (0.1.0b9), Integration procedure (merge, re-chain, stamp), Migrations across parallel workstreams, Mutation-checked guard and tripwire tests, warden project working agreement (CLAUDE.md), Single-use credentials consumed by one guarded atomic write, Acceptance tests from Termograph hardening findings, Argon2id passwords with legacy PBKDF2 rehash (D15) (+15 more)

### Community 91 - "Cluster: modules()"
Cohesion: 0.19
Nodes (20): Pattern, _docstring_nodes(), identifiers(), module_name(), modules(), AST, Path, Helpers for tripwires that read warden's own source. (+12 more)

### Community 92 - "pathlib"
Cohesion: 0.05
Nodes (35): cryptography, cryptography_hazmat_primitives, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, cryptography_x509_oid, pathlib, Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0. (+27 more)

### Community 93 - "test_audit_router.py"
Cohesion: 0.16
Nodes (21): client(), exporter(), NoKeys, Any, AsyncClient, fixture, parametrize, Audit routers: list, export and verify, behind the product's own authorisation. (+13 more)

### Community 94 - "verify_chain"
Cohesion: 0.19
Nodes (23): Verify the chain, from its first surviving row to ``through_id`` (or the head)., verify_chain(), ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id. (+15 more)

### Community 95 - "main"
Cohesion: 0.20
Nodes (22): main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests.…, _export(), FakeSecrets, FakeSettings, Any, CaptureFixture, fixture (+14 more)

### Community 96 - "attestation.py"
Cohesion: 0.14
Nodes (13): AttestationObject, Certificate, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca(), _issued_by() (+5 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.10
Nodes (11): _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range() (+3 more)

### Community 98 - "watchlists.py"
Cohesion: 0.09
Nodes (31): ValueError, Errors raised by password policies and watch lists. Messages carry field names,…, A watch list, or a change to one, was refused., No watch list has that id., The change clashes with the stored state: a list still attached to a policy., An import was refused or failed; the list is left as it was. ``line`` is the…, WatchListConflict, WatchListError (+23 more)

### Community 99 - "SingleSignOn"
Cohesion: 0.06
Nodes (43): Exception, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic(), _https(), _KeySet, parse_metadata(), Any (+35 more)

### Community 100 - "Cluster: test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (16): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations() (+8 more)

### Community 101 - ".register"
Cohesion: 0.15
Nodes (14): Algorithm, AttestationFormat, FLAG, PrivateKey, _new_key(), Any, AuthenticatorData, CollectedClientData (+6 more)

### Community 102 - "test_syslog_sd_id.py"
Cohesion: 0.14
Nodes (20): Any, model_validator, Self, Build settings from the shared ``SyslogConfig``. ``secrets`` looks up a konfig…, Syslog forwarding: every field ``SyslogSettings`` needs.…, SyslogConfig, _config(), Any (+12 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.12
Nodes (9): _check_secret_name(), _check_url(), IdentityConfig, field_validator, ValueError, A konfig secret name: letters, digits, '.', '_', '/' and '-'., Validate an absolute http(s) URL; plain http only for loopback hosts. The value…, OIDC single sign-on. Provisional until 0.1.0b1: the single sign-on workstream… (+1 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (30): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+22 more)

### Community 106 - "test_console_passkeys.py"
Cohesion: 0.06
Nodes (81): create_administrator(), Create an active user with ``password`` holding the administrator role. Running…, client(), console(), make_console(), build(), Any, AsyncClient (+73 more)

### Community 107 - "test_syslog_routes.py"
Cohesion: 0.23
Nodes (19): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), _audit_rows(), authorise(), _client(), collector() (+11 more)

### Community 108 - "Cluster: test_identity_lifecycle_routes.py"
Cohesion: 0.20
Nodes (18): app(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory, Public lifecycle routes: accept an invitation, request and complete a password… (+10 more)

### Community 109 - "WatchLists"
Cohesion: 0.12
Nodes (39): Watch lists, their entries and terms, imports, and matching., WatchListKind, WatchLists, builtin(), _lines(), lists(), policies(), Any (+31 more)

### Community 110 - "WardenConfig"
Cohesion: 0.26
Nodes (14): warden's whole configuration: one object, validated once at start-up., WardenConfig, parametrize, Session policy: defaults from configuration, audited changes, cross-replica…, The product wraps its app's lifespan in ``identity.running()``., Replica B caches the policy for an hour, yet sees A's change at once via NOTIFY., _store(), test_a_change_reaches_another_replica_promptly() (+6 more)

### Community 111 - "check_dist.py"
Cohesion: 0.11
Nodes (25): argparse, email_parser, dist_problems(), import_problems(), main(), _metadata_version(), Path, Check warden's built distributions, and the installed package, before… (+17 more)

### Community 112 - "Cluster: test_cli.py"
Cohesion: 0.22
Nodes (12): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: migrate and keys rotate., _settings(), test_invalid_configuration_fails_before_doing_anything(), test_keys_rotate_adds_a_key_and_prints_only_its_id() (+4 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (17): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+9 more)

### Community 114 - "test_password_feedback.py"
Cohesion: 0.11
Nodes (30): failing_transport(), handler(), listing_transport(), MockTransport, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., _counts() (+22 more)

### Community 115 - "collector.py"
Cohesion: 0.08
Nodes (13): Framing, ssl, BlackholeCollector, Event, SSLContext, StreamReader, StreamWriter, In-process syslog collectors for tests: stream (TCP or TLS), UDP and a… (+5 more)

### Community 116 - "CheckpointSigner"
Cohesion: 0.24
Nodes (5): CheckpointSigner, _KeyLike, Protocol, What a purge needs from the key store: ``KeyStore`` fits., _SignatureLike

### Community 117 - "test_audit_grants.py"
Cohesion: 0.13
Nodes (20): age(), Any, Connection, Test-only helpers that stand in for audit rows recorded long ago. Ageing a row…, Recompute every hash and link from the first surviving row's ``prev_hash``., Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then…, rechain(), _as() (+12 more)

### Community 118 - "grants.py"
Cohesion: 0.28
Nodes (15): append_only_grants(), _application(), _forwarder(), grants_sql(), _ident(), _purger(), Composable, Composed (+7 more)

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "parse_config"
Cohesion: 0.22
Nodes (12): _format_errors(), load_config(), parse_config(), Any, Protocol, What warden needs from konfig's ``Settings``., What warden needs from konfig's ``Secrets``., Validate a settings tree into ``WardenConfig`` or raise ``ConfigError``. (+4 more)

### Community 121 - "test_identity_mfa_mail.py"
Cohesion: 0.40
Nodes (9): _confirmed_at(), UserFactory, The MFA-enrolled notice: sent once enrolment is confirmed, never at its expense., _signed_in(), test_a_failed_notice_does_not_undo_the_enrolment(), test_a_signed_in_enrolment_sends_the_notice(), test_a_wrong_code_sends_nothing(), test_an_enrolment_under_a_challenge_sends_the_notice() (+1 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.17
Nodes (27): _assert_one_unforked_chain(), _event(), Any, fixture, The chained recorder: links, server-side order, the details cap, and…, Poll until backend ``pid`` waits on the chain's advisory lock., Row id order is commit order: the second inserter waits for the first's commit., A server default of REPEATABLE READ must not make warden's own writes conflict. (+19 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 125 - "test_public_api.py"
Cohesion: 0.12
Nodes (8): importlib, packaging_version, warden: identity and audit for Python web applications. The public API lives in…, Packaging: one version source, typed marker, distribution metadata., parametrize, The public import surface, fixed as a snapshot. warden's public API is whatever…, test_every_exported_name_resolves_once(), test_the_public_names_match_the_snapshot()

### Community 126 - "keys_router"
Cohesion: 0.25
Nodes (9): _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter, Response (+1 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (15): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+7 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.18
Nodes (16): importlib_util, init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch. (+8 more)

### Community 129 - "build_console"
Cohesion: 0.15
Nodes (10): actor(), build_console(), _mount_pages(), FastAPI, Request, A FastAPI dependency for warden's audit, syslog and SSO routes. Those routes…, Build the console over the product's open pool and konfig's secrets store.…, work() (+2 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "http"
Cohesion: 0.11
Nodes (27): http(), _administrator(), _change(), _codes(), _create(), _forced(), _hash(), _http_failures() (+19 more)

### Community 132 - "._accept"
Cohesion: 0.14
Nodes (16): Complete, Method, MethodCheck, AcceptedInvitation, InvitationMismatch, check(), complete(), NoReturn (+8 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "test_readme.py"
Cohesion: 0.43
Nodes (5): README.md is the PyPI project description, so it must render there without…, _targets(), test_every_link_is_absolute(), test_link_check_refuses_relative_link_and_image(), test_readme_has_links()

### Community 136 - "_FieldProblems"
Cohesion: 0.36
Nodes (4): _FieldProblems, model_validator, Self, Cross-field problems, each with a path relative to the failing model.

### Community 137 - "AnchorSigner"
Cohesion: 0.24
Nodes (5): AnchorSigner, _KeyLike, Protocol, What anchoring needs from the key store: ``KeyStore`` fits., _SignatureLike

### Community 138 - "webauthn/service.py"
Cohesion: 0.07
Nodes (44): enum, Ceremony, Challenges, ConsumedChallenge, _hash(), IssuedChallenge, Any, AsyncConnection (+36 more)

### Community 139 - "test_examples_public_surface.py"
Cohesion: 0.26
Nodes (12): ast, _private(), _private_path(), Path, Tripwire: the sample console uses only warden's public surface. The sample…, Every reach into a private warden module or name in ``source``., sample_sources(), test_nothing_under_examples_reaches_into_warden_internals() (+4 more)

### Community 140 - "console_router"
Cohesion: 0.17
Nodes (13): _anchor_report(), console_router(), anchor_head(), change_policy(), check_anchors(), reset_policy(), show_policy(), syslog_settings() (+5 more)

### Community 141 - "test_no_private_imports.py"
Cohesion: 0.36
Nodes (8): ImportFrom, _from_warden(), _private(), Tripwire: no warden module reaches into another module's private names. A…, Local names bound by an import from warden (modules or anything else)., test_no_module_reaches_into_another_modules_private_names(), _violations(), _warden_bindings()

### Community 142 - "test_password_policy_store.py"
Cohesion: 0.16
Nodes (27): Any, fixture, parametrize, UUID, The password policy store (rulings PW1, PW2 and PW11): policies, priorities,…, _settings(), _store(), test_a_change_notifies_in_its_own_transaction() (+19 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.16
Nodes (27): Purpose, StrEnum, Delete expired tokens, whatever their state; returns how many., Tokens in ``warden.single_use_tokens``. Every method works in the caller's…, SingleUseTokens, The token in a sent message's link (the test links end ``?t=<token>``)., _consume(), _issue() (+19 more)

### Community 144 - "Fingerprints"
Cohesion: 0.11
Nodes (25): Fingerprints, OpenedFingerprint, password_digest(), UUID, Sealed password fingerprints (ruling PW8). A fingerprint is the SHA-1 of the…, The SHA-1 of ``password`` as UTF-8: the form watch lists and the range API use., A fingerprint as stored: the sealing key's id and the sealed bytes., An opened fingerprint, held in memory only for the length of a check. (+17 more)

### Community 145 - "well_formed"
Cohesion: 0.15
Nodes (18): IssuedToken, _live_token(), LiveToken, Any, AsyncConnection, datetime, TypeGuard, UUID (+10 more)

### Community 146 - "BuiltinList"
Cohesion: 0.12
Nodes (22): functools, BuiltinList, _bundled(), bundled_list(), _check(), Path, The built-in common-password list (ruling PW12). A read-only list of common…, Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled… (+14 more)

### Community 147 - "test_password_cli.py"
Cohesion: 0.24
Nodes (22): _banned(), _entries(), FakeSettings, _policy(), Any, CaptureFixture, Path, UUID (+14 more)

### Community 148 - "test_no_direct_environment.py"
Cohesion: 0.31
Nodes (9): _enclosing_functions(), visit(), _findings(), AST, Tripwire: warden reads configuration only through konfig. No module under…, Each node's innermost enclosing function name, keyed by ``id(node)``., Every forbidden use, and whether it is the named exemption., test_each_exemption_covers_exactly_one_read() (+1 more)

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "config.py"
Cohesion: 0.07
Nodes (29): fido2_rpid, AuditConfig, _base_origin(), _check_origin(), _check_template(), DbConfig, HttpConfig, _is_domain() (+21 more)

### Community 151 - "test_a_purge_committing_during_verification_breaks_nothing"
Cohesion: 0.18
Nodes (7): _AfterFirstQuery, _HookedPool, MemorySecrets, Any, Delegates to a connection, running ``hook`` once after the checkpoint listing., test_a_purge_committing_during_verification_breaks_nothing(), purge_now()

### Community 152 - "test_database.py"
Cohesion: 0.46
Nodes (7): _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.18
Nodes (30): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, anonymous(), bearer(), deployment(), make(), member() (+22 more)

### Community 154 - "Cluster: test_tls_fail_closed.py"
Cohesion: 0.46
Nodes (7): expr, _findings(), _is_cert_required(), _is_true(), Tripwire: nothing in warden turns TLS verification off. Fails on any use of…, test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 155 - "SsoSettingsStore"
Cohesion: 0.15
Nodes (22): ValueError, A settings change was refused. The message names fields, never values., SsoSettingsError, SsoSettingsStore, config(), fixture, parametrize, UserFactory (+14 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.10
Nodes (27): PasswordHistory, Any, AsyncConnection, datetime, UUID, Password history (ruling PW6). Each password a user sets is kept as its…, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password. (+19 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "test_watch_list_admin_routes.py"
Cohesion: 0.19
Nodes (22): app(), client(), create_list(), _forms(), headers(), Any, AsyncClient, FastAPI (+14 more)

### Community 159 - "console/cli.py"
Cohesion: 0.09
Nodes (40): _create_admin(), work(), _dsn(), _init(), main(), _parser(), Any, ArgumentParser (+32 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "HibpRangeClient"
Cohesion: 0.08
Nodes (34): AsyncBaseTransport, PasswordsConfig, Password policies: the fingerprint key and the breached-password range API.…, Whether a policy may enable the sealed fingerprint (ruling PW8)., HibpUnavailable, Exception, The breached-password range service could not be used. Always the same message:…, HibpRangeClient (+26 more)

### Community 162 - "Identity"
Cohesion: 0.04
Nodes (84): Identity, AbstractAsyncContextManager, APIRouter, FastAPI, The signed-in user's security keys and passkeys, oldest first., warden's identity subsystem for one deployment., Delete expired tokens, MFA and WebAuthn challenges, and ended throttle windows., Run ``prune`` every ``every_seconds`` for a block, such as the product's… (+76 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "register_syslog_actions"
Cohesion: 0.22
Nodes (10): Register the audit actions the syslog routes record. Safe to call more than…, register_syslog_actions(), test_the_syslog_actions_register_idempotently(), parametrize, The ``warden.`` action namespace belongs to warden (ruling of 27 October 2026).…, test_a_product_cannot_pre_empt_a_warden_action(), test_a_product_registration_in_the_warden_namespace_is_refused(), test_every_action_warden_registers_is_in_the_warden_namespace() (+2 more)

### Community 165 - "lifecycle.py"
Cohesion: 0.08
Nodes (41): Any, The kept messages, newest first, as the outbox page shows them., detail(), _inline(), resolve(), InvitationAcceptBody, json_body(), LinkPasswordCheckBody (+33 more)

### Community 166 - "audit_router"
Cohesion: 0.12
Nodes (17): AwareDatetime, description, max_length, Outcome, Any, A row as a JSON-ready object: ISO timestamps (UTC), hex hashes., row_to_json(), _address_or_none() (+9 more)

### Community 167 - "sys"
Cohesion: 0.12
Nodes (20): _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``., stamp() (+12 more)

### Community 169 - "rules.py"
Cohesion: 0.14
Nodes (19): _classes(), _detail_tokens(), evaluate(), Evaluation, _local_part(), _longest_run(), _meets(), normalise() (+11 more)

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "test_cli_audit.py"
Cohesion: 0.24
Nodes (14): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up() (+6 more)

### Community 173 - "test_cli_audit_errors.py"
Cohesion: 0.19
Nodes (14): _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path, The warden audit CLI without a database: connection failures and grants. (+6 more)

### Community 174 - "test_config_passwords.py"
Cohesion: 0.22
Nodes (18): _parse(), Any, parametrize, Start-up validation of the password settings (rulings PW2, PW7 and PW8 of 10…, _refused(), test_a_fingerprint_key_name_makes_the_fingerprint_available(), test_a_malformed_secret_name_is_refused(), test_a_previous_key_needs_a_current_key() (+10 more)

### Community 175 - "race"
Cohesion: 0.13
Nodes (21): race(), Run ``calls`` as concurrent tasks released together by a barrier. Every task…, parametrize, UserFactory, Password reset by emailed link: refusal paths, single use (#127), sessions…, #127 for reset tokens., _reasons(), test_a_failed_send_leaves_no_link() (+13 more)

### Community 176 - "identity"
Cohesion: 0.15
Nodes (16): app(), audit_registry(), client(), config(), identity(), keys(), make_user(), permissions() (+8 more)

### Community 177 - "fake_idp.py"
Cohesion: 0.14
Nodes (15): jwt_algorithms, _Drop, A fake OIDC provider for unit tests (imported as ``fake_idp``). It serves…, app(), config(), idp(), Any, AsyncClient (+7 more)

### Community 178 - "test_audit_export.py"
Cohesion: 0.17
Nodes (22): csv, io, csv_lines(), _csv_record(), escape_cell(), ndjson_lines(), One JSON object per line., ``value``, made safe to open in a spreadsheet. (+14 more)

### Community 179 - ".__init__"
Cohesion: 0.06
Nodes (27): get_recorder(), Register one of warden's own actions. Internal to warden; not for products., register_warden_action(), The audit actions identity records, registered when ``Identity`` is constructed., register_actions(), register_actions(), Protocol, SecretStore (+19 more)

### Community 180 - "PasswordRules"
Cohesion: 0.16
Nodes (17): PassphraseRule, PasswordRules, _preempts(), _problems(), When a password counts as a passphrase (PW4)., A change-period tier (PW5): its condition and maximum age., A policy's deterministic rules (PW3), passphrase setting (PW4) and tiers (PW5)., Raise ``PasswordPolicyError`` naming every inconsistent field. (+9 more)

### Community 181 - "PolicySettings"
Cohesion: 0.22
Nodes (10): RangeCache, Range answers for one recheck run, by prefix. Never kept beyond the run., PolicySettings, What an administrator sets on a policy: everything but its id, priority and…, The outcome of ``match``: the first match, and whether the range API could not…, Whether the password is refused: a match, or an unreachable API the policy…, The first watch list ``password`` is on under ``policy``; whether the API…, As ``match``, for a fingerprint's digest: every check but terms, which need the… (+2 more)

### Community 182 - "licence_audit.py"
Cohesion: 0.23
Nodes (14): packaging_requirements, packaging_utils, audit(), classify(), data_problems(), installed(), main(), _one() (+6 more)

### Community 183 - "throttle.py"
Cohesion: 0.07
Nodes (32): PasswordPruning, Pruner, PruneReport, Identifier, Protocol, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., What the pruner needs from password policies. (+24 more)

### Community 184 - "require_permission"
Cohesion: 0.25
Nodes (9): Forbidden, installed_identity(), HTTPException, Request, A dependency requiring ``permission``; with ``scoped``, also the product's…, The signed-in user (by access token or API key), or the uniform 401 refusal., require_permission(), dependency() (+1 more)

### Community 185 - "copy"
Cohesion: 0.22
Nodes (9): copy, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1() (+1 more)

### Community 186 - "password_support.py"
Cohesion: 0.15
Nodes (17): mail(), RecordingSender, The product's mail sender; records every message instead of sending it., bearer(), codes(), lifecycle_app(), pin_policy(), Any (+9 more)

### Community 187 - "ConnectionSource"
Cohesion: 0.18
Nodes (8): ConnectionSource, AbstractAsyncContextManager, Any, AsyncConnection, Protocol, Anything that lends async connections; ``psycopg_pool.AsyncConnectionPool``…, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - "test_password_rule_vectors.py"
Cohesion: 0.21
Nodes (14): build(), _case(), Any, The rule test cases behind ``docs/contract/password-rule-vectors.json``. The…, render(), _file(), Any, parametrize (+6 more)

### Community 191 - "_LazySecrets"
Cohesion: 0.22
Nodes (7): _LazySecrets, _OneConnection, Any, AsyncConnection, A connection source lending a single connection, for one CLI command., konfig ``Secrets``, constructed only if a command actually needs a secret., _rotate()

### Community 192 - "resolve"
Cohesion: 0.22
Nodes (7): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PW1: the pin, else the highest-priority mapped and declared role, else the…, resolve(), test_resolution_order_is_pin_then_highest_priority_role_then_default()

### Community 193 - ".from_description"
Cohesion: 0.36
Nodes (7): _bool(), _int(), _opt_int(), Any, The versioned JSON shape a browser evaluates., Rebuild rules from ``describe()``'s shape; refuses another version., _str()

### Community 194 - "Notes"
Cohesion: 0.24
Nodes (4): Note, Notes, Any, The in-memory note store.

### Community 195 - "InvitationAcceptance"
Cohesion: 0.29
Nodes (7): PasskeyRegistration, Protocol, Single sign-on's subject pinning, run inside the acceptance transaction.…, The WebAuthn registration, run inside the acceptance transaction. Called with…, SubjectPin, InvitationAcceptance, Identity lifecycle's SSO acceptance entry point (``identity.invitations``).

### Community 196 - "Refused"
Cohesion: 0.67
Nodes (3): HTTPException, Raised by dependencies; FastAPI's default handler renders the uniform refusal., Refused

### Community 197 - "notes_router"
Cohesion: 0.18
Nodes (13): _audit(), notes_router(), create_note(), delete_note(), found(), update_note(), APIRouter, IPv4Address (+5 more)

### Community 198 - "_Invalid"
Cohesion: 0.67
Nodes (3): _Invalid, Exception, A policy body refused, with each field at fault and a fixed message.

### Community 199 - "_PinRefused"
Cohesion: 0.50
Nodes (3): _PinRefused, Exception, Raised by the acceptance pin, so the whole acceptance rolls back.

### Community 200 - "test_identity_totp_storage.py"
Cohesion: 0.36
Nodes (8): MemorySecrets, UserFactory, TOTP secrets are sealed at rest, bound to their user, and survive key rotation., _row(), test_a_secret_copied_to_another_user_does_not_open(), test_identity_refuses_to_start_without_a_totp_key(), test_rotation_keeps_enrolments_working_and_reseals(), test_the_stored_secret_is_sealed()

### Community 201 - "BaseModel"
Cohesion: 0.25
Nodes (8): AuditEventPage, AuditEventView, BrokenLinkView, ChainVerification, BaseModel, The verification report (documentation only)., One audit row, as listed and as exported in NDJSON (documentation only)., A page of events, newest first (documentation only).

### Community 202 - "test_nothing_secret_is_recorded_logged_or_raised"
Cohesion: 0.50
Nodes (3): _forms(), LogCaptureFixture, test_nothing_secret_is_recorded_logged_or_raised()

### Community 203 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends an acceptance transaction without committing it.

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 211 - "JwkSet"
Cohesion: 0.40
Nodes (5): JwkSet, OkpJwk, BaseModel, One published key, an RFC 8037 OKP JSON Web Key (documentation only)., An RFC 7517 JWK Set (documentation only).

### Community 213 - "_NoDatabase"
Cohesion: 0.22
Nodes (8): main(), _NoDatabase, openapi_text(), Any, AsyncConnection, The document as committed: two-space indent, ASCII, one trailing newline., A connection source that refuses: the reference app is described, never served., render()

### Community 219 - "package"
Cohesion: 0.67
Nodes (3): package(), fixture, Install a throwaway template package under a unique name.

## Knowledge Gaps
- **109 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+104 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1911 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **18 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `typing`, `AuthenticationRefused`, `KeyStore`, `RecordingSender`, `test_identity_tokens.py`, `test_webauthn_mfa.py`, `contract.py`, `password_admin.py`, `passkey_support.py`, `WebAuthn`, `Database`, `record_audit`, `invitations.py`, `test_webauthn_reset.py`, `test_identity_totp_reset.py`, `json_response`, `test_identity_key_publication.py`, `current_code`, `test_password_sign_in.py`, `admin.py`, `test_webauthn_authentication.py`, `Mfa`, `test_identity_prune.py`, `User`, `mail.py`, `test_password_recheck.py`, `build_reference_app`, `identity/__init__.py`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `MemorySecrets`, `pytest`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `sso.py`, `test_passkey_options_throttle.py`, `test_password_admin_routes.py`, `roles.py`, `client_ip`, `test_identity_admin_routes.py`, `SecretBox`, `test_sso_capabilities.py`, `audit_rows`, `test_sso_admin_routes.py`, `SingleSignOn`, `test_passkey_invitation.py`, `test_console_passkeys.py`, `Cluster: test_identity_lifecycle_routes.py`, `WardenConfig`, `test_password_feedback.py`, `test_identity_mfa_mail.py`, `Cluster: test_identity_client_address.py`, `build_console`, `http`, `console_router`, `SingleUseTokens`, `test_password_cli.py`, `test_identity_capabilities.py`, `SsoSettingsStore`, `PasswordHistory`, `test_watch_list_admin_routes.py`, `lifecycle.py`, `race`, `identity`, `fake_idp.py`, `.__init__`, `PasswordRules`, `throttle.py`, `require_permission`, `password_support.py`, `test_identity_totp_storage.py`, `test_nothing_secret_is_recorded_logged_or_raised`, `test_inviting_an_existing_address_is_refused`?**
  _High betweenness centrality (0.142) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `typing`, `ApiKeys`, `KeyStore`, `RecordingSender`, `test_identity_tokens.py`, `AuditRecorder`, `test_webauthn_mfa.py`, `passkey_support.py`, `test_audit_recorder.py`, `WebAuthn`, `AuditEvent`, `PasswordPolicies`, `record_audit`, `invitations.py`, `test_webauthn_reset.py`, `test_identity_totp_reset.py`, `SsoSettings`, `test_audit_retention.py`, `test_syslog_forwarder.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `warden/cli.py`, `test_webauthn_authentication.py`, `SyslogSettings`, `test_identity_prune.py`, `User`, `soft_authenticator.py`, `test_password_recheck.py`, `build_reference_app`, `identity/__init__.py`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `MemorySecrets`, `pytest`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_passkey_options_throttle.py`, `test_password_admin_routes.py`, `roles.py`, `test_identity_admin_routes.py`, `SecretBox`, `Cluster: test_key_publication.py`, `AuditQuery`, `audit_rows`, `test_sso_admin_routes.py`, `test_audit_router.py`, `verify_chain`, `watchlists.py`, `SingleSignOn`, `test_passkey_invitation.py`, `test_syslog_routes.py`, `Cluster: test_identity_lifecycle_routes.py`, `WatchLists`, `WardenConfig`, `test_password_feedback.py`, `test_audit_grants.py`, `test_identity_mfa_mail.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `build_console`, `http`, `webauthn/service.py`, `test_password_policy_store.py`, `SingleUseTokens`, `Fingerprints`, `test_password_cli.py`, `test_a_purge_committing_during_verification_breaks_nothing`, `test_database.py`, `test_identity_capabilities.py`, `SsoSettingsStore`, `PasswordHistory`, `test_watch_list_admin_routes.py`, `HibpRangeClient`, `Identity`, `race`, `identity`, `.__init__`, `throttle.py`, `ConnectionSource`, `_LazySecrets`, `test_identity_totp_storage.py`, `test_nothing_secret_is_recorded_logged_or_raised`?**
  _High betweenness centrality (0.107) - this node is a cross-community bridge._
- **Why does `AuditEvent` connect `AuditEvent` to `typing`, `ApiKeys`, `AuthenticationRefused`, `AuditRecorder`, `password_admin.py`, `test_audit_recorder.py`, `syslog/__init__.py`, `Fingerprints`, `PasswordPolicies`, `._refuse`, `Invitations`, `test_audit_anchor_format.py`, `record_audit`, `invitations.py`, `test_a_purge_committing_during_verification_breaks_nothing`, `SsoSettings`, `test_audit_retention.py`, `ActionRegistry`, `test_syslog_forwarder.py`, `SyslogSettings`, `Mfa`, `identity/__init__.py`, `password_policy/__init__.py`, `notes_router`, `Sessions`, `roles.py`, `AuditQuery`, `test_audit_router.py`, `verify_chain`, `watchlists.py`, `test_syslog_routes.py`, `test_audit_grants.py`, `test_audit_chain_recorder.py`?**
  _High betweenness centrality (0.027) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Are the 93 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 93 INFERRED edges - model-reasoned connections that need verification._
- **Are the 152 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 152 INFERRED edges - model-reasoned connections that need verification._
- **Are the 134 inferred relationships involving `KeyStore` (e.g. with `build_console()` and `Console`) actually correct?**
  _`KeyStore` has 134 INFERRED edges - model-reasoned connections that need verification._