# Graph Report - warden  (2026-11-10)

## Corpus Check
- 326 files · ~334,957 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 6817 nodes · 22208 edges · 232 communities (212 shown, 20 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2046 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4441ea30`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- syslog/__init__.py
- FakeIdp
- AuditEvent
- SourceIp
- KeyStore
- RecordingSender
- PasswordResets
- AuditRecorder
- h
- test_webauthn_mfa.py
- contract.py
- password_admin.py
- webauthn.py
- test_audit_recorder.py
- StreamTransport
- SoftwareAuthenticator
- test_console_password_policy.py
- Database
- PasswordPolicies
- SingleSignOn
- Invitations
- WebAuthnError
- test_audit_anchor_format.py
- PasswordEnforcement
- SignInMethod
- password_policy/__init__.py
- chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- SsoSettingsStore
- CI Workflows
- test_audit_retention.py
- ActionRegistry
- test_identity_key_publication.py
- PasswordHasher
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
- WebAuthn
- SyslogSettings
- Cluster: syslog
- Mfa
- test_identity_prune.py
- User
- test_distributions.py
- test_config_fields.py
- verify.py
- soft_authenticator.py
- Mailer
- test_password_recheck.py
- export_openapi.py
- typing
- PasswordStates
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- test_audit_registry.py
- current_revision
- test_sso_live.py
- test_webauthn_live.py
- Sessions
- test_identity_dependencies.py
- test_passkey_registration_link.py
- lifecycle.py
- build_sso_router
- httpx
- test_password_admin_routes.py
- test_identity_throttle.py
- client_ip
- test_identity_admin_routes.py
- test_webauthn_migration.py
- SecretBox
- Cluster: test_key_publication.py
- test_sso_capabilities.py
- json
- test_openapi_contract.py
- test_identity_migration.py
- migrate.py
- test_identity_sign_in.py
- test_sso_admin_routes.py
- Cluster: Client-behaviour guide
- Cluster: warden design overview
- Cluster: modules()
- bump_version.py
- test_audit_router.py
- verify_chain
- test_cli_audit_anchor.py
- attestation.py
- test_db_schema.py
- WatchLists
- provider.py
- Module
- MailMessage
- Roles
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- test_console_passkeys.py
- test_syslog_routes.py
- audit_rows
- test_password_watch_lists.py
- PolicyStore
- pytest
- Cluster: test_cli.py
- Cluster: Audit hash chain specification
- test_password_feedback.py
- BlackholeCollector
- _purge_prefix
- test_audit_grants.py
- grants.py
- Cluster: with
- parse_config
- test_sso_issuer.py
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- .__init__
- test_passkey_options_throttle.py
- test_lifecycle_migration.py
- test_bump_version.py
- build_console
- test_password_policy_migration.py
- test_password_set_points.py
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
- test_a_purge_committing_during_verification_breaks_nothing
- test_database.py
- test_identity_capabilities.py
- test_tls_fail_closed.py
- ceremony.js
- PasswordHistory
- Cluster: verify
- mail.py
- console/settings.py
- Cluster: rsyslog
- test_password_hibp.py
- Identity
- test_licence_audit.py
- test_dependabot.py
- test_console_app.py
- .register
- subprocess
- Cluster: examples/__init__.py
- ._accept
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- main
- test_cli_audit_errors.py
- tests/conftest.py
- test_console_gaps.py
- test_config_passwords.py
- test_sso_password_state.py
- test_identity_reset.py
- .__init__
- test_webauthn_credentials.py
- test_sso_preset_label_only.py
- licence_audit.py
- SignInThrottle
- require_permission
- copy
- PolicySettings
- ConnectionSource
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- password_support.py
- _LazySecrets
- test_identity_roles.py
- test_console_password_rules.py
- identity/actions.py
- .sso_settings_router
- Refused
- Notes
- _Invalid
- test_password_enforcement_keys.py
- AnchorSigner
- resolve
- notes_router
- NoteScope
- test_client_guide.py
- keys_router
- test_identity_totp_storage.py
- totp.py
- BaseModel
- .install
- The built-in common-password list
- app.py
- test_a_key_registered_while_switching_to_sso_only_never_leaves_both
- _Abort
- .password_subject
- _Prioritised
- _Abort
- test_the_import_check_reports_a_module_that_fails
- _load
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
- `test_event_defaults_to_now_in_utc()` --calls--> `AuditEvent`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/events.py
- `test_event_details_must_be_json()` --calls--> `AuditEvent`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/events.py
- `test_event_is_immutable()` --calls--> `AuditEvent`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/events.py
- `test_event_outcome_is_constrained()` --calls--> `AuditEvent`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/events.py
- `test_event_parses_source_ip()` --calls--> `AuditEvent`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/events.py

## Import Cycles
- 3-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 3-file cycle: `src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/apikeys.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 5-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`

## Hyperedges (group relationships)
- **Audit tamper-evidence mechanisms** — docs_design_audit_chain_audit_hash_chain, docs_design_audit_chain_retention_checkpoint, docs_design_audit_chain_anchor, docs_design_audit_chain_audit_database_roles, docs_design_overview_tamper_evidence [EXTRACTED 1.00]
- **Release and publication pipeline** — docs_releasing_bump_version, github_workflows_publish, docs_releasing_check_dist, docs_releasing_trusted_publishing, claude_integration_procedure [EXTRACTED 1.00]
- **Tripwire tests guarding architecture rules** — docs_design_overview_single_audit_writer, docs_design_overview_audit_independence, examples_console_readme_public_surface_tripwire, claude_mutation_checked_guards [INFERRED 0.85]

## Communities (232 total, 20 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.14
Nodes (48): expire_challenge_of(), give_passkey(), passkey_assertion(), passkey_sign_in(), Any, AsyncClient, Expire only the challenge a browser response answers, as if its lifetime had…, Register a credential for an active user straight through the ceremony. (+40 more)

### Community 1 - "syslog/__init__.py"
Cohesion: 0.04
Nodes (57): DatagramTransport, errno, IntEnum, socket, Event severity, numbered as RFC 5424 syslog severities., Severity, _clip(), build() (+49 more)

### Community 2 - "FakeIdp"
Cohesion: 0.06
Nodes (70): jwt, jwt_algorithms, jwt_exceptions, Discovery, JwksCache, ProviderHttp, ProviderMetadata, AsyncClient (+62 more)

### Community 3 - "AuditEvent"
Cohesion: 0.04
Nodes (46): AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., AuditChainConflict, Any, AsyncConnection, Exception, Record ``event`` and return its row id. With ``conn``, the row is written… (+38 more)

### Community 4 - "SourceIp"
Cohesion: 0.05
Nodes (47): Principal, The signed-in user behind a request. For a request made with an API key,…, _Account, _credential_id(), PasswordChangeIssued, PasswordTokenPair, Any, AsyncConnection (+39 more)

### Community 5 - "KeyStore"
Cohesion: 0.05
Nodes (67): Ed25519PrivateKey, KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., _b64url(), _b64url_decode(), key_id_for(), KeyStore, KeyStoreError (+59 more)

### Community 6 - "RecordingSender"
Cohesion: 0.09
Nodes (56): InvitationError, An administrative invitation change was refused. Messages carry no values., A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, race(), The product's mail sender, recording instead of sending. ``fail`` makes it… (+48 more)

### Community 7 - "PasswordResets"
Cohesion: 0.20
Nodes (15): _Account, _Checked, PasswordResets, Any, AsyncConnection, NoReturn, SourceIp, UUID (+7 more)

### Community 8 - "AuditRecorder"
Cohesion: 0.11
Nodes (62): AnchorRecord, An anchor written to the trail, and the id of the row that carries it., AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors(), age(), Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then… (+54 more)

### Community 9 - "h"
Cohesion: 0.07
Nodes (139): apiKeysScreen(), capabilities(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames() (+131 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.11
Nodes (71): enrol_totp(), Enrol and confirm TOTP for ``user``; returns the secret. Confirmation claims…, _amr(), _app(), _assertion(), _bearer(), _challenge(), http() (+63 more)

### Community 11 - "contract.py"
Cohesion: 0.05
Nodes (83): build_auth_router(), capabilities(), APIRouter, Public sign-in routes. The product mounts them under…, BuiltinListBody, ChallengeBody, ChangePasswordBody, CodeBody (+75 more)

### Community 12 - "password_admin.py"
Cohesion: 0.06
Nodes (92): AffectedUsersProposalBody, PasswordPolicyCreateBody, PasswordPolicyOrderBody, PasswordPolicyPinBody, PasswordPolicyPriorityBody, PasswordPolicyRoleBody, PasswordPolicyUpdateBody, WardenAffectedUsersProposal (+84 more)

### Community 13 - "webauthn.py"
Cohesion: 0.14
Nodes (27): bearer_token(), EnrolmentBody, A completed second factor: a session, or a forced password change first., What the browser passes to `navigator.credentials.create()` or `get()`., The key and the recovery codes; under a challenge, with the new session (or a…, WardenSecondFactorAnswer, WardenWebAuthnCredentialEnvelope, WardenWebAuthnCredentialList (+19 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.13
Nodes (31): Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any (+23 more)

### Community 15 - "StreamTransport"
Cohesion: 0.29
Nodes (4): StreamReader, StreamWriter, TCP or TLS. After any failure the connection is spent and must be replaced., StreamTransport

### Community 16 - "SoftwareAuthenticator"
Cohesion: 0.15
Nodes (44): One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, Any, parametrize, UserFactory, UUID, Registering a passkey or security key: the options, the checks and every…, _refused() (+36 more)

### Community 17 - "test_console_password_policy.py"
Cohesion: 0.18
Nodes (25): bearer(), make_user(), admin_token(), new_policy(), Any, AsyncClient, The sample console's password policy support: routes, the development clock,…, Every (method, path) a screen sends to a warden router, path parameters as… (+17 more)

### Community 18 - "Database"
Cohesion: 0.12
Nodes (60): Body, Database, warden's handle on the product's connection pool., Started, accept(), acceptance_rows(), app(), _bodies() (+52 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.08
Nodes (44): PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, A password policy, or a change to one, was refused., No password policy has that id., The change clashes with the stored state: a stale version, a name or priority…, Delete history beyond the largest count any policy keeps; returns how many., _check_priority() (+36 more)

### Community 20 - "SingleSignOn"
Cohesion: 0.09
Nodes (27): Single sign-on's subject pinning, run inside the acceptance transaction.…, SubjectPin, _challenge(), _hash(), InvitationAcceptance, _PinRefused, Any, AsyncConnection (+19 more)

### Community 21 - "Invitations"
Cohesion: 0.14
Nodes (16): Method, Invitations, _Invitee, Any, AsyncConnection, datetime, NoReturn, SourceIp (+8 more)

### Community 22 - "WebAuthnError"
Cohesion: 0.11
Nodes (25): PublicKeyCredentialDescriptor, Exception, A WebAuthn ceremony or credential change was refused. ``user_id`` and…, Whether the refusal reports a credential that may have been copied., WebAuthnError, _extension_results(), _parse(), Any (+17 more)

### Community 23 - "test_audit_anchor_format.py"
Cohesion: 0.08
Nodes (52): cryptography_hazmat_primitives_asymmetric_ed25519, Anchor, _b64url(), _b64url_decode(), _from_ndjson(), _from_syslog(), _int(), MalformedAnchor (+44 more)

### Community 24 - "PasswordEnforcement"
Cohesion: 0.06
Nodes (39): SetPlace, AcceptedPassword, _match_details(), PasswordAdvice, PasswordEnforcement, PasswordFailure, PasswordFeedback, PasswordRejected (+31 more)

### Community 25 - "SignInMethod"
Cohesion: 0.09
Nodes (34): _link_refusal(), PasskeyLinkNotConfigured, PasskeyLinkRefused, datetime, Exception, No registration link for this user: ``sso_only``, or not active (ruling P8).…, Why a user may not have a passkey registration link, or None (ruling P8)., Abandons a transaction whose refusal must also undo earlier writes. (+26 more)

### Community 26 - "password_policy/__init__.py"
Cohesion: 0.07
Nodes (38): HibpUnavailable, Exception, The breached-password range service could not be used. Always the same message:…, Fingerprints, OpenedFingerprint, password_digest(), UUID, Sealed password fingerprints (ruling PW8). A fingerprint is the SHA-1 of the… (+30 more)

### Community 27 - "chain.py"
Cohesion: 0.08
Nodes (44): decimal, JsonValue, address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields() (+36 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.10
Nodes (45): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+37 more)

### Community 29 - "test_config.py"
Cohesion: 0.06
Nodes (84): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, FakeSecrets, FakeSettings, _load(), Any, parametrize (+76 more)

### Community 30 - "json_response"
Cohesion: 0.09
Nodes (61): json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), begin_enrolment(), change_password() (+53 more)

### Community 31 - "SsoSettingsStore"
Cohesion: 0.09
Nodes (35): _from_config(), _plain(), Any, AsyncConnection, The effective settings, cached for ``max_age`` seconds., The effective settings, read now on ``conn`` (no cache)., Override some fields: validated as a whole, audited, and, when this turns…, Drop every override, returning to configuration. (+27 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_audit_retention.py"
Cohesion: 0.12
Nodes (39): purge(), Exception, A purge was refused. The message carries row ids only., Delete audit rows older than ``retention_days`` behind a signed checkpoint., RetentionError, Any, Connection, Recompute every hash and link from the first surviving row's ``prev_hash``. (+31 more)

### Community 34 - "ActionRegistry"
Cohesion: 0.13
Nodes (43): ActionRegistry, Register one of warden's own actions. Internal to warden; not for products., The set of actions this deployment records., register_warden_action(), format_message(), neutralise(), The RFC 5424 message for ``record``, at most ``settings.max_message_bytes``…, Replace every control character in ``value`` with a visible ``\\xNN`` escape. (+35 more)

### Community 35 - "test_identity_key_publication.py"
Cohesion: 0.29
Nodes (13): PyJWK, _access_token(), _b64(), _decode(), keys_client(), _published_key(), Any, AsyncClient (+5 more)

### Community 36 - "PasswordHasher"
Cohesion: 0.10
Nodes (18): PasswordHasher, Match, The outcome of checking a password against a stored hash., Argon2id hashing with legacy PBKDF2 verification. The defaults are…, An Argon2id hash of ``password``., Check ``password`` against ``encoded``; never raises for a bad input., Spend the time one Argon2id verification takes, for a user who has no hash.…, Verification (+10 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.20
Nodes (39): ForwarderFactory, _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader() (+31 more)

### Community 38 - "rules.py"
Cohesion: 0.05
Nodes (85): Each rule's result and any watch-list match. Never history; stores and audits…, _bool(), _classes(), _detail_tokens(), evaluate(), Evaluation, _int(), _local_part() (+77 more)

### Community 39 - "current_code"
Cohesion: 0.09
Nodes (55): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), _challenge(), _enrolled(), _fresh_code() (+47 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.05
Nodes (60): cryptography_hazmat_primitives, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, cryptography_x509_oid, Framing, frame(), open_transport(), Connect to the collector named in ``settings``; ``TransportError`` on failure. (+52 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.14
Nodes (49): Clock, http(), A settable clock for ``Identity(clock=...)``: real time plus an offset., Replace the default policy's settings (keeping its name)., set_default(), _amr(), clock(), _complete() (+41 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.07
Nodes (28): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+20 more)

### Community 43 - "admin.py"
Cohesion: 0.09
Nodes (61): _api_key(), _assignment(), _BadRequest, build_admin_router(), assign_role(), capabilities(), create_key(), invite() (+53 more)

### Community 44 - "test_sso_sealing.py"
Cohesion: 0.15
Nodes (26): cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's…, The token sealed in ``sealed``, or None if it does not open to one. (+18 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (11): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+3 more)

### Community 46 - "warden/cli.py"
Cohesion: 0.08
Nodes (52): BinaryIO, sqlalchemy_exc, AnchorError, ExternalAnchor, Exception, An anchor could not be written. The message carries identifiers only., An anchor found in an export: its line, its own row id when known, and the…, PurgeResult (+44 more)

### Community 47 - "WebAuthn"
Cohesion: 0.18
Nodes (38): The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, _enrolled(), Any, parametrize, UserFactory, UUID (+30 more)

### Community 48 - "SyslogSettings"
Cohesion: 0.07
Nodes (41): Any, BaseModel, field_validator, model_validator, Self, Build settings from the shared ``SyslogConfig``. ``secrets`` looks up a konfig…, Everything the forwarder, formatter and transports need., SyslogSettings (+33 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Mfa"
Cohesion: 0.12
Nodes (22): SecondFactor, Challenge, _hash_token(), Mfa, Any, AsyncConnection, ChallengePurpose, UUID (+14 more)

### Community 51 - "test_identity_prune.py"
Cohesion: 0.18
Nodes (16): _count(), _expire_all(), _fixtures(), Any, MonkeyPatch, UserFactory, Pruning (#134): expired refresh and single-use tokens, MFA challenges, throttle…, Move every row of ``table`` into the past, keeping its own constraints. (+8 more)

### Community 52 - "User"
Cohesion: 0.10
Nodes (72): An opaque cursor for ``list(after=...)``: the users listed after ``user``., User, callback(), completion(), handoff(), provider_code(), AsyncClient, Response (+64 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.16
Nodes (29): dist(), _only(), fixture, parametrize, Path, TempPathFactory, The built distributions hold what is published, and nothing else. The wheel…, A wheel at ``version`` whose METADATA declares ``declared`` (by default the… (+21 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.13
Nodes (30): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+22 more)

### Community 55 - "verify.py"
Cohesion: 0.08
Nodes (33): BreakReason, _b64url(), _b64url_decode(), Checkpoint, HistoricalVerifier, _int(), MalformedCheckpoint, Any (+25 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.12
Nodes (26): CoseKey, fido2, fido2_cose, ca(), make_webauthn(), factory(), Any, fixture (+18 more)

### Community 57 - "Mailer"
Cohesion: 0.17
Nodes (25): MailConfig, Mail settings. The product implements the sender. Provisional until 0.1.0b1., Mailer, MailKind, StrEnum, Renders warden's messages and hands them to the product's sender., Whether a sender is installed., Render one message to ``email``. Datetime values are formatted with… (+17 more)

### Community 58 - "test_password_recheck.py"
Cohesion: 0.18
Nodes (17): _config(), fp_identity(), Any, fixture, Request, Response, Range, range_api() (+9 more)

### Community 59 - "export_openapi.py"
Cohesion: 0.13
Nodes (18): build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), Any, AsyncConnection (+10 more)

### Community 60 - "typing"
Cohesion: 0.05
Nodes (96): argon2, argon2_exceptions, asyncio, base64, binascii, collections_abc, contextlib, cryptography_exceptions (+88 more)

### Community 61 - "PasswordStates"
Cohesion: 0.07
Nodes (48): ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID, Use the challenge up; False if another request already did, or it lapsed., Count a refused attempt against the challenge, in its own transaction. (+40 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.14
Nodes (26): ApiKeyError, Exception, An API key change was refused. Messages carry no values., _app(), _bearer(), client(), AsyncClient, FastAPI (+18 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.08
Nodes (21): PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role, fixture, parametrize (+13 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.08
Nodes (31): Scope, ASGI middleware adding the policy and related headers to every HTTP answer., SecurityHeaders, with_headers(), Receive, Send, _address(), Any (+23 more)

### Community 65 - "test_audit_registry.py"
Cohesion: 0.07
Nodes (22): ActionSpec, _check_summary(), A registered action: dotted name, severity and summary template., The one-line summary for ``event``; absent fields render as ``-``., Register a product action. Re-registering an identical spec is a no-op. Actions…, The spec for ``action``; ``KeyError`` if it was never registered., complete(), parametrize (+14 more)

### Community 66 - "current_revision"
Cohesion: 0.11
Nodes (31): current_revision(), heads(), migrate(), The chain's head revisions. A healthy chain has exactly one., Upgrade the database at ``dsn`` to ``revision`` in one transaction., The revision the database is at, or ``None`` if none is applied., _columns(), _constraints() (+23 more)

### Community 67 - "test_sso_live.py"
Cohesion: 0.15
Nodes (25): os, accept_through_sso(), AsyncClient, parametrize, Live check: an invitation accepted through single sign-on, against the stub…, test_live_invitation_accepted_through_sso_then_sign_in_by_subject(), app(), browser_to_idp() (+17 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.06
Nodes (47): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+39 more)

### Community 69 - "Sessions"
Cohesion: 0.11
Nodes (21): AccessClaims, _b64(), _hash(), _json(), Any, AsyncConnection, NoReturn, SourceIp (+13 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (22): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, Request (+14 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.20
Nodes (34): admin(), config(), _credential_count(), http(), _identity(), _link(), _options(), Any (+26 more)

### Community 72 - "lifecycle.py"
Cohesion: 0.09
Nodes (35): Any, The kept messages, newest first, as the outbox page shows them., detail(), _inline(), resolve(), InvitationAcceptBody, json_body(), LinkPasswordCheckBody (+27 more)

### Community 73 - "build_sso_router"
Cohesion: 0.21
Nodes (18): _body_field(), build_sso_router(), callback(), clear_cookie(), failed(), handoff(), land(), set_cookie() (+10 more)

### Community 74 - "httpx"
Cohesion: 0.10
Nodes (23): httpx, pathlib, sys, pool(), Any, console(), make_console(), build() (+15 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.07
Nodes (68): bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests., app(), client() (+60 more)

### Community 76 - "test_identity_throttle.py"
Cohesion: 0.19
Nodes (18): _fail(), UserFactory, Sign-in throttling per (identifier, source address)., Otherwise a password holder gets unlimited challenges, and so unlimited code…, Barriered concurrent attempts: no more than the limit reach password…, An attacker elsewhere cannot lock the user out., Throttling must not reveal whether an account exists., test_a_password_alone_does_not_reset_the_count_when_mfa_follows() (+10 more)

### Community 77 - "client_ip"
Cohesion: 0.20
Nodes (17): client_ip(), Network, Request, SourceIp, The client address, for audit events and the sign-in throttle key. Resolved by…, build_sso_settings_router(), actor_id(), get_settings() (+9 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "SecretBox"
Cohesion: 0.08
Nodes (28): _decode(), _key_id(), new_totp_key(), Exception, Protocol, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., A TOTP key is missing or malformed. Names the secret, never its value. (+20 more)

### Community 81 - "Cluster: test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "json"
Cohesion: 0.03
Nodes (102): AwareDatetime, csv, description, NoteBody, BaseModel, The sample product's own resource: notes, gated by warden's permissions. It…, ExportFormat, fastapi_responses (+94 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.19
Nodes (15): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+7 more)

### Community 86 - "migrate.py"
Cohesion: 0.09
Nodes (26): alembic_config, alembic_runtime_migration, alembic_script, importlib, packaging_version, sqlalchemy_pool, _config(), downgrade() (+18 more)

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

### Community 92 - "bump_version.py"
Cohesion: 0.27
Nodes (9): _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``., stamp() (+1 more)

### Community 93 - "test_audit_router.py"
Cohesion: 0.16
Nodes (21): client(), exporter(), NoKeys, Any, AsyncClient, fixture, parametrize, Audit routers: list, export and verify, behind the product's own authorisation. (+13 more)

### Community 94 - "verify_chain"
Cohesion: 0.19
Nodes (23): Verify the chain, from its first surviving row to ``through_id`` (or the head)., verify_chain(), ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id. (+15 more)

### Community 95 - "test_cli_audit_anchor.py"
Cohesion: 0.20
Nodes (20): _export(), FakeSecrets, FakeSettings, Any, CaptureFixture, fixture, Path, The warden CLI: audit anchor, and audit verify --anchors, against a real… (+12 more)

### Community 96 - "attestation.py"
Cohesion: 0.12
Nodes (14): AttestationObject, Certificate, cryptography, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca() (+6 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.09
Nodes (12): warden: identity and audit for Python web applications. The public API lives in…, _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct() (+4 more)

### Community 98 - "WatchLists"
Cohesion: 0.10
Nodes (33): ValueError, Errors raised by password policies and watch lists. Messages carry field names,…, A watch list, or a change to one, was refused., No watch list has that id., The change clashes with the stored state: a list still attached to a policy., An import was refused or failed; the list is left as it was. ``line`` is the…, WatchListConflict, WatchListError (+25 more)

### Community 99 - "provider.py"
Cohesion: 0.13
Nodes (16): Exception, Single sign-on refusals. ``SsoError.reason`` is a fixed category, recorded in…, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic(), _https(), _KeySet, parse_metadata() (+8 more)

### Community 100 - "Module"
Cohesion: 0.27
Nodes (8): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations()

### Community 101 - "MailMessage"
Cohesion: 0.20
Nodes (7): MailMessage, MailSender, Protocol, One rendered message, ready for the product's sender., Implemented by the product. Raise to report that a message was not delivered., FailingSender, RecordingSender

### Community 102 - "Roles"
Cohesion: 0.11
Nodes (21): LastAdministratorError, lock_administrators(), Any, AsyncConnection, datetime, Exception, UUID, Role assignments in ``warden.role_assignments``. (+13 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.11
Nodes (12): AsyncBaseTransport, _check_secret_name(), _check_url(), PasswordsConfig, field_validator, ValueError, A konfig secret name: letters, digits, '.', '_', '/' and '-'., Validate an absolute http(s) URL; plain http only for loopback hosts. The value… (+4 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (30): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+22 more)

### Community 106 - "test_console_passkeys.py"
Cohesion: 0.17
Nodes (30): authenticator(), AsyncClient, A software authenticator that makes passkeys: discoverable, verifying the user., sign_in(), amr(), browser(), link_token(), outbox_message() (+22 more)

### Community 107 - "test_syslog_routes.py"
Cohesion: 0.20
Nodes (21): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), syslog_test(), _audit_rows(), authorise(), _client() (+13 more)

### Community 108 - "audit_rows"
Cohesion: 0.11
Nodes (32): audit_rows(), app(), config(), Any, AsyncClient, FastAPI, fixture, parametrize (+24 more)

### Community 109 - "test_password_watch_lists.py"
Cohesion: 0.10
Nodes (38): StrEnum, WatchListKind, builtin(), _lines(), lists(), policies(), Any, fixture (+30 more)

### Community 110 - "PolicyStore"
Cohesion: 0.13
Nodes (14): PolicyError, PolicyStore, Any, AsyncConnection, Event, ValueError, Whether ``listen()`` currently holds a LISTEN on the policy channel., Forget the cached policy; the next ``current()`` re-reads it. (+6 more)

### Community 111 - "pytest"
Cohesion: 0.11
Nodes (26): argparse, email_parser, dist_problems(), import_problems(), main(), _metadata_version(), Path, Check warden's built distributions, and the installed package, before… (+18 more)

### Community 112 - "Cluster: test_cli.py"
Cohesion: 0.22
Nodes (12): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: migrate and keys rotate., _settings(), test_invalid_configuration_fails_before_doing_anything(), test_keys_rotate_adds_a_key_and_prints_only_its_id() (+4 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (17): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+9 more)

### Community 114 - "test_password_feedback.py"
Cohesion: 0.11
Nodes (29): failing_transport(), handler(), listing_transport(), MockTransport, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., _counts() (+21 more)

### Community 115 - "BlackholeCollector"
Cohesion: 0.25
Nodes (4): BlackholeCollector, StreamReader, StreamWriter, Accepts connections and never reads, so a sender's buffers fill and stall.

### Community 116 - "_purge_prefix"
Cohesion: 0.16
Nodes (9): CheckpointSigner, _KeyLike, _purge_prefix(), Any, AsyncConnection, datetime, Protocol, What a purge needs from the key store: ``KeyStore`` fits. (+1 more)

### Community 117 - "test_audit_grants.py"
Cohesion: 0.21
Nodes (13): _as(), MemorySecrets, _pool(), Any, parametrize, Append-only grants: the application role can only insert and read audit rows.…, _refused(), _registry() (+5 more)

### Community 118 - "grants.py"
Cohesion: 0.28
Nodes (15): append_only_grants(), _application(), _forwarder(), grants_sql(), _ident(), _purger(), Composable, Composed (+7 more)

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "parse_config"
Cohesion: 0.12
Nodes (19): _format_errors(), load_config(), parse_config(), Any, Protocol, What warden needs from konfig's ``Settings``., What warden needs from konfig's ``Secrets``., Accept a comma-separated string (as the environment supplies) for a list field. (+11 more)

### Community 121 - "test_sso_issuer.py"
Cohesion: 0.13
Nodes (23): alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer(), Any (+15 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.17
Nodes (27): _assert_one_unforked_chain(), _event(), Any, fixture, The chained recorder: links, server-side order, the details cap, and…, Poll until backend ``pid`` waits on the chain's advisory lock., Row id order is commit order: the second inserter waits for the first's commit., A server default of REPEATABLE READ must not make warden's own writes conflict. (+19 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 125 - ".__init__"
Cohesion: 0.10
Nodes (24): Register warden's audit actions. Idempotent., register_audit_actions(), register_actions(), ``secrets`` is konfig's secrets store. It must hold the TOTP encryption key…, parametrize, Session policy: defaults from configuration, audited changes, cross-replica…, The product wraps its app's lifespan in ``identity.running()``., Replica B caches the policy for an hour, yet sees A's change at once via NOTIFY. (+16 more)

### Community 126 - "test_passkey_options_throttle.py"
Cohesion: 0.21
Nodes (28): assert_refused(), passkey_options(), Response, The uniform refusal, byte for byte., other_key(), A key no credential holds, for signatures that must not verify., _challenges(), elsewhere() (+20 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (15): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+7 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.18
Nodes (16): importlib_util, init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch. (+8 more)

### Community 129 - "build_console"
Cohesion: 0.08
Nodes (33): actor(), build_console(), _mount_pages(), FastAPI, Request, Build the console over the product's open pool and konfig's secrets store.…, A FastAPI dependency for warden's audit, syslog and SSO routes. Those routes…, create_administrator() (+25 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "test_password_set_points.py"
Cohesion: 0.11
Nodes (25): _administrator(), _change(), _codes(), _create(), _forced(), _hash(), _http_failures(), _invitation() (+17 more)

### Community 132 - "MemorySecrets"
Cohesion: 0.13
Nodes (23): config(), make_config(), MemorySecrets, Any, cli_secrets(), fp_identity(), fixture, MemorySecrets (+15 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "passkey_support.py"
Cohesion: 0.13
Nodes (25): http_client(), passkey_app(), passkey_config(), FastAPI, UUID, Helpers shared by the passkey tests (imported as ``passkey_support``). An…, The identity tests' configuration, with the passkey registration link., Change the sign-in method behind the services' back (no rule applies). (+17 more)

### Community 136 - "_FieldProblems"
Cohesion: 0.36
Nodes (4): _FieldProblems, model_validator, Self, Cross-field problems, each with a path relative to the failing model.

### Community 137 - ".prune"
Cohesion: 0.40
Nodes (3): AbstractAsyncContextManager, Delete expired tokens, MFA and WebAuthn challenges, and ended throttle windows., Run ``prune`` every ``every_seconds`` for a block, such as the product's…

### Community 138 - "identity/__init__.py"
Cohesion: 0.04
Nodes (63): enum, Protocol, The product's resource-level check, consulted by ``require_permission(...,…, ResourceScopeHook, warden's identity subsystem: users, sign-in, sessions, roles and permissions,…, Invitation, InvitationMismatch, PendingInvitation (+55 more)

### Community 139 - "test_examples_public_surface.py"
Cohesion: 0.29
Nodes (11): _private(), _private_path(), Path, Tripwire: the sample console uses only warden's public surface. The sample…, Every reach into a private warden module or name in ``source``., sample_sources(), test_nothing_under_examples_reaches_into_warden_internals(), test_the_check_sees_each_kind_of_private_reach() (+3 more)

### Community 140 - "console_router"
Cohesion: 0.14
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
Cohesion: 0.12
Nodes (22): functools, BuiltinList, _bundled(), bundled_list(), _check(), Path, The built-in common-password list (ruling PW12). A read-only list of common…, Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled… (+14 more)

### Community 147 - "test_console_capabilities.py"
Cohesion: 0.25
Nodes (10): client(), AsyncClient, _admin(), _client(), Any, AsyncClient, The sample console asks warden what the deployment can do, and its screens…, test_with_a_sender_everything_that_mails_is_available() (+2 more)

### Community 148 - "test_no_direct_environment.py"
Cohesion: 0.31
Nodes (9): _enclosing_functions(), visit(), _findings(), AST, Tripwire: warden reads configuration only through konfig. No module under…, Each node's innermost enclosing function name, keyed by ``id(node)``., Every forbidden use, and whether it is the named exemption., test_each_exemption_covers_exactly_one_read() (+1 more)

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "HttpConfig"
Cohesion: 0.07
Nodes (23): _base_origin(), _check_origin(), _check_template(), DbConfig, HttpConfig, _is_domain(), BaseModel, Validate a UI link template: a path or URL using exactly ``placeholders``. (+15 more)

### Community 151 - "test_a_purge_committing_during_verification_breaks_nothing"
Cohesion: 0.18
Nodes (7): _AfterFirstQuery, _HookedPool, MemorySecrets, Any, Delegates to a connection, running ``hook`` once after the checkpoint listing., test_a_purge_committing_during_verification_breaks_nothing(), purge_now()

### Community 152 - "test_database.py"
Cohesion: 0.46
Nodes (7): _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.06
Nodes (74): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, app(), audit_registry(), client(), identity(), keys() (+66 more)

### Community 154 - "test_tls_fail_closed.py"
Cohesion: 0.39
Nodes (8): ast, expr, _findings(), _is_cert_required(), _is_true(), Tripwire: nothing in warden turns TLS verification off. Fails on any use of…, test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 155 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.11
Nodes (24): PasswordHistory, Any, AsyncConnection, datetime, UUID, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password., Whether ``password`` matches any of the user's last ``count`` passwords. (+16 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "mail.py"
Cohesion: 0.12
Nodes (20): html, _check(), format_expiry(), _is_control(), _load(), MailDeliveryError, MailError, MailTemplate (+12 more)

### Community 159 - "console/settings.py"
Cohesion: 0.12
Nodes (27): _init(), Namespace, KonfigSecrets, load_settings(), Any, Path, The sample's configuration: written for a sandbox, read through konfig. A…, Put the secrets warden needs in konfig's store, keeping any already there. The… (+19 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "test_password_hibp.py"
Cohesion: 0.18
Nodes (19): _client(), LogCaptureFixture, parametrize, Request, Response, The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed…, Recorder, test_a_digest_must_be_twenty_bytes() (+11 more)

### Community 162 - "Identity"
Cohesion: 0.06
Nodes (75): Identity, warden's identity subsystem for one deployment., Run identity's background work (the session and password policy listeners) for…, Delete sign-in throttle records whose window has ended., Any, test_construction_writes_nothing_and_the_seeded_default_refuses_a_common_password(), test_prune_trims_history_and_expired_change_challenges(), test_running_also_listens_for_password_policy_changes() (+67 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "test_dependabot.py"
Cohesion: 0.24
Nodes (7): _blocks(), Dependabot keeps the pinned GitHub Actions current. Pinning every action to a…, test_dependabot_watches_github_actions_weekly(), Tripwire: every GitHub Action is pinned to a full commit SHA. A tag such as…, _references(), test_every_action_is_pinned_to_a_commit_sha(), test_workflows_reference_actions()

### Community 165 - "test_console_app.py"
Cohesion: 0.17
Nodes (21): assert_strict_csp(), Response, link_token(), Any, AsyncClient, Path, The sample console against a real Postgres: mounting, the Content Security…, The users screen's reset button calls warden's own route (question 6). (+13 more)

### Community 166 - ".register"
Cohesion: 0.16
Nodes (13): Algorithm, AttestationFormat, FLAG, PrivateKey, _new_key(), Any, AuthenticatorData, CollectedClientData (+5 more)

### Community 167 - "subprocess"
Cohesion: 0.13
Nodes (14): subprocess, parametrize, The public import surface, fixed as a snapshot. warden's public API is whatever…, test_every_exported_name_resolves_once(), test_the_public_names_match_the_snapshot(), _device_modules_after(), parametrize, Tripwire: warden uses fido2's relying-party side only, never its device code.… (+6 more)

### Community 169 - "._accept"
Cohesion: 0.16
Nodes (12): Complete, MethodCheck, AcceptedInvitation, check(), complete(), PasskeyRegistration, Protocol, The WebAuthn registration, run inside the acceptance transaction. Called with… (+4 more)

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "main"
Cohesion: 0.23
Nodes (16): main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests.…, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed() (+8 more)

### Community 173 - "test_cli_audit_errors.py"
Cohesion: 0.19
Nodes (14): _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path, The warden audit CLI without a database: connection failures and grants. (+6 more)

### Community 174 - "tests/conftest.py"
Cohesion: 0.32
Nodes (7): dsn(), migrated_dsn(), pg_admin_url(), fixture, Shared fixtures. Database tests use a real Postgres through testcontainers., A fresh, empty database for one test., run()

### Community 175 - "test_console_gaps.py"
Cohesion: 0.18
Nodes (7): Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., Question 39 was a defect in the admin route, fixed in warden 0.1.0., test_forbid_user_details_is_no_longer_a_gap(), test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap()

### Community 176 - "test_config_passwords.py"
Cohesion: 0.22
Nodes (18): _parse(), Any, parametrize, Start-up validation of the password settings (rulings PW2, PW7 and PW8 of 10…, _refused(), test_a_fingerprint_key_name_makes_the_fingerprint_available(), test_a_malformed_secret_name_is_refused(), test_a_previous_key_needs_a_current_key() (+10 more)

### Community 177 - "test_sso_password_state.py"
Cohesion: 0.22
Nodes (12): app(), config(), idp(), Any, AsyncClient, FastAPI, fixture, parametrize (+4 more)

### Community 178 - "test_identity_reset.py"
Cohesion: 0.21
Nodes (17): parametrize, UserFactory, Password reset by emailed link: refusal paths, single use (#127), sessions…, #127 for reset tokens., _reasons(), test_a_failed_send_leaves_no_link(), test_a_link_is_refused_and_spent_if_the_account_changed_since(), test_a_new_request_revokes_earlier_links() (+9 more)

### Community 179 - ".__init__"
Cohesion: 0.29
Nodes (3): Protocol, SecretReader, SecretWriter

### Community 180 - "test_webauthn_credentials.py"
Cohesion: 0.18
Nodes (15): fido2_utils, LogCaptureFixture, parametrize, UserFactory, The credential store (list, rename, remove, count) and challenge pruning., test_an_invalid_nickname_is_refused(), test_another_users_credential_cannot_be_touched(), test_list_count_rename_and_remove() (+7 more)

### Community 181 - "test_sso_preset_label_only.py"
Cohesion: 0.39
Nodes (8): preset_names(), Tripwire: the single sign-on provider preset is a label, never behaviour.…, scanned(), test_every_configured_preset_has_guidance(), test_no_sign_in_module_reads_the_preset(), test_the_allowed_modules_really_carry_the_label(), test_the_scan_covers_the_sign_in_code(), _violations()

### Community 182 - "licence_audit.py"
Cohesion: 0.23
Nodes (14): packaging_requirements, packaging_utils, audit(), classify(), data_problems(), installed(), main(), _one() (+6 more)

### Community 183 - "SignInThrottle"
Cohesion: 0.06
Nodes (32): PasswordPruning, Pruner, PruneReport, Identifier, Protocol, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., What the pruner needs from password policies. (+24 more)

### Community 184 - "require_permission"
Cohesion: 0.29
Nodes (9): Forbidden, installed_identity(), HTTPException, Request, A dependency requiring ``permission``; with ``scoped``, also the product's…, The signed-in user (by access token or API key), or the uniform 401 refusal., require_permission(), dependency() (+1 more)

### Community 185 - "copy"
Cohesion: 0.22
Nodes (9): copy, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1() (+1 more)

### Community 186 - "PolicySettings"
Cohesion: 0.25
Nodes (8): PolicySettings, What an administrator sets on a policy: everything but its id, priority and…, The outcome of ``match``: the first match, and whether the range API could not…, Whether the password is refused: a match, or an unreachable API the policy…, The first watch list ``password`` is on under ``policy``; whether the API…, As ``match``, for a fingerprint's digest: every check but terms, which need the…, _settings_of(), WatchListCheck

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
Cohesion: 0.24
Nodes (6): _LazySecrets, _OneConnection, Any, AsyncConnection, A connection source lending a single connection, for one CLI command., konfig ``Secrets``, constructed only if a command actually needs a secret.

### Community 192 - "test_identity_roles.py"
Cohesion: 0.25
Nodes (13): _admins(), UserFactory, Role assignments: audited, expiring, and never leaving no administrator., Two administrators demoting each other at once: exactly one demotion succeeds., test_an_administrator_role_cannot_expire(), test_an_expired_assignment_grants_nothing(), test_an_inactive_administrator_does_not_count(), test_assign_and_revoke_are_audited() (+5 more)

### Community 193 - "test_console_password_rules.py"
Cohesion: 0.26
Nodes (11): answers(), cases(), node(), Any, fixture, parametrize, TempPathFactory, The browser's password rules against warden's test vectors. The checklist in… (+3 more)

### Community 194 - "identity/actions.py"
Cohesion: 0.18
Nodes (6): The audit actions identity records, registered when ``Identity`` is constructed., _identity_actions(), fixture, Fixtures for password policy tests: identity's audit actions are registered, as…, Every audit action password policies and watch lists need is registered now…, test_every_password_action_is_registered()

### Community 195 - ".sso_settings_router"
Cohesion: 0.18
Nodes (6): APIRouter, Invitation acceptance and password reset; mount under…, Administration routes; mount under ``config.http.admin_prefix``. ``permission``…, The public sign-in routes; mount under ``config.http.auth_prefix``., The single sign-on routes; mount under ``config.http.auth_prefix`` too., Single sign-on administration; mount under ``config.http.admin_prefix``.…

### Community 196 - "Refused"
Cohesion: 0.67
Nodes (3): HTTPException, Raised by dependencies; FastAPI's default handler renders the uniform refusal., Refused

### Community 197 - "Notes"
Cohesion: 0.27
Nodes (4): Note, Notes, Any, The in-memory note store.

### Community 198 - "_Invalid"
Cohesion: 0.67
Nodes (3): _Invalid, Exception, A policy body refused, with each field at fault and a fixed message.

### Community 199 - "test_password_enforcement_keys.py"
Cohesion: 0.33
Nodes (10): _amr(), Any, AsyncClient, parametrize, UserFactory, Password policies with security keys and passkeys (rulings PW9 and P4 to P7). A…, _sign_in(), test_a_forced_enrolment_with_a_key_answers_the_change_with_the_key() (+2 more)

### Community 200 - "AnchorSigner"
Cohesion: 0.24
Nodes (5): AnchorSigner, _KeyLike, Protocol, What anchoring needs from the key store: ``KeyStore`` fits., _SignatureLike

### Community 201 - "resolve"
Cohesion: 0.22
Nodes (7): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PW1: the pin, else the highest-priority mapped and declared role, else the…, resolve(), test_resolution_order_is_pin_then_highest_priority_role_then_default()

### Community 202 - "notes_router"
Cohesion: 0.33
Nodes (8): _audit(), notes_router(), create_note(), delete_note(), found(), update_note(), APIRouter, ``/notes`` routes; the sample mounts them under ``/api``.

### Community 203 - "NoteScope"
Cohesion: 0.22
Nodes (7): NoteScope, IPv4Address, IPv6Address, Request, The client address (already resolved by the trusted-proxy middleware), if it is…, The product's resource-scope hook (warden's ``ResourceScopeHook``). warden…, _source()

### Community 204 - "test_client_guide.py"
Cohesion: 0.47
Nodes (4): _contract_routes(), The client-behaviour guide (docs/guide/clients.md) and the contract agree on…, test_every_contract_route_is_linked_from_the_guide(), test_every_route_the_guide_names_is_in_the_contract()

### Community 205 - "keys_router"
Cohesion: 0.25
Nodes (9): _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter, Response (+1 more)

### Community 206 - "test_identity_totp_storage.py"
Cohesion: 0.36
Nodes (8): MemorySecrets, UserFactory, TOTP secrets are sealed at rest, bound to their user, and survive key rotation., _row(), test_a_secret_copied_to_another_user_does_not_open(), test_identity_refuses_to_start_without_a_totp_key(), test_rotation_keeps_enrolments_working_and_reseals(), test_the_stored_secret_is_sealed()

### Community 207 - "totp.py"
Cohesion: 0.12
Nodes (17): hmac, generate_recovery_codes(), generate_secret(), hash_recovery_code(), matching_step(), parse_code(), parse_recovery_code(), provisioning_uri() (+9 more)

### Community 208 - "BaseModel"
Cohesion: 0.40
Nodes (5): BaseModel, Only the fields to change; each is validated by the configuration's rules., SsoSettingsBody, WardenPresetGuide, WardenSsoSettingsView

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 211 - "app.py"
Cohesion: 0.11
Nodes (17): collections, Console, The sample console's application: how a product wires warden into FastAPI. Read…, The built console: the app and the warden objects behind it., The sample's own routes, built on warden's public Python API. Where warden…, A development clock for the sample: walk password expiry without waiting.…, Outbox, A mail sender that keeps messages in memory, so the console can show them.… (+9 more)

### Community 213 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends an acceptance transaction without committing it.

### Community 216 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends a transaction without committing it.

### Community 219 - "package"
Cohesion: 0.67
Nodes (3): package(), fixture, Install a throwaway template package under a unique name.

## Knowledge Gaps
- **110 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+105 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1934 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **20 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `AuditEvent`, `SourceIp`, `KeyStore`, `RecordingSender`, `test_webauthn_mfa.py`, `contract.py`, `password_admin.py`, `webauthn.py`, `SoftwareAuthenticator`, `Database`, `SingleSignOn`, `PasswordEnforcement`, `SignInMethod`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `test_identity_key_publication.py`, `PasswordHasher`, `rules.py`, `current_code`, `test_password_sign_in.py`, `admin.py`, `warden/cli.py`, `WebAuthn`, `Mfa`, `test_identity_prune.py`, `User`, `Mailer`, `test_password_recheck.py`, `export_openapi.py`, `typing`, `PasswordStates`, `test_identity_apikeys.py`, `PermissionRegistry`, `test_sso_live.py`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `lifecycle.py`, `build_sso_router`, `test_password_admin_routes.py`, `test_identity_throttle.py`, `test_identity_admin_routes.py`, `SecretBox`, `test_sso_capabilities.py`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `MailMessage`, `Roles`, `test_passkey_invitation.py`, `audit_rows`, `PolicyStore`, `test_password_feedback.py`, `parse_config`, `test_sso_issuer.py`, `Cluster: test_identity_client_address.py`, `.__init__`, `test_passkey_options_throttle.py`, `build_console`, `test_password_set_points.py`, `MemorySecrets`, `passkey_support.py`, `.prune`, `identity/__init__.py`, `console_router`, `SingleUseTokens`, `test_password_cli.py`, `test_identity_capabilities.py`, `PasswordHistory`, `mail.py`, `test_sso_password_state.py`, `test_identity_reset.py`, `SignInThrottle`, `require_permission`, `password_support.py`, `test_identity_roles.py`, `.sso_settings_router`, `test_password_enforcement_keys.py`, `test_identity_totp_storage.py`, `.install`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`?**
  _High betweenness centrality (0.123) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `syslog/__init__.py`, `AuditEvent`, `KeyStore`, `RecordingSender`, `AuditRecorder`, `test_webauthn_mfa.py`, `test_audit_recorder.py`, `SoftwareAuthenticator`, `PasswordPolicies`, `password_policy/__init__.py`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `test_audit_retention.py`, `test_syslog_forwarder.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `warden/cli.py`, `WebAuthn`, `SyslogSettings`, `test_identity_prune.py`, `User`, `verify.py`, `soft_authenticator.py`, `test_password_recheck.py`, `export_openapi.py`, `typing`, `PasswordStates`, `test_identity_apikeys.py`, `PermissionRegistry`, `test_sso_live.py`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_admin_routes.py`, `test_identity_throttle.py`, `test_identity_admin_routes.py`, `SecretBox`, `Cluster: test_key_publication.py`, `json`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `test_audit_router.py`, `verify_chain`, `attestation.py`, `WatchLists`, `Roles`, `test_passkey_invitation.py`, `test_syslog_routes.py`, `audit_rows`, `test_password_watch_lists.py`, `PolicyStore`, `test_password_feedback.py`, `test_audit_grants.py`, `parse_config`, `test_sso_issuer.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `.__init__`, `test_passkey_options_throttle.py`, `build_console`, `test_password_set_points.py`, `MemorySecrets`, `passkey_support.py`, `identity/__init__.py`, `test_password_policy_store.py`, `SingleUseTokens`, `test_password_cli.py`, `BuiltinList`, `test_a_purge_committing_during_verification_breaks_nothing`, `test_database.py`, `test_identity_capabilities.py`, `PasswordHistory`, `Identity`, `test_identity_reset.py`, `.__init__`, `test_webauthn_credentials.py`, `SignInThrottle`, `ConnectionSource`, `test_identity_roles.py`, `test_identity_totp_storage.py`?**
  _High betweenness centrality (0.116) - this node is a cross-community bridge._
- **Why does `AuditEvent` connect `AuditEvent` to `syslog/__init__.py`, `SourceIp`, `PasswordResets`, `AuditRecorder`, `password_admin.py`, `test_audit_recorder.py`, `PasswordPolicies`, `SingleSignOn`, `Invitations`, `test_audit_anchor_format.py`, `PasswordEnforcement`, `SignInMethod`, `password_policy/__init__.py`, `test_a_purge_committing_during_verification_breaks_nothing`, `SsoSettingsStore`, `test_audit_retention.py`, `test_syslog_forwarder.py`, `SyslogSettings`, `Mfa`, `typing`, `test_audit_registry.py`, `Sessions`, `notes_router`, `json`, `test_audit_router.py`, `verify_chain`, `WatchLists`, `Roles`, `test_syslog_routes.py`, `PolicyStore`, `_purge_prefix`, `test_audit_grants.py`, `test_audit_chain_recorder.py`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Are the 93 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 93 INFERRED edges - model-reasoned connections that need verification._
- **Are the 152 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 152 INFERRED edges - model-reasoned connections that need verification._
- **Are the 134 inferred relationships involving `KeyStore` (e.g. with `build_console()` and `Console`) actually correct?**
  _`KeyStore` has 134 INFERRED edges - model-reasoned connections that need verification._