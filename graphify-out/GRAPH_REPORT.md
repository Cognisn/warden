# Graph Report - warden  (2026-11-10)

## Corpus Check
- 326 files · ~334,382 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 6814 nodes · 22205 edges · 229 communities (209 shown, 20 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2046 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `65aa9dd9`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- ActionRegistry
- FakeIdp
- AuditEvent
- SourceIp
- KeyStore
- Database
- reset.py
- AuditRecorder
- h
- test_webauthn_mfa.py
- contract.py
- build_password_admin_router
- build_auth_router
- test_audit_recorder.py
- classify_error
- SoftwareAuthenticator
- test_console_password_policy.py
- test_sso_invitations.py
- PasswordPolicies
- SingleSignOn
- Invitations
- WebAuthnError
- anchor.py
- password_enforcement.py
- identity/__init__.py
- test_webauthn_reset.py
- test_audit_chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- SsoSettingsStore
- CI Workflows
- test_audit_retention.py
- format_message
- test_identity_key_publication.py
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
- WebAuthn
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
- export_openapi.py
- typing
- PasswordStates
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- test_config_webauthn.py
- current_revision
- httpx
- test_webauthn_live.py
- Sessions
- test_identity_dependencies.py
- test_passkey_registration_link.py
- Outbox
- sso.py
- console_support.py
- test_password_admin_routes.py
- test_identity_throttle.py
- build_sso_settings_router
- test_identity_admin_routes.py
- test_webauthn_migration.py
- SecretBox
- Cluster: test_key_publication.py
- test_sso_capabilities.py
- AuditQuery
- test_openapi_contract.py
- test_identity_migration.py
- test_sso_migration.py
- test_identity_sign_in.py
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
- password_policy/__init__.py
- SsoError
- Module
- MailMessage
- test_syslog_sd_id.py
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- test_console_passkeys.py
- test_syslog_routes.py
- test_identity_lifecycle_routes.py
- WatchLists
- PolicyStore
- check_dist.py
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
- test_packaging.py
- Challenges
- test_lifecycle_migration.py
- test_bump_version.py
- build_console
- test_password_policy_migration.py
- test_password_set_points.py
- Checkpoint
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- test_readme.py
- _FieldProblems
- PruneReport
- WebAuthnRefusal
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- load_cursor
- .consume
- BuiltinList
- test_console_capabilities.py
- test_no_direct_environment.py
- Cluster: updates
- WebAuthnConfig
- test_audit_verify_snapshot.py
- test_database.py
- test_identity_capabilities.py
- test_tls_fail_closed.py
- ceremony.js
- PasswordHistory
- Cluster: verify
- _Section
- load_settings
- Cluster: rsyslog
- test_password_hibp.py
- Identity
- test_licence_audit.py
- test_dependabot.py
- PasswordsConfig
- audit_router
- pytest
- Cluster: examples/__init__.py
- test_sso_break_glass_live.py
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- test_cli_audit.py
- test_cli_audit_errors.py
- tests/conftest.py
- test_console_gaps.py
- UdpCollector
- app
- test_audit_export.py
- SecretReader
- test_syslog_live.py
- test_sso_preset_label_only.py
- licence_audit.py
- SignInThrottle
- require_user
- test_cli_errors.py
- test_public_api.py
- ConnectionSource
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- .sign_in
- _LazySecrets
- WebAuthnCredential
- neutralise
- .__init__
- split_frames
- Refused
- Notes
- _Invalid
- AnchorCheck
- test_audit_chain_migration.py
- test_lock_live_holds_the_token_until_the_holder_ends
- round_trip
- test_a_reset_racing_a_registration_ends_consistent
- test_client_guide.py
- .factory
- make
- matching_step
- test_sso_signs_in_whatever_the_passwords_state
- .install
- The built-in common-password list
- app.py
- _clip
- build
- .prune
- registry
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

## Communities (229 total, 20 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.06
Nodes (111): assert_refused(), expire_challenge_of(), give_passkey(), http_client(), passkey_app(), passkey_assertion(), passkey_config(), passkey_options() (+103 more)

### Community 1 - "ActionRegistry"
Cohesion: 0.03
Nodes (109): errno, IntEnum, psycopg_pq, pydantic, socket, The audit actions warden's own audit subsystem records., Register warden's audit actions. Idempotent., register_audit_actions() (+101 more)

### Community 2 - "FakeIdp"
Cohesion: 0.07
Nodes (61): Discovery, JwksCache, ProviderHttp, ProviderMetadata, AsyncClient, The provider's metadata, cached per issuer., Fetch and check the metadata, bypassing the cache., The provider's signing keys, by key id. (+53 more)

### Community 3 - "AuditEvent"
Cohesion: 0.04
Nodes (54): AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., Record ``event`` through the installed recorder. See ``AuditRecorder.record``., record_audit(), The one-line summary for ``event``; absent fields render as ``-``., IdentityConfig, ApiKey (+46 more)

### Community 4 - "SourceIp"
Cohesion: 0.05
Nodes (45): Principal, The signed-in user behind a request. For a request made with an API key,…, _credential_id(), PasswordChangeIssued, PasswordTokenPair, Any, AsyncConnection, ChallengePurpose (+37 more)

### Community 5 - "KeyStore"
Cohesion: 0.05
Nodes (65): Ed25519PrivateKey, _b64url(), _b64url_decode(), key_id_for(), KeyStore, KeyStoreError, PublicKey, Any (+57 more)

### Community 6 - "Database"
Cohesion: 0.05
Nodes (101): Database, warden's handle on the product's connection pool., A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, audit_rows(), race() (+93 more)

### Community 7 - "reset.py"
Cohesion: 0.06
Nodes (47): html, _is_control(), MailDeliveryError, MailError, MailSender, _neutralise(), Exception, Protocol (+39 more)

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
Cohesion: 0.04
Nodes (97): AffectedUsersProposalBody, BuiltinListBody, _Doc, InvitationAcceptBody, LinkPasswordCheckBody, LinkTokenBody, PasskeyRegistrationBody, PasskeyTokenBody (+89 more)

### Community 12 - "build_password_admin_router"
Cohesion: 0.08
Nodes (68): build_password_admin_router(), actor(), add_entries(), add_terms(), affected(), attach_list(), attached_to(), attachment() (+60 more)

### Community 13 - "build_auth_router"
Cohesion: 0.07
Nodes (53): bearer_token(), build_auth_router(), capabilities(), APIRouter, Public sign-in routes. The product mounts them under…, ChallengeBody, ChangePasswordBody, CodeBody (+45 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.14
Nodes (29): Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any (+21 more)

### Community 15 - "classify_error"
Cohesion: 0.11
Nodes (10): DatagramTransport, classify_error(), BaseException, Exception, TCP or TLS. After any failure the connection is spent and must be replaced., One message per datagram. UDP has no acknowledgement, so delivery is best…, A fixed, detail-free category for ``exc``., StreamTransport (+2 more)

### Community 16 - "SoftwareAuthenticator"
Cohesion: 0.10
Nodes (60): One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, LogCaptureFixture, parametrize, UserFactory, The credential store (list, rename, remove, count) and challenge pruning., test_an_invalid_nickname_is_refused(), test_another_users_credential_cannot_be_touched() (+52 more)

### Community 17 - "test_console_password_policy.py"
Cohesion: 0.10
Nodes (49): assert_strict_csp(), bearer(), make_user(), AsyncClient, Response, sign_in(), link_token(), Any (+41 more)

### Community 18 - "test_sso_invitations.py"
Cohesion: 0.11
Nodes (58): Body, Started, accept(), acceptance_rows(), app(), _bodies(), config(), handoffs_of() (+50 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.07
Nodes (46): PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, A password policy, or a change to one, was refused., No password policy has that id., The change clashes with the stored state: a stale version, a name or priority…, Delete history beyond the largest count any policy keeps; returns how many., _check_priority() (+38 more)

### Community 20 - "SingleSignOn"
Cohesion: 0.12
Nodes (22): _challenge(), _hash(), _PinRefused, Any, AsyncConnection, Exception, NoReturn, SourceIp (+14 more)

### Community 21 - "Invitations"
Cohesion: 0.08
Nodes (34): Complete, Method, MethodCheck, _Abort, InvitationError, Invitations, check(), complete() (+26 more)

### Community 22 - "WebAuthnError"
Cohesion: 0.09
Nodes (31): PublicKeyCredentialDescriptor, Exception, A WebAuthn ceremony or credential change was refused. ``user_id`` and…, Whether the refusal reports a credential that may have been copied., WebAuthnError, Passkeys and security keys (WebAuthn): the ceremonies and the credential store.…, _extension_results(), _parse() (+23 more)

### Community 23 - "anchor.py"
Cohesion: 0.06
Nodes (64): cryptography_hazmat_primitives_asymmetric_ed25519, Anchor, AnchorError, AnchorSigner, _b64url(), _b64url_decode(), _from_ndjson(), _from_syslog() (+56 more)

### Community 24 - "password_enforcement.py"
Cohesion: 0.06
Nodes (43): SetPlace, AcceptedPassword, _match_details(), PasswordAdvice, PasswordEnforcement, PasswordFailure, PasswordFeedback, PasswordRejected (+35 more)

### Community 25 - "identity/__init__.py"
Cohesion: 0.05
Nodes (70): Protocol, The product's resource-level check, consulted by ``require_permission(...,…, ResourceScopeHook, warden's identity subsystem: users, sign-in, sessions, roles and permissions,…, AcceptedInvitation, Invitation, InvitationMismatch, PendingInvitation (+62 more)

### Community 26 - "test_webauthn_reset.py"
Cohesion: 0.26
Nodes (19): _admin(), _bearer(), http(), AsyncClient, fixture, MonkeyPatch, Response, UserFactory (+11 more)

### Community 27 - "test_audit_chain.py"
Cohesion: 0.08
Nodes (42): JsonValue, address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields(), _number() (+34 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.10
Nodes (44): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+36 more)

### Community 29 - "test_config.py"
Cohesion: 0.07
Nodes (66): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, FakeSecrets, FakeSettings, _load(), _parse(), Any (+58 more)

### Community 30 - "json_response"
Cohesion: 0.09
Nodes (61): json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), begin_enrolment(), change_password() (+53 more)

### Community 31 - "SsoSettingsStore"
Cohesion: 0.09
Nodes (31): _from_config(), _plain(), Any, AsyncConnection, ValueError, The effective settings, cached for ``max_age`` seconds., The effective settings, read now on ``conn`` (no cache)., Override some fields: validated as a whole, audited, and, when this turns… (+23 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_audit_retention.py"
Cohesion: 0.11
Nodes (40): purge(), Exception, A purge was refused. The message carries row ids only., Delete audit rows older than ``retention_days`` behind a signed checkpoint., RetentionError, Any, Connection, Test-only helpers that stand in for audit rows recorded long ago. Ageing a row… (+32 more)

### Community 34 - "format_message"
Cohesion: 0.25
Nodes (27): format_message(), The RFC 5424 message for ``record``, at most ``settings.max_message_bytes``…, _oversized(), _parse(), Any, parametrize, The RFC 5424 formatter: neutralised values, escaping and a byte cap that caps., Split a formatted message into header fields, SD params and MSG. (+19 more)

### Community 35 - "test_identity_key_publication.py"
Cohesion: 0.14
Nodes (22): PyJWK, _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter (+14 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.14
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.24
Nodes (34): ForwarderFactory, _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), _leader(), Any (+26 more)

### Community 38 - "rules.py"
Cohesion: 0.05
Nodes (81): _bool(), _classes(), _detail_tokens(), evaluate(), Evaluation, _int(), _local_part(), _longest_run() (+73 more)

### Community 39 - "current_code"
Cohesion: 0.09
Nodes (55): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), _challenge(), _enrolled(), _fresh_code() (+47 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.11
Nodes (41): frame(), open_transport(), SSLContext, Connect to the collector named in ``settings``; ``TransportError`` on failure., Frame ``message`` for a stream transport (RFC 6587)., A client context that verifies the chain and host name, TLS 1.2 or later. The…, tls_context(), Authority (+33 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.09
Nodes (66): failing_transport(), handler(), listing_transport(), MockTransport, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., bearer() (+58 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.09
Nodes (15): Any, AsyncConnection, Task, Begin competing for the forwarder lock and, once held, forwarding., Stop forwarding, release the lock and close the transport. Idempotent., Switch to new settings; the next send opens a transport with them. Waits for an…, Try for the lock; lead until stopped or the session ends. True if it led., Read every notification as it arrives, so Postgres' queue never backs up. (+7 more)

### Community 43 - "admin.py"
Cohesion: 0.08
Nodes (68): A dependency requiring ``permission``; with ``scoped``, also the product's…, require_permission(), _api_key(), _assignment(), _BadRequest, build_admin_router(), assign_role(), capabilities() (+60 more)

### Community 44 - "test_sso_sealing.py"
Cohesion: 0.15
Nodes (26): cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's…, The token sealed in ``sealed``, or None if it does not open to one. (+18 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (11): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+3 more)

### Community 46 - "warden/cli.py"
Cohesion: 0.08
Nodes (53): BinaryIO, sqlalchemy_exc, ExternalAnchor, An anchor found in an export: its line, its own row id when known, and the…, PurgeResult, AnchorReport, The chain's own verification, and each external anchor checked against it., VerificationReport (+45 more)

### Community 47 - "WebAuthn"
Cohesion: 0.19
Nodes (36): The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, _enrolled(), Any, parametrize, UserFactory, UUID (+28 more)

### Community 48 - "SyslogSettings"
Cohesion: 0.12
Nodes (18): BaseModel, field_validator, model_validator, Self, Everything the forwarder, formatter and transports need., SyslogSettings, StreamReader, StreamWriter (+10 more)

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
Cohesion: 0.11
Nodes (71): User, callback(), completion(), handoff(), provider_code(), Any, AsyncClient, Response (+63 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.12
Nodes (34): importlib_util, dist(), _load(), _only(), fixture, ModuleType, MonkeyPatch, parametrize (+26 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.14
Nodes (28): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+20 more)

### Community 55 - "AuditRow"
Cohesion: 0.14
Nodes (17): BreakReason, HistoricalVerifier, Protocol, What verification needs from the key store: ``KeyStore`` fits., AuditRow, Any, A stored audit row: every hashed column plus the stored ``row_hash``., An ``AuditRow`` from a result row selected with ``ROW_COLUMNS``. (+9 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.07
Nodes (40): Algorithm, AttestationFormat, CoseKey, fido2, fido2_cose, fido2_utils, FLAG, PrivateKey (+32 more)

### Community 57 - "Mailer"
Cohesion: 0.18
Nodes (27): MailConfig, Mail settings. The product implements the sender. Provisional until 0.1.0b1., _check(), _load(), Mailer, MailKind, MailTemplate, StrEnum (+19 more)

### Community 58 - "PolicySettings"
Cohesion: 0.11
Nodes (24): PolicySettings, What an administrator sets on a policy: everything but its id, priority and…, The outcome of ``match``: the first match, and whether the range API could not…, Whether the password is refused: a match, or an unreachable API the policy…, The first watch list ``password`` is on under ``policy``; whether the API…, As ``match``, for a fingerprint's digest: every check but terms, which need the…, _settings_of(), WatchListCheck (+16 more)

### Community 59 - "export_openapi.py"
Cohesion: 0.13
Nodes (18): build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), Any, AsyncConnection (+10 more)

### Community 60 - "typing"
Cohesion: 0.04
Nodes (102): argon2, argon2_exceptions, asyncio, base64, binascii, collections_abc, contextlib, cryptography_exceptions (+94 more)

### Community 61 - "PasswordStates"
Cohesion: 0.07
Nodes (48): ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID, Forced-change challenges (ruling PW9). After a correct password and the second…, Use the challenge up; False if another request already did, or it lapsed. (+40 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.14
Nodes (26): ApiKeyError, Exception, An API key change was refused. Messages carry no values., _app(), _bearer(), client(), AsyncClient, FastAPI (+18 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.04
Nodes (79): PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role, make_config(), MemorySecrets (+71 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.12
Nodes (25): _address(), Any, Network, _Scope, Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``., The client address, given the peer and every ``X-Forwarded-For`` value in order., ASGI middleware setting ``scope["client"]`` to the resolved client address., resolve_client_ip() (+17 more)

### Community 65 - "test_config_webauthn.py"
Cohesion: 0.11
Nodes (36): _certificate(), _parse(), Any, parametrize, Start-up validation of the WebAuthn settings (rulings P2, P3 and P7 of 6…, _refused(), _Secrets, test_a_malformed_passkey_registration_link_is_refused() (+28 more)

### Community 66 - "current_revision"
Cohesion: 0.09
Nodes (41): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), current_revision(), downgrade(), heads() (+33 more)

### Community 67 - "httpx"
Cohesion: 0.16
Nodes (17): httpx, accept_through_sso(), AsyncClient, parametrize, Live check: an invitation accepted through single sign-on, against the stub…, test_live_invitation_accepted_through_sso_then_sign_in_by_subject(), app(), browser_to_idp() (+9 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.06
Nodes (47): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+39 more)

### Community 69 - "Sessions"
Cohesion: 0.11
Nodes (21): AccessClaims, _b64(), _hash(), _json(), Any, AsyncConnection, NoReturn, SourceIp (+13 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.13
Nodes (21): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, UserFactory (+13 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.20
Nodes (34): admin(), config(), _credential_count(), http(), _identity(), _link(), _options(), Any (+26 more)

### Community 72 - "Outbox"
Cohesion: 0.13
Nodes (10): Outbox, Any, A ``MailSender`` holding the last ``limit`` messages, newest last., The kept messages, newest first, as the outbox page shows them., Scope, ASGI middleware adding the policy and related headers to every HTTP answer., SecurityHeaders, with_headers() (+2 more)

### Community 73 - "sso.py"
Cohesion: 0.08
Nodes (40): client_ip(), Network, Request, SourceIp, The client address, for audit events and the sign-in throttle key. Resolved by…, HandoffBody, _inline(), resolve() (+32 more)

### Community 74 - "console_support.py"
Cohesion: 0.14
Nodes (18): client(), console(), make_console(), build(), Any, AsyncClient, fixture, MemorySecrets (+10 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.07
Nodes (66): bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests., app(), client() (+58 more)

### Community 76 - "test_identity_throttle.py"
Cohesion: 0.16
Nodes (20): _fail(), fixture, UserFactory, Sign-in throttling per (identifier, source address)., Otherwise a password holder gets unlimited challenges, and so unlimited code…, Barriered concurrent attempts: no more than the limit reach password…, An attacker elsewhere cannot lock the user out., Throttling must not reveal whether an account exists. (+12 more)

### Community 77 - "build_sso_settings_router"
Cohesion: 0.13
Nodes (18): build_sso_settings_router(), actor_id(), get_settings(), put_client_secret(), put_settings(), reset_settings(), source(), test_configuration() (+10 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.18
Nodes (24): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+16 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "SecretBox"
Cohesion: 0.05
Nodes (49): _decode(), _key_id(), new_totp_key(), Exception, Protocol, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., A TOTP key is missing or malformed. Names the secret, never its value. (+41 more)

### Community 81 - "Cluster: test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "AuditQuery"
Cohesion: 0.11
Nodes (29): csv, ExportFormat, io, export(), Record the export, then stream the matching rows in chain order. The export…, AuditQuery, iter_events(), BaseModel (+21 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.20
Nodes (14): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+6 more)

### Community 86 - "test_sso_migration.py"
Cohesion: 0.26
Nodes (11): Connection, parametrize, UUID, Single sign-on's migration: its tables, their constraints, and a tested…, _tables(), test_a_subject_is_pinned_to_one_user(), test_a_user_has_at_most_one_pin(), test_constraints() (+3 more)

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

### Community 92 - "pathlib"
Cohesion: 0.09
Nodes (25): cryptography, cryptography_hazmat_primitives, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, cryptography_x509_oid, pathlib, _current_branch(), main() (+17 more)

### Community 93 - "test_audit_router.py"
Cohesion: 0.14
Nodes (23): list_events(), A page of matching rows, newest first, older than ``before_id`` if given., client(), exporter(), NoKeys, Any, AsyncClient, fixture (+15 more)

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

### Community 98 - "password_policy/__init__.py"
Cohesion: 0.06
Nodes (45): HibpUnavailable, Exception, ValueError, Errors raised by password policies and watch lists. Messages carry field names,…, A watch list, or a change to one, was refused., No watch list has that id., The change clashes with the stored state: a list still attached to a policy., An import was refused or failed; the list is left as it was. ``line`` is the… (+37 more)

### Community 99 - "SsoError"
Cohesion: 0.11
Nodes (17): Exception, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic(), _https(), _KeySet, parse_metadata(), Any (+9 more)

### Community 100 - "Module"
Cohesion: 0.27
Nodes (8): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations()

### Community 101 - "MailMessage"
Cohesion: 0.14
Nodes (11): format_expiry(), MailMessage, datetime, A time for a message: UTC, to the minute, such as ``4 November 2026 at 03:07…, Render one message to ``email``. Datetime values are formatted with…, Hand a rendered message to the sender; ``MailDeliveryError`` if it fails., Render and deliver one message; returns what was sent., One rendered message, ready for the product's sender. (+3 more)

### Community 102 - "test_syslog_sd_id.py"
Cohesion: 0.14
Nodes (19): Any, Build settings from the shared ``SyslogConfig``. ``secrets`` looks up a konfig…, Syslog forwarding: every field ``SyslogSettings`` needs.…, SyslogConfig, _config(), Any, The default structured-data id, ``warden@67382`` (design D12, ruling of 28…, _record() (+11 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.10
Nodes (15): _check_secret_name(), _check_template(), _check_url(), HttpConfig, field_validator, ValueError, A konfig secret name: letters, digits, '.', '_', '/' and '-'., Validate an absolute http(s) URL; plain http only for loopback hosts. The value… (+7 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.15
Nodes (32): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+24 more)

### Community 106 - "test_console_passkeys.py"
Cohesion: 0.18
Nodes (28): authenticator(), A software authenticator that makes passkeys: discoverable, verifying the user., amr(), browser(), link_token(), outbox_message(), passkey_sign_in(), Any (+20 more)

### Community 107 - "test_syslog_routes.py"
Cohesion: 0.24
Nodes (18): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), _audit_rows(), authorise(), _client(), collector() (+10 more)

### Community 108 - "test_identity_lifecycle_routes.py"
Cohesion: 0.21
Nodes (17): app(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory, Public lifecycle routes: accept an invitation, request and complete a password… (+9 more)

### Community 109 - "WatchLists"
Cohesion: 0.12
Nodes (39): StrEnum, Watch lists, their entries and terms, imports, and matching., WatchListKind, WatchLists, builtin(), _lines(), lists(), Any (+31 more)

### Community 110 - "PolicyStore"
Cohesion: 0.08
Nodes (27): PolicyError, PolicyStore, Any, AsyncConnection, Event, ValueError, Whether ``listen()`` currently holds a LISTEN on the policy channel., Forget the cached policy; the next ``current()`` re-reads it. (+19 more)

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
Cohesion: 0.15
Nodes (23): _counts(), identity(), _place(), _policy(), Any, AsyncClient, fixture, parametrize (+15 more)

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
Cohesion: 0.17
Nodes (15): _format_errors(), load_config(), parse_config(), Any, Protocol, What warden needs from konfig's ``Settings``., What warden needs from konfig's ``Secrets``., Accept a comma-separated string (as the environment supplies) for a list field. (+7 more)

### Community 121 - "test_sso_issuer.py"
Cohesion: 0.18
Nodes (17): alice(), app(), config(), configured_issuer(), idp(), provider_issuer(), Any, FastAPI (+9 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.17
Nodes (27): _assert_one_unforked_chain(), _event(), Any, fixture, The chained recorder: links, server-side order, the details cap, and…, Poll until backend ``pid`` waits on the chain's advisory lock., Row id order is commit order: the second inserter waits for the first's commit., A server default of REPEATABLE READ must not make warden's own writes conflict. (+19 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 125 - "test_packaging.py"
Cohesion: 0.22
Nodes (3): packaging_version, warden: identity and audit for Python web applications. The public API lives in…, Packaging: one version source, typed marker, distribution metadata.

### Community 126 - "Challenges"
Cohesion: 0.16
Nodes (12): Ceremony, Challenges, ConsumedChallenge, _hash(), IssuedChallenge, Any, AsyncConnection, StrEnum (+4 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (14): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+6 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.20
Nodes (15): init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch., test_accepts_release_forms() (+7 more)

### Community 129 - "build_console"
Cohesion: 0.08
Nodes (33): actor(), build_console(), Console, _mount_pages(), FastAPI, Request, Build the console over the product's open pool and konfig's secrets store.…, The built console: the app and the warden objects behind it. (+25 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "test_password_set_points.py"
Cohesion: 0.13
Nodes (22): _administrator(), _change(), _codes(), _create(), _forced(), _hash(), _http_failures(), _invitation() (+14 more)

### Community 132 - "Checkpoint"
Cohesion: 0.19
Nodes (12): _b64url(), _b64url_decode(), Checkpoint, _int(), MalformedCheckpoint, Any, ValueError, A purge row's details do not hold a well-formed checkpoint. (+4 more)

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

### Community 137 - "PruneReport"
Cohesion: 0.14
Nodes (11): Pruner, PruneReport, Identifier, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., How many rows one prune deleted, by kind., scheduled(), loop() (+3 more)

### Community 138 - "WebAuthnRefusal"
Cohesion: 0.15
Nodes (17): StrEnum, UUID, Why a ceremony, or a change to a credential, was refused., WebAuthnRefusal, check_nickname(), credential_from_row(), Any, AsyncConnection (+9 more)

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
Cohesion: 0.11
Nodes (32): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PW1: the pin, else the highest-priority mapped and declared role, else the…, resolve(), Any, fixture (+24 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.24
Nodes (21): Purpose, StrEnum, Tokens in ``warden.single_use_tokens``. Every method works in the caller's…, SingleUseTokens, _consume(), _issue(), fixture, parametrize (+13 more)

### Community 144 - "load_cursor"
Cohesion: 0.23
Nodes (10): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+2 more)

### Community 145 - ".consume"
Cohesion: 0.16
Nodes (16): IssuedToken, _live_token(), LiveToken, Any, AsyncConnection, datetime, UUID, The user a token was issued to, live or not, without locking anything. (+8 more)

### Community 146 - "BuiltinList"
Cohesion: 0.12
Nodes (22): functools, BuiltinList, _bundled(), bundled_list(), _check(), Path, The built-in common-password list (ruling PW12). A read-only list of common…, Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled… (+14 more)

### Community 147 - "test_console_capabilities.py"
Cohesion: 0.29
Nodes (8): _admin(), _client(), Any, AsyncClient, The sample console asks warden what the deployment can do, and its screens…, test_with_a_sender_everything_that_mails_is_available(), test_without_a_sender_the_capabilities_say_so_and_the_503_stays(), test_without_the_link_setting_only_the_registration_link_is_unavailable()

### Community 148 - "test_no_direct_environment.py"
Cohesion: 0.31
Nodes (9): _enclosing_functions(), visit(), _findings(), AST, Tripwire: warden reads configuration only through konfig. No module under…, Each node's innermost enclosing function name, keyed by ``id(node)``., Every forbidden use, and whether it is the named exemption., test_each_exemption_covers_exactly_one_read() (+1 more)

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "WebAuthnConfig"
Cohesion: 0.13
Nodes (12): _base_origin(), _check_origin(), _is_domain(), A lower-case DNS name, or ``localhost``; never an IP address., An origin as a browser serialises it: no path, no default port., An exact origin, ``https://host[:port]``; plain http only for localhost., Passkeys and security keys (WebAuthn): the relying party and ceremony limits.…, The relying party id, or None when WebAuthn is unavailable. It is unavailable… (+4 more)

### Community 151 - "test_audit_verify_snapshot.py"
Cohesion: 0.19
Nodes (7): _AfterFirstQuery, _HookedPool, MemorySecrets, Any, Verification reads one snapshot: a purge committing mid-verification breaks…, Delegates to a connection, running ``hook`` once after the checkpoint listing., test_a_purge_committing_during_verification_breaks_nothing()

### Community 152 - "test_database.py"
Cohesion: 0.46
Nodes (7): _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.08
Nodes (52): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, app(), audit_registry(), client(), config(), db() (+44 more)

### Community 154 - "test_tls_fail_closed.py"
Cohesion: 0.39
Nodes (8): ast, expr, _findings(), _is_cert_required(), _is_true(), Tripwire: nothing in warden turns TLS verification off. Fails on any use of…, test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 155 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.08
Nodes (30): PasswordHistory, Any, AsyncConnection, datetime, UUID, Password history (ruling PW6). Each password a user sets is kept as its…, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password. (+22 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "_Section"
Cohesion: 0.18
Nodes (8): AuditConfig, DbConfig, KeysConfig, BaseModel, Database settings. At runtime warden uses the product's pool, never this DSN., Ed25519 signing keys. Private halves live in konfig's secrets store., Audit trail settings., _Section

### Community 159 - "load_settings"
Cohesion: 0.14
Nodes (23): _init(), Namespace, KonfigSecrets, load_settings(), Any, Path, Put the secrets warden needs in konfig's store, keeping any already there. The…, konfig's ``Secrets``, typed as the store warden expects (``get`` and ``set``). (+15 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "test_password_hibp.py"
Cohesion: 0.20
Nodes (18): _client(), LogCaptureFixture, parametrize, Request, Response, The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed…, Recorder, test_a_digest_must_be_twenty_bytes() (+10 more)

### Community 162 - "Identity"
Cohesion: 0.05
Nodes (90): Identity, warden's identity subsystem for one deployment., Run identity's background work (the session and password policy listeners) for…, Delete sign-in throttle records whose window has ended., Any, test_construction_writes_nothing_and_the_seeded_default_refuses_a_common_password(), test_prune_trims_history_and_expired_change_challenges(), test_running_also_listens_for_password_policy_changes() (+82 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "test_dependabot.py"
Cohesion: 0.24
Nodes (7): _blocks(), Dependabot keeps the pinned GitHub Actions current. Pinning every action to a…, test_dependabot_watches_github_actions_weekly(), Tripwire: every GitHub Action is pinned to a full commit SHA. A tag such as…, _references(), test_every_action_is_pinned_to_a_commit_sha(), test_workflows_reference_actions()

### Community 165 - "PasswordsConfig"
Cohesion: 0.22
Nodes (5): AsyncBaseTransport, PasswordsConfig, Password policies: the fingerprint key and the breached-password range API.…, Whether a policy may enable the sealed fingerprint (ruling PW8)., test_a_transport_error_is_the_same_fixed_error()

### Community 166 - "audit_router"
Cohesion: 0.12
Nodes (17): AwareDatetime, description, max_length, Outcome, Any, A row as a JSON-ready object: ISO timestamps (UTC), hex hashes., row_to_json(), _address_or_none() (+9 more)

### Community 167 - "pytest"
Cohesion: 0.12
Nodes (22): pytest, subprocess, answers(), cases(), node(), Any, fixture, parametrize (+14 more)

### Community 169 - "test_sso_break_glass_live.py"
Cohesion: 0.31
Nodes (8): os, app(), config(), Any, FastAPI, fixture, Live check: break-glass password sign-in with the identity provider stopped.…, secrets()

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "test_cli_audit.py"
Cohesion: 0.24
Nodes (14): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up() (+6 more)

### Community 173 - "test_cli_audit_errors.py"
Cohesion: 0.18
Nodes (15): copy, _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path (+7 more)

### Community 174 - "tests/conftest.py"
Cohesion: 0.31
Nodes (8): dsn(), migrated_dsn(), pg_admin_url(), pool(), Any, fixture, Shared fixtures. Database tests use a real Postgres through testcontainers., A fresh, empty database for one test.

### Community 175 - "test_console_gaps.py"
Cohesion: 0.22
Nodes (5): Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap()

### Community 176 - "UdpCollector"
Cohesion: 0.22
Nodes (3): Event, UdpCollector, _UdpProtocol

### Community 177 - "app"
Cohesion: 0.33
Nodes (7): app(), config(), idp(), Any, FastAPI, fixture, secrets()

### Community 178 - "test_audit_export.py"
Cohesion: 0.20
Nodes (20): csv_lines(), _csv_record(), escape_cell(), ndjson_lines(), One JSON object per line., ``value``, made safe to open in a spreadsheet., A header line, then one CSV record per row., _collect() (+12 more)

### Community 179 - "SecretReader"
Cohesion: 0.33
Nodes (3): Protocol, SecretReader, SecretWriter

### Community 180 - "test_syslog_live.py"
Cohesion: 0.36
Nodes (8): _lines_with(), Any, parametrize, Path, Live check: the forwarder against a real rsyslog collector over UDP, TCP and…, test_the_forwarder_delivers_to_a_real_collector(), test_tls_to_a_real_collector_fails_closed_with_the_wrong_ca(), _wait_for_lines()

### Community 181 - "test_sso_preset_label_only.py"
Cohesion: 0.39
Nodes (8): preset_names(), Tripwire: the single sign-on provider preset is a label, never behaviour.…, scanned(), test_every_configured_preset_has_guidance(), test_no_sign_in_module_reads_the_preset(), test_the_allowed_modules_really_carry_the_label(), test_the_scan_covers_the_sign_in_code(), _violations()

### Community 182 - "licence_audit.py"
Cohesion: 0.23
Nodes (14): packaging_requirements, packaging_utils, audit(), classify(), data_problems(), installed(), main(), _one() (+6 more)

### Community 183 - "SignInThrottle"
Cohesion: 0.12
Nodes (20): _address(), passkey_keys(), passkey_options_key(), password_check_keys(), Any, AsyncConnection, SourceIp, ``check_limit`` is the password check budget per credential (by default… (+12 more)

### Community 184 - "require_user"
Cohesion: 0.36
Nodes (7): Forbidden, installed_identity(), HTTPException, Request, The signed-in user (by access token or API key), or the uniform 401 refusal., dependency(), require_user()

### Community 185 - "test_cli_errors.py"
Cohesion: 0.24
Nodes (8): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1(), test_migrate_connection_failure_prints_a_fixed_message_and_exits_1()

### Community 186 - "test_public_api.py"
Cohesion: 0.22
Nodes (7): importlib, reset(), parametrize, The public import surface, fixed as a snapshot. warden's public API is whatever…, test_every_exported_name_resolves_once(), test_identity_exports_the_objects_its_modules_define(), test_the_public_names_match_the_snapshot()

### Community 187 - "ConnectionSource"
Cohesion: 0.18
Nodes (8): ConnectionSource, AbstractAsyncContextManager, Any, AsyncConnection, Protocol, Anything that lends async connections; ``psycopg_pool.AsyncConnectionPool``…, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - ".sign_in"
Cohesion: 0.25
Nodes (6): _Account, ChallengeIssued, The password was right; a second factor (or enrolment) is needed next., Exactly one of ``tokens``, ``challenge`` and ``password_change`` is set., Check a password. Every failure costs one password verification. Unknown users,…, SignInResult

### Community 191 - "_LazySecrets"
Cohesion: 0.29
Nodes (4): _LazySecrets, Any, AsyncConnection, konfig ``Secrets``, constructed only if a command actually needs a secret.

### Community 192 - "WebAuthnCredential"
Cohesion: 0.25
Nodes (6): The signed-in user's security keys and passkeys, oldest first., A successful sign-in with a credential., WebAuthnAssertion, A registered passkey or security key, as warden describes it., Whether it signs in on its own: discoverable and registered with user…, WebAuthnCredential

### Community 193 - "neutralise"
Cohesion: 0.29
Nodes (7): neutralise(), Match, Replace every control character in ``value`` with a visible ``\\xNN`` escape., _replacement(), test_neutralise_leaves_ordinary_text_alone(), test_neutralise_replaces_c1_controls_and_unicode_line_separators(), test_neutralise_replaces_every_c0_control_and_del()

### Community 194 - ".__init__"
Cohesion: 0.29
Nodes (4): PasswordPruning, Protocol, What the pruner needs from password policies., ``webauthn`` is None where passkeys are not configured: nothing to prune.…

### Community 195 - "split_frames"
Cohesion: 0.33
Nodes (4): Framing, SSLContext, Complete frames in ``raw`` and the incomplete remainder., split_frames()

### Community 196 - "Refused"
Cohesion: 0.67
Nodes (3): HTTPException, Raised by dependencies; FastAPI's default handler renders the uniform refusal., Refused

### Community 197 - "Notes"
Cohesion: 0.10
Nodes (19): _audit(), Note, Notes, notes_router(), create_note(), delete_note(), found(), update_note() (+11 more)

### Community 198 - "_Invalid"
Cohesion: 0.67
Nodes (3): _Invalid, Exception, A policy body refused, with each field at fault and a fixed message.

### Community 199 - "AnchorCheck"
Cohesion: 0.40
Nodes (4): AnchorCheck, _check_anchor(), result(), The outcome for one external anchor. Carries identifiers only, never row…

### Community 200 - "test_audit_chain_migration.py"
Cohesion: 0.60
Nodes (5): _columns(), _constraints(), The audit chain migration: reversible, and refuses rows it cannot chain., test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(), test_head_includes_the_chain_revision()

### Community 201 - "test_lock_live_holds_the_token_until_the_holder_ends"
Cohesion: 0.40
Nodes (5): The token in a sent message's link (the test links end ``?t=<token>``)., A pre-consume decision under lock_live cannot be overtaken by another request., test_lock_live_holds_the_token_until_the_holder_ends(), contender(), holder()

### Community 202 - "round_trip"
Cohesion: 0.47
Nodes (6): provider_login(), AsyncClient, UserFactory, Sign in on the provider's login page; returns the (code, state) it redirects…, round_trip(), test_live_round_trip_and_refusals()

### Community 203 - "test_a_reset_racing_a_registration_ends_consistent"
Cohesion: 0.33
Nodes (5): Any, UUID, Either the key (with fresh codes) survives the reset, or neither does., _state(), test_a_reset_racing_a_registration_ends_consistent()

### Community 204 - "test_client_guide.py"
Cohesion: 0.47
Nodes (4): _contract_routes(), The client-behaviour guide (docs/guide/clients.md) and the contract agree on…, test_every_contract_route_is_linked_from_the_guide(), test_every_route_the_guide_names_is_in_the_contract()

### Community 206 - "make"
Cohesion: 0.40
Nodes (5): make(), fixture, recorder(), registry(), _settings()

### Community 207 - "matching_step"
Cohesion: 0.50
Nodes (4): matching_step(), parse_code(), ``code`` if it is exactly six ASCII digits, otherwise None., The step within the window whose code is ``code``, or None. Every candidate is…

### Community 208 - "test_sso_signs_in_whatever_the_passwords_state"
Cohesion: 0.50
Nodes (4): AsyncClient, parametrize, UserFactory, test_sso_signs_in_whatever_the_passwords_state()

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 211 - "app.py"
Cohesion: 0.06
Nodes (32): collections, The sample console's application: how a product wires warden into FastAPI. Read…, The sample's own routes, built on warden's public Python API. Where warden…, A development clock for the sample: walk password expiry without waiting.…, NoteBody, BaseModel, The sample product's own resource: notes, gated by warden's permissions. It…, A mail sender that keeps messages in memory, so the console can show them.… (+24 more)

### Community 219 - "package"
Cohesion: 0.67
Nodes (3): package(), fixture, Install a throwaway template package under a unique name.

## Knowledge Gaps
- **110 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+105 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1933 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **20 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `ActionRegistry`, `AuditEvent`, `KeyStore`, `reset.py`, `AuditRecorder`, `test_webauthn_mfa.py`, `test_audit_recorder.py`, `SoftwareAuthenticator`, `test_sso_invitations.py`, `PasswordPolicies`, `password_enforcement.py`, `identity/__init__.py`, `test_webauthn_reset.py`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `test_audit_retention.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `warden/cli.py`, `WebAuthn`, `test_identity_prune.py`, `User`, `soft_authenticator.py`, `PolicySettings`, `export_openapi.py`, `typing`, `PasswordStates`, `test_identity_apikeys.py`, `PermissionRegistry`, `httpx`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_admin_routes.py`, `test_identity_throttle.py`, `test_identity_admin_routes.py`, `SecretBox`, `Cluster: test_key_publication.py`, `AuditQuery`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `test_audit_router.py`, `verify_chain`, `password_policy/__init__.py`, `test_passkey_invitation.py`, `test_syslog_routes.py`, `test_identity_lifecycle_routes.py`, `WatchLists`, `PolicyStore`, `test_password_feedback.py`, `test_audit_grants.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `Challenges`, `build_console`, `test_password_set_points.py`, `WebAuthnRefusal`, `test_password_policy_store.py`, `SingleUseTokens`, `BuiltinList`, `test_audit_verify_snapshot.py`, `test_database.py`, `test_identity_capabilities.py`, `PasswordHistory`, `_Section`, `Identity`, `test_syslog_live.py`, `SignInThrottle`, `ConnectionSource`, `.__init__`, `test_lock_live_holds_the_token_until_the_holder_ends`, `round_trip`, `test_a_reset_racing_a_registration_ends_consistent`, `make`?**
  _High betweenness centrality (0.115) - this node is a cross-community bridge._
- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `build_console`, `AuditEvent`, `SourceIp`, `KeyStore`, `Database`, `reset.py`, `test_password_set_points.py`, `PruneReport`, `test_webauthn_mfa.py`, `contract.py`, `console_router`, `build_auth_router`, `SingleUseTokens`, `SoftwareAuthenticator`, `test_sso_invitations.py`, `SingleSignOn`, `password_enforcement.py`, `identity/__init__.py`, `test_identity_capabilities.py`, `test_webauthn_reset.py`, `PasswordHistory`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `test_identity_key_publication.py`, `rules.py`, `current_code`, `test_password_sign_in.py`, `test_sso_break_glass_live.py`, `admin.py`, `warden/cli.py`, `WebAuthn`, `app`, `Mfa`, `test_identity_prune.py`, `User`, `SignInThrottle`, `require_user`, `Mailer`, `PolicySettings`, `export_openapi.py`, `typing`, `.sign_in`, `PermissionRegistry`, `WebAuthnCredential`, `test_identity_apikeys.py`, `httpx`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `sso.py`, `round_trip`, `test_password_admin_routes.py`, `test_identity_throttle.py`, `build_sso_settings_router`, `test_identity_admin_routes.py`, `test_a_reset_racing_a_registration_ends_consistent`, `SecretBox`, `.install`, `test_sso_capabilities.py`, `app.py`, `test_sso_signs_in_whatever_the_passwords_state`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `password_policy/__init__.py`, `test_passkey_invitation.py`, `test_identity_lifecycle_routes.py`, `PolicyStore`, `test_password_feedback.py`, `test_sso_issuer.py`, `Cluster: test_identity_client_address.py`?**
  _High betweenness centrality (0.112) - this node is a cross-community bridge._
- **Why does `AuditEvent` connect `AuditEvent` to `ActionRegistry`, `SourceIp`, `reset.py`, `AuditRecorder`, `contract.py`, `build_password_admin_router`, `test_audit_recorder.py`, `PasswordPolicies`, `SingleSignOn`, `Invitations`, `anchor.py`, `password_enforcement.py`, `identity/__init__.py`, `test_audit_verify_snapshot.py`, `test_audit_chain.py`, `SsoSettingsStore`, `test_audit_retention.py`, `test_syslog_forwarder.py`, `Mfa`, `test_syslog_live.py`, `typing`, `Notes`, `Sessions`, `AuditQuery`, `test_audit_router.py`, `verify_chain`, `password_policy/__init__.py`, `test_syslog_routes.py`, `PolicyStore`, `_purge_prefix`, `test_audit_grants.py`, `test_audit_chain_recorder.py`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Are the 93 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 93 INFERRED edges - model-reasoned connections that need verification._
- **Are the 152 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 152 INFERRED edges - model-reasoned connections that need verification._
- **Are the 134 inferred relationships involving `KeyStore` (e.g. with `build_console()` and `Console`) actually correct?**
  _`KeyStore` has 134 INFERRED edges - model-reasoned connections that need verification._