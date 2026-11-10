# Graph Report - warden  (2026-11-10)

## Corpus Check
- 305 files · ~267,992 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 6149 nodes · 19577 edges · 238 communities (211 shown, 27 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 1851 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `49a65329`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- typing
- test_sso_provider.py
- ApiKeys
- AuditEvent
- KeyStore
- RecordingSender
- audit_rows
- AuditRecorder
- Sample Console Front End
- test_webauthn_mfa.py
- contract.py
- .__init__
- passkey_support.py
- test_audit_recorder.py
- transport.py
- SoftwareAuthenticator
- test_audit_registry.py
- Database
- PasswordPolicies
- SingleSignOn
- Invitations
- WebAuthn Ceremonies
- test_audit_anchor_format.py
- test_console_app.py
- invitations.py
- test_webauthn_reset.py
- test_audit_chain.py
- Identity
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
- race
- test_syslog_transport.py
- webauthn.py
- SyslogForwarder
- _id
- test_config_webauthn.py
- alembic
- warden/cli.py
- WebAuthn
- SyslogSettings
- Cluster: syslog
- SecretBox
- test_identity_prune.py
- FakeIdp
- test_distributions.py
- test_config_fields.py
- AuditRow
- Cluster: soft_authenticator.py
- Mailer
- test_password_recheck.py
- build_reference_app
- totp.py
- password_policy/__init__.py
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- MemorySecrets
- current_revision
- test_sso_live.py
- test_webauthn_live.py
- Sessions
- test_identity_dependencies.py
- test_passkey_registration_link.py
- Outbox
- sso.py
- test_passkey_options_throttle.py
- PruneReport
- roles.py
- client_ip
- test_identity_admin_routes.py
- test_webauthn_migration.py
- console_support.py
- Cluster: test_key_publication.py
- test_sso_capabilities.py
- AuditQuery
- test_openapi_contract.py
- test_identity_migration.py
- test_sso_migration.py
- test_identity_sign_in.py
- Cluster: test_sso_admin_routes.py
- Cluster: Client-behaviour guide
- Cluster: warden design overview
- Cluster: modules()
- certs.py
- test_audit_router.py
- test_audit_verify.py
- main
- attestation.py
- test_db_schema.py
- WatchLists
- test_sso_issuer.py
- Cluster: test_sso_preset_label_only.py
- .register
- test_syslog_sd_id.py
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- test_console_passkeys.py
- test_syslog_routes.py
- Cluster: test_identity_lifecycle_routes.py
- test_password_watch_lists.py
- WardenConfig
- check_dist.py
- Cluster: test_cli.py
- Cluster: Audit hash chain specification
- provider.py
- collector.py
- _purge_prefix
- test_audit_grants.py
- grants.py
- Cluster: with
- parse_config
- test_identity_mfa_mail.py
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- test_packaging.py
- keys_router
- test_lifecycle_migration.py
- test_bump_version.py
- build_console
- test_password_policy_migration.py
- test_console_capabilities.py
- test_identity_roles.py
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- pathlib
- _FieldProblems
- AnchorSigner
- identity/__init__.py
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- Fingerprints
- .configured
- BuiltinList
- .install
- test_no_direct_environment.py
- Cluster: updates
- HttpConfig
- test_a_purge_committing_during_verification_breaks_nothing
- pytest
- test_identity_capabilities.py
- Cluster: test_tls_fail_closed.py
- tests/conftest.py
- PasswordHistory
- Cluster: verify
- ProviderHttp
- console/settings.py
- Cluster: rsyslog
- test_password_hibp.py
- test_identity_throttle.py
- test_licence_audit.py
- ActionRegistry
- lifecycle.py
- audit_router
- subprocess
- Cluster: examples/__init__.py
- test_webauthn_credentials.py
- Cluster: cognisn-warden
- Anchor
- test_cli_audit.py
- test_cli_audit_errors.py
- mail.py
- test_identity_reset.py
- identity
- ceremony.js
- test_audit_export.py
- register_warden_action
- MailMessage
- PolicySettings
- licence_audit.py
- SourceIp
- require_user
- copy
- bump_version.py
- ConnectionSource
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- soft_authenticator.py
- HibpRangeClient
- SignInThrottle
- .sso_settings_router
- Notes
- load_cursor
- ._handle
- notes_router
- NoteScope
- test_console_gaps.py
- test_identity_totp_storage.py
- BaseModel
- neutralise
- _structured_data
- escape_cell
- _Section
- format_expiry
- test_audit_chain_migration.py
- security.py
- AuditSink
- The built-in common-password list
- JwkSet
- .client
- openapi_text
- test_a_key_registered_while_switching_to_sso_only_never_leaves_both
- ._ordered
- .where
- AuditChainConflict
- _Prioritised
- package
- console/__init__.py
- NoteBody
- _LeadershipLost
- _local_hostname
- identity/schema.py
- .cursor
- .base
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
1. `Database` - 554 edges
2. `Identity` - 543 edges
3. `KeyStore` - 165 edges
4. `audit_rows()` - 163 edges
5. `RecordingSender` - 153 edges
6. `ActionRegistry` - 133 edges
7. `AuditRecorder` - 132 edges
8. `FakeIdp` - 118 edges
9. `AuditEvent` - 112 edges
10. `User` - 99 edges

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
- 3-file cycle: `src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/apikeys.py`
- 3-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 5-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`

## Hyperedges (group relationships)
- **Audit tamper-evidence mechanisms** — docs_design_audit_chain_audit_hash_chain, docs_design_audit_chain_retention_checkpoint, docs_design_audit_chain_anchor, docs_design_audit_chain_audit_database_roles, docs_design_overview_tamper_evidence [EXTRACTED 1.00]
- **Release and publication pipeline** — docs_releasing_bump_version, github_workflows_publish, docs_releasing_check_dist, docs_releasing_trusted_publishing, claude_integration_procedure [EXTRACTED 1.00]
- **Tripwire tests guarding architecture rules** — docs_design_overview_single_audit_writer, docs_design_overview_audit_independence, examples_console_readme_public_surface_tripwire, claude_mutation_checked_guards [INFERRED 0.85]

## Communities (238 total, 27 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.17
Nodes (40): passkey_assertion(), passkey_sign_in(), AsyncClient, _admin(), _amr(), _last_sign_in_failure(), _passkey_user(), Any (+32 more)

### Community 1 - "typing"
Cohesion: 0.04
Nodes (107): argon2, argon2_exceptions, asyncio, base64, binascii, collections, collections_abc, contextlib (+99 more)

### Community 2 - "test_sso_provider.py"
Cohesion: 0.11
Nodes (36): jwt, jwt_algorithms, ProviderMetadata, IdTokenValidator, Any, Configuration's algorithms that the provider also advertises., _Drop, ec_key() (+28 more)

### Community 3 - "ApiKeys"
Cohesion: 0.12
Nodes (18): IdentityConfig, ApiKey, ApiKeys, _hash(), NewApiKey, Any, datetime, SourceIp (+10 more)

### Community 4 - "AuditEvent"
Cohesion: 0.04
Nodes (60): AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., Any, AsyncConnection, Record ``event`` and return its row id. With ``conn``, the row is written…, Record ``event`` through the installed recorder. See ``AuditRecorder.record``., record_audit() (+52 more)

### Community 5 - "KeyStore"
Cohesion: 0.05
Nodes (67): Ed25519PrivateKey, KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., _b64url(), _b64url_decode(), key_id_for(), KeyStore, KeyStoreError (+59 more)

### Community 6 - "RecordingSender"
Cohesion: 0.10
Nodes (52): A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, The product's mail sender, recording instead of sending. ``fail`` makes it…, RecordingSender, _accept(), FakePins (+44 more)

### Community 7 - "audit_rows"
Cohesion: 0.13
Nodes (37): audit_rows(), Any, Any, test_without_a_fingerprint_key_recheck_checks_no_one(), _b64(), _parts(), AsyncClient, parametrize (+29 more)

### Community 8 - "AuditRecorder"
Cohesion: 0.11
Nodes (62): AnchorRecord, An anchor written to the trail, and the id of the row that carries it., AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors(), age(), Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then… (+54 more)

### Community 9 - "Sample Console Front End"
Cohesion: 0.11
Nodes (91): apiKeysScreen(), capabilities(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames() (+83 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.12
Nodes (69): _amr(), _app(), _assertion(), _bearer(), _challenge(), http(), _key_sign_in(), _options() (+61 more)

### Community 11 - "contract.py"
Cohesion: 0.07
Nodes (67): _BadRequest, build_admin_router(), APIRouter, Exception, Administration routes. The product mounts them under…, Routes for users, roles, invitations and API keys, each area behind one…, Public sign-in routes. The product mounts them under…, ChallengeBody (+59 more)

### Community 12 - ".__init__"
Cohesion: 0.06
Nodes (29): get_recorder(), Protocol, SecretStore, Protocol, The product's resource-level check, consulted by ``require_permission(...,…, ResourceScopeHook, PolicyError, PolicyStore (+21 more)

### Community 13 - "passkey_support.py"
Cohesion: 0.13
Nodes (26): expire_challenge_of(), give_passkey(), http_client(), passkey_app(), passkey_config(), Any, FastAPI, Helpers shared by the passkey tests (imported as ``passkey_support``). An… (+18 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.14
Nodes (29): Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any (+21 more)

### Community 15 - "transport.py"
Cohesion: 0.07
Nodes (21): DatagramTransport, errno, socket, classify_error(), BaseException, Exception, Protocol, StreamReader (+13 more)

### Community 16 - "SoftwareAuthenticator"
Cohesion: 0.14
Nodes (45): One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, Any, parametrize, UserFactory, UUID, Registering a passkey or security key: the options, the checks and every…, _refused() (+37 more)

### Community 17 - "test_audit_registry.py"
Cohesion: 0.07
Nodes (22): ActionSpec, _check_summary(), A registered action: dotted name, severity and summary template., The one-line summary for ``event``; absent fields render as ``-``., Register a product action. Re-registering an identical spec is a no-op. Actions…, The spec for ``action``; ``KeyError`` if it was never registered., complete(), parametrize (+14 more)

### Community 18 - "Database"
Cohesion: 0.11
Nodes (61): Body, Database, warden's handle on the product's connection pool., Any, test_construction_and_sign_in_write_no_policy(), test_prune_trims_history_and_expired_change_challenges(), accept(), acceptance_rows() (+53 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.07
Nodes (47): PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, Errors raised by password policies and watch lists. Messages carry field names,…, A password policy, or a change to one, was refused., No password policy has that id., The change clashes with the stored state: a stale version, a name or priority…, Delete history beyond the largest count any policy keeps; returns how many. (+39 more)

### Community 20 - "SingleSignOn"
Cohesion: 0.11
Nodes (22): _challenge(), _hash(), _PinRefused, Any, AsyncConnection, Exception, NoReturn, SourceIp (+14 more)

### Community 21 - "Invitations"
Cohesion: 0.06
Nodes (43): Complete, Method, MethodCheck, _Abort, AcceptedInvitation, Invitation, InvitationError, InvitationMismatch (+35 more)

### Community 22 - "WebAuthn Ceremonies"
Cohesion: 0.11
Nodes (25): PublicKeyCredentialDescriptor, Exception, A WebAuthn ceremony or credential change was refused. ``user_id`` and…, Whether the refusal reports a credential that may have been copied., WebAuthnError, _extension_results(), _parse(), Any (+17 more)

### Community 23 - "test_audit_anchor_format.py"
Cohesion: 0.14
Nodes (31): cryptography_hazmat_primitives_asymmetric_ed25519, The anchors in an export from a SIEM, one record per line, numbered from 1. Two…, read_anchors(), _anchor(), _ndjson(), Any, parametrize, Anchors: the signed payload, its domain separation, and reading anchors back… (+23 more)

### Community 24 - "test_console_app.py"
Cohesion: 0.18
Nodes (24): assert_strict_csp(), make_user(), AsyncClient, Response, sign_in(), link_token(), Any, AsyncClient (+16 more)

### Community 25 - "invitations.py"
Cohesion: 0.06
Nodes (48): Invitations: an invited user, staged role grants, and a single-use link.…, PasswordHasher, Argon2id hashing with legacy PBKDF2 verification. The defaults are…, An Argon2id hash of ``password``., Spend the time one Argon2id verification takes, for a user who has no hash.…, _Abort, _Account, PasswordResets (+40 more)

### Community 26 - "test_webauthn_reset.py"
Cohesion: 0.18
Nodes (26): enrol_totp(), Enrol and confirm TOTP for ``user``; returns the secret. Confirmation claims…, _admin(), _bearer(), http(), Any, AsyncClient, fixture (+18 more)

### Community 27 - "test_audit_chain.py"
Cohesion: 0.09
Nodes (39): JsonValue, address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields(), _number() (+31 more)

### Community 28 - "Identity"
Cohesion: 0.06
Nodes (80): Identity, warden's identity subsystem for one deployment., Run identity's background work (the session and password policy listeners) for…, Delete sign-in throttle records whose window has ended., test_running_also_listens_for_password_policy_changes(), test_the_services_are_attributes_built_at_construction(), _app(), _bearer() (+72 more)

### Community 29 - "test_config.py"
Cohesion: 0.07
Nodes (66): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, FakeSecrets, FakeSettings, _load(), _parse(), Any (+58 more)

### Community 30 - "json_response"
Cohesion: 0.10
Nodes (54): json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), capabilities(), list_roles() (+46 more)

### Community 31 - "SsoSettingsStore"
Cohesion: 0.09
Nodes (34): _from_config(), _plain(), Any, AsyncConnection, ValueError, The effective settings, cached for ``max_age`` seconds., The effective settings, read now on ``conn`` (no cache)., Override some fields: validated as a whole, audited, and, when this turns… (+26 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_audit_retention.py"
Cohesion: 0.12
Nodes (41): purge(), Exception, A purge was refused. The message carries row ids only., Delete audit rows older than ``retention_days`` behind a signed checkpoint., RetentionError, Verify the chain, from its first surviving row to ``through_id`` (or the head)., verify_chain(), Any (+33 more)

### Community 34 - "format_message"
Cohesion: 0.18
Nodes (34): AuditRecord, _clip(), format_message(), build(), The RFC 5424 message for ``record``, at most ``settings.max_message_bytes``…, One committed audit row, as the forwarder reads it., The longest prefix of ``value`` whose encoded UTF-8 form fits in ``budget``…, _sd_escape() (+26 more)

### Community 35 - "test_identity_key_publication.py"
Cohesion: 0.29
Nodes (13): PyJWK, _access_token(), _b64(), _decode(), keys_client(), _published_key(), Any, AsyncClient (+5 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.13
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.20
Nodes (39): ForwarderFactory, _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader() (+31 more)

### Community 38 - "rules.py"
Cohesion: 0.05
Nodes (72): _bool(), _classes(), _detail_tokens(), evaluate(), Evaluation, _int(), _local_part(), _longest_run() (+64 more)

### Community 39 - "race"
Cohesion: 0.09
Nodes (52): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), race(), Run ``calls`` as concurrent tasks released together by a barrier. Every task…, _challenge() (+44 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.14
Nodes (35): frame(), open_transport(), Connect to the collector named in ``settings``; ``TransportError`` on failure., Frame ``message`` for a stream transport (RFC 6587)., Authority, A TCP (or, with ``ssl``, TLS) collector that records raw bytes and frames., Stop listening and drop every open connection, as a stopped collector would., StreamCollector (+27 more)

### Community 41 - "webauthn.py"
Cohesion: 0.10
Nodes (27): Passkeys and security keys are not configured for this deployment.…, WebAuthnUnavailable, _inline(), resolve(), json_body(), BaseModel, A new session. Every route that issues one answers with this body., A new session after a forced enrolment, with the recovery codes, shown once. (+19 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.08
Nodes (17): Any, AsyncConnection, Task, Begin competing for the forwarder lock and, once held, forwarding., Stop forwarding, release the lock and close the transport. Idempotent., Switch to new settings; the next send opens a transport with them. Waits for an…, The snapshot plus the stored cursor and the lag behind it. Read from the…, Try for the lock; lead until stopped or the session ends. True if it led. (+9 more)

### Community 43 - "_id"
Cohesion: 0.16
Nodes (35): _api_key(), _assignment(), assign_role(), create_key(), invite(), list_invitations(), list_keys(), list_users() (+27 more)

### Community 44 - "test_config_webauthn.py"
Cohesion: 0.06
Nodes (63): cryptography_hazmat_primitives, cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's… (+55 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (11): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+3 more)

### Community 46 - "warden/cli.py"
Cohesion: 0.07
Nodes (41): sqlalchemy_exc, Register warden's audit actions. Idempotent., register_audit_actions(), AnchorError, ExternalAnchor, Exception, An anchor could not be written. The message carries identifiers only., An anchor found in an export: its line, its own row id when known, and the… (+33 more)

### Community 47 - "WebAuthn"
Cohesion: 0.20
Nodes (35): The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, _enrolled(), Any, parametrize, UserFactory, UUID (+27 more)

### Community 48 - "SyslogSettings"
Cohesion: 0.08
Nodes (34): ForwarderSnapshot, BaseModel, This process's view of the forwarder, without touching the database., Syslog forwarding of committed audit rows (RFC 5424 over UDP, TCP or TLS)., BaseModel, Whether the test message reached the transport, and if not, why (a fixed…, Send one test message over a fresh connection with the forwarder's settings., send_test_message() (+26 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "SecretBox"
Cohesion: 0.06
Nodes (44): SecondFactor, _decode(), _key_id(), Exception, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., A TOTP key is missing or malformed. Names the secret, never its value., Seals and opens small secrets with the current (and, while rotating, previous)… (+36 more)

### Community 51 - "test_identity_prune.py"
Cohesion: 0.18
Nodes (16): _count(), _expire_all(), _fixtures(), Any, MonkeyPatch, UserFactory, Pruning (#134): expired refresh and single-use tokens, MFA challenges, throttle…, Move every row of ``table`` into the past, keeping its own constraints. (+8 more)

### Community 52 - "FakeIdp"
Cohesion: 0.12
Nodes (72): User, FakeIdp, callback(), completion(), handoff(), provider_code(), Any, AsyncClient (+64 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.12
Nodes (35): importlib_util, dist(), _load(), _only(), fixture, ModuleType, MonkeyPatch, parametrize (+27 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.13
Nodes (30): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+22 more)

### Community 55 - "AuditRow"
Cohesion: 0.07
Nodes (33): BreakReason, _b64url(), _b64url_decode(), Checkpoint, HistoricalVerifier, _int(), MalformedCheckpoint, Any (+25 more)

### Community 56 - "Cluster: soft_authenticator.py"
Cohesion: 0.15
Nodes (21): ca(), make_webauthn(), factory(), Any, fixture, Fixtures for the WebAuthn ceremonies: the service, a test CA and user helpers., A relying party that trusts only ``ca``'s attestation root (ruling P3)., rogue_ca() (+13 more)

### Community 57 - "Mailer"
Cohesion: 0.26
Nodes (22): MailConfig, Mail settings. The product implements the sender. Provisional until 0.1.0b1., Mailer, MailKind, StrEnum, Renders warden's messages and hands them to the product's sender., parametrize, Mail: the sender protocol, warden's templates and the product's overrides. No… (+14 more)

### Community 58 - "test_password_recheck.py"
Cohesion: 0.18
Nodes (16): new_totp_key(), A fresh 256-bit key, encoded for the secrets store., _config(), fp_identity(), fixture, Request, Response, Range (+8 more)

### Community 59 - "build_reference_app"
Cohesion: 0.12
Nodes (13): build_reference_app(), contract_version(), _NoDatabase, _product_authorisation(), Any, AsyncConnection, FastAPI, Every warden router, mounted under the default prefixes. (+5 more)

### Community 60 - "totp.py"
Cohesion: 0.12
Nodes (17): hmac, generate_recovery_codes(), generate_secret(), hash_recovery_code(), matching_step(), parse_code(), parse_recovery_code(), provisioning_uri() (+9 more)

### Community 61 - "password_policy/__init__.py"
Cohesion: 0.06
Nodes (53): ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID, Forced-change challenges (ruling PW9). After a correct password and the second…, Use the challenge up; False if another request already did, or it lapsed. (+45 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.14
Nodes (26): ApiKeyError, Exception, An API key change was refused. Messages carry no values., _app(), _bearer(), client(), AsyncClient, FastAPI (+18 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.08
Nodes (21): PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role, fixture, parametrize (+13 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.12
Nodes (25): _address(), Any, Network, _Scope, Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``., The client address, given the peer and every ``X-Forwarded-For`` value in order., ASGI middleware setting ``scope["client"]`` to the resolved client address., resolve_client_ip() (+17 more)

### Community 65 - "MemorySecrets"
Cohesion: 0.17
Nodes (18): config(), make_config(), MemorySecrets, test_keys_may_be_unexpiring_when_no_maximum_is_set(), test_the_configured_prefix_is_used(), _identity(), MemorySecrets, UserFactory (+10 more)

### Community 66 - "current_revision"
Cohesion: 0.09
Nodes (42): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), current_revision(), downgrade(), heads() (+34 more)

### Community 67 - "test_sso_live.py"
Cohesion: 0.15
Nodes (25): os, accept_through_sso(), AsyncClient, parametrize, Live check: an invitation accepted through single sign-on, against the stub…, test_live_invitation_accepted_through_sso_then_sign_in_by_subject(), app(), browser_to_idp() (+17 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.06
Nodes (47): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+39 more)

### Community 69 - "Sessions"
Cohesion: 0.08
Nodes (30): RangeCache, Range answers for one recheck run, by prefix. Never kept beyond the run., PasswordRecheck, UUID, What one run did, in counts., Check every fingerprinted password in use; flag, end sessions and audit on a…, RecheckReport, AccessClaims (+22 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (22): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, Request (+14 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.15
Nodes (40): UUID, Change the sign-in method behind the services' back (no rule applies)., set_method(), set_status(), admin(), config(), _credential_count(), http() (+32 more)

### Community 72 - "Outbox"
Cohesion: 0.12
Nodes (12): Console, The built console: the app and the warden objects behind it., Outbox, Any, A ``MailSender`` holding the last ``limit`` messages, newest last., The kept messages, newest first, as the outbox page shows them., Scope, ASGI middleware adding the policy and related headers to every HTTP answer. (+4 more)

### Community 73 - "sso.py"
Cohesion: 0.12
Nodes (28): fastapi_responses, _body_field(), build_sso_router(), callback(), clear_cookie(), failed(), handoff(), land() (+20 more)

### Community 74 - "test_passkey_options_throttle.py"
Cohesion: 0.23
Nodes (26): assert_refused(), passkey_options(), Response, The uniform refusal, byte for byte., _challenges(), elsewhere(), here(), _passkey_failures() (+18 more)

### Community 75 - "PruneReport"
Cohesion: 0.14
Nodes (10): PruneReport, Identifier, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., How many rows one prune deleted, by kind., scheduled(), loop(), AbstractAsyncContextManager (+2 more)

### Community 76 - "roles.py"
Cohesion: 0.13
Nodes (21): LastAdministratorError, lock_administrators(), Any, AsyncConnection, datetime, Exception, UUID, Roles and permissions (design D5). The product registers its permissions and… (+13 more)

### Community 77 - "client_ip"
Cohesion: 0.11
Nodes (25): client_ip(), Network, Request, SourceIp, The client address, for audit events and the sign-in throttle key. Resolved by…, build_sso_settings_router(), actor_id(), get_settings() (+17 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "console_support.py"
Cohesion: 0.14
Nodes (18): client(), console(), make_console(), build(), Any, AsyncClient, fixture, MemorySecrets (+10 more)

### Community 81 - "Cluster: test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "AuditQuery"
Cohesion: 0.18
Nodes (22): AuditQuery, iter_events(), list_events(), BaseModel, Every matching row in chain (id) order, from one consistent snapshot., A filter over the audit trail. Every given field must match. ``since`` is…, A page of matching rows, newest first, older than ``before_id`` if given., _collect() (+14 more)

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
Cohesion: 0.19
Nodes (23): statistics, _assert_refusal(), Any, AsyncClient, parametrize, Response, UserFactory, Password sign-in over HTTP: outcomes, uniform refusals, timing and rehashing. (+15 more)

### Community 88 - "Cluster: test_sso_admin_routes.py"
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

### Community 92 - "certs.py"
Cohesion: 0.11
Nodes (16): cryptography, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, cryptography_x509_oid, main(), Write a throwaway CA and a TLS keystore for the stub identity provider. python…, Issued, _key_pem() (+8 more)

### Community 93 - "test_audit_router.py"
Cohesion: 0.16
Nodes (21): client(), exporter(), NoKeys, Any, AsyncClient, fixture, parametrize, Audit routers: list, export and verify, behind the product's own authorisation. (+13 more)

### Community 94 - "test_audit_verify.py"
Cohesion: 0.19
Nodes (21): ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id., A forger who recomputes the altered row's hash is caught at the next row., Swap every stored column of two rows except their ids. (+13 more)

### Community 95 - "main"
Cohesion: 0.19
Nodes (23): _dsn(), main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests., _export(), FakeSecrets, FakeSettings, Any, CaptureFixture (+15 more)

### Community 96 - "attestation.py"
Cohesion: 0.13
Nodes (13): AttestationObject, Certificate, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca(), _issued_by() (+5 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.10
Nodes (11): _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range() (+3 more)

### Community 98 - "WatchLists"
Cohesion: 0.12
Nodes (27): ValueError, A watch list, or a change to one, was refused., No watch list has that id., An import was refused or failed; the list is left as it was. ``line`` is the…, WatchListError, WatchListImportError, WatchListNotFound, _check_label() (+19 more)

### Community 99 - "test_sso_issuer.py"
Cohesion: 0.12
Nodes (27): sso_config(), alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer() (+19 more)

### Community 100 - "Cluster: test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (16): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations() (+8 more)

### Community 101 - ".register"
Cohesion: 0.18
Nodes (9): AttestationFormat, FLAG, Any, AuthenticatorData, CollectedClientData, What the authenticator keeps for one credential., Answer ``navigator.credentials.create()`` with ``options`` (the publicKey part)., Answer ``navigator.credentials.get()`` with ``options`` (the publicKey part).… (+1 more)

### Community 102 - "test_syslog_sd_id.py"
Cohesion: 0.11
Nodes (26): format_test_message(), _header_field(), datetime, A NOTICE message with MSGID ``test``, for checking the path to the collector., A header field: PRINTUSASCII only, at most ``limit`` characters, never empty., _timestamp(), Any, model_validator (+18 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.10
Nodes (12): AsyncBaseTransport, _check_secret_name(), _check_url(), PasswordsConfig, field_validator, ValueError, A konfig secret name: letters, digits, '.', '_', '/' and '-'., Validate an absolute http(s) URL; plain http only for loopback hosts. The value… (+4 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.17
Nodes (32): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+24 more)

### Community 106 - "test_console_passkeys.py"
Cohesion: 0.18
Nodes (29): authenticator(), bearer(), A software authenticator that makes passkeys: discoverable, verifying the user., amr(), browser(), link_token(), outbox_message(), passkey_sign_in() (+21 more)

### Community 107 - "test_syslog_routes.py"
Cohesion: 0.23
Nodes (19): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), _audit_rows(), authorise(), _client(), collector() (+11 more)

### Community 108 - "Cluster: test_identity_lifecycle_routes.py"
Cohesion: 0.20
Nodes (18): app(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory, Public lifecycle routes: accept an invitation, request and complete a password… (+10 more)

### Community 109 - "test_password_watch_lists.py"
Cohesion: 0.11
Nodes (36): StrEnum, WatchListKind, builtin(), _lines(), lists(), policies(), Any, fixture (+28 more)

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

### Community 114 - "provider.py"
Cohesion: 0.09
Nodes (23): jwt_exceptions, Exception, Single sign-on refusals. ``SsoError.reason`` is a fixed category, recorded in…, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic(), _https(), JwksCache (+15 more)

### Community 115 - "collector.py"
Cohesion: 0.08
Nodes (13): Framing, ssl, BlackholeCollector, Event, SSLContext, StreamReader, StreamWriter, In-process syslog collectors for tests: stream (TCP or TLS), UDP and a… (+5 more)

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

### Community 121 - "test_identity_mfa_mail.py"
Cohesion: 0.40
Nodes (9): _confirmed_at(), UserFactory, The MFA-enrolled notice: sent once enrolment is confirmed, never at its expense., _signed_in(), test_a_failed_notice_does_not_undo_the_enrolment(), test_a_signed_in_enrolment_sends_the_notice(), test_a_wrong_code_sends_nothing(), test_an_enrolment_under_a_challenge_sends_the_notice() (+1 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.19
Nodes (25): _assert_one_unforked_chain(), _event(), Any, The chained recorder: links, server-side order, the details cap, and…, Poll until backend ``pid`` waits on the chain's advisory lock., Row id order is commit order: the second inserter waits for the first's commit., A server default of REPEATABLE READ must not make warden's own writes conflict., _raw_insert() (+17 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 125 - "test_packaging.py"
Cohesion: 0.20
Nodes (4): importlib, packaging_version, warden: identity and audit for Python web applications. The public API lives in…, Packaging: one version source, typed marker, distribution metadata.

### Community 126 - "keys_router"
Cohesion: 0.25
Nodes (9): _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter, Response (+1 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (14): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+6 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.22
Nodes (14): init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch., test_accepts_release_forms() (+6 more)

### Community 129 - "build_console"
Cohesion: 0.09
Nodes (31): actor(), build_console(), _mount_pages(), FastAPI, Request, A FastAPI dependency for warden's audit, syslog and SSO routes. Those routes…, Build the console over the product's open pool and konfig's secrets store.…, create_administrator() (+23 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "test_console_capabilities.py"
Cohesion: 0.29
Nodes (8): _admin(), _client(), Any, AsyncClient, The sample console asks warden what the deployment can do, and its screens…, test_with_a_sender_everything_that_mails_is_available(), test_without_a_sender_the_capabilities_say_so_and_the_503_stays(), test_without_the_link_setting_only_the_registration_link_is_unavailable()

### Community 132 - "test_identity_roles.py"
Cohesion: 0.25
Nodes (13): _admins(), UserFactory, Role assignments: audited, expiring, and never leaving no administrator., Two administrators demoting each other at once: exactly one demotion succeeds., test_an_administrator_role_cannot_expire(), test_an_expired_assignment_grants_nothing(), test_an_inactive_administrator_does_not_count(), test_assign_and_revoke_are_audited() (+5 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "pathlib"
Cohesion: 0.11
Nodes (17): pathlib, _contract_routes(), The client-behaviour guide (docs/guide/clients.md) and the contract agree on…, test_every_contract_route_is_linked_from_the_guide(), test_every_route_the_guide_names_is_in_the_contract(), README.md is the PyPI project description, so it must render there without…, _targets(), test_every_link_is_absolute() (+9 more)

### Community 136 - "_FieldProblems"
Cohesion: 0.36
Nodes (4): _FieldProblems, model_validator, Self, Cross-field problems, each with a path relative to the failing model.

### Community 137 - "AnchorSigner"
Cohesion: 0.24
Nodes (5): AnchorSigner, _KeyLike, Protocol, What anchoring needs from the key store: ``KeyStore`` fits., _SignatureLike

### Community 138 - "identity/__init__.py"
Cohesion: 0.04
Nodes (66): enum, Creating the first administrator. warden's own CLI cannot do this, because the…, MfaError, Exception, An MFA enrolment change was refused. Messages carry identifiers only., warden's identity subsystem: users, sign-in, sessions, roles and permissions,…, PendingInvitation, Enrolment (+58 more)

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
Cohesion: 0.11
Nodes (33): Collection, P, PolicySource, PW1: the pin, else the highest-priority mapped and declared role, else the…, resolve(), Any, fixture, parametrize (+25 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.09
Nodes (45): IssuedToken, _live_token(), LiveToken, Purpose, Any, AsyncConnection, datetime, StrEnum (+37 more)

### Community 144 - "Fingerprints"
Cohesion: 0.12
Nodes (23): Fingerprints, OpenedFingerprint, password_digest(), UUID, Sealed password fingerprints (ruling PW8). A fingerprint is the SHA-1 of the…, The SHA-1 of ``password`` as UTF-8: the form watch lists and the range API use., A fingerprint as stored: the sealing key's id and the sealed bytes., An opened fingerprint, held in memory only for the length of a check. (+15 more)

### Community 146 - "BuiltinList"
Cohesion: 0.12
Nodes (22): functools, BuiltinList, _bundled(), bundled_list(), _check(), Path, The built-in common-password list (ruling PW12). A read-only list of common…, Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled… (+14 more)

### Community 148 - "test_no_direct_environment.py"
Cohesion: 0.31
Nodes (9): _enclosing_functions(), visit(), _findings(), AST, Tripwire: warden reads configuration only through konfig. No module under…, Each node's innermost enclosing function name, keyed by ``id(node)``., Every forbidden use, and whether it is the named exemption., test_each_exemption_covers_exactly_one_read() (+1 more)

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "HttpConfig"
Cohesion: 0.09
Nodes (19): _base_origin(), _check_origin(), _check_template(), HttpConfig, _is_domain(), Validate a UI link template: a path or URL using exactly ``placeholders``., Where the product exposes warden (design D9). Mount prefixes are where the…, The OIDC redirect URI, derived so it cannot disagree with the mount. (+11 more)

### Community 151 - "test_a_purge_committing_during_verification_breaks_nothing"
Cohesion: 0.18
Nodes (7): _AfterFirstQuery, _HookedPool, MemorySecrets, Any, Delegates to a connection, running ``hook`` once after the checkpoint listing., test_a_purge_committing_during_verification_breaks_nothing(), purge_now()

### Community 152 - "pytest"
Cohesion: 0.10
Nodes (24): httpx, pytest, _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction() (+16 more)

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.18
Nodes (30): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, anonymous(), bearer(), deployment(), make(), member() (+22 more)

### Community 154 - "Cluster: test_tls_fail_closed.py"
Cohesion: 0.46
Nodes (7): expr, _findings(), _is_cert_required(), _is_true(), Tripwire: nothing in warden turns TLS verification off. Fails on any use of…, test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 155 - "tests/conftest.py"
Cohesion: 0.31
Nodes (8): dsn(), migrated_dsn(), pg_admin_url(), pool(), Any, fixture, Shared fixtures. Database tests use a real Postgres through testcontainers., A fresh, empty database for one test.

### Community 156 - "PasswordHistory"
Cohesion: 0.14
Nodes (22): PasswordHistory, Any, AsyncConnection, datetime, UUID, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password., Whether ``password`` matches any of the user's last ``count`` passwords. (+14 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "ProviderHttp"
Cohesion: 0.13
Nodes (20): Discovery, ProviderHttp, AsyncClient, The provider's metadata, cached per issuer., Fetch and check the metadata, bypassing the cache., The one HTTP client single sign-on uses to reach the provider. Redirects are…, http(), idp() (+12 more)

### Community 159 - "console/settings.py"
Cohesion: 0.13
Nodes (23): _init(), Namespace, KonfigSecrets, load_settings(), Any, Path, The sample's configuration: written for a sandbox, read through konfig. A…, Put the secrets warden needs in konfig's store, keeping any already there. The… (+15 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "test_password_hibp.py"
Cohesion: 0.18
Nodes (19): _client(), LogCaptureFixture, parametrize, Request, Response, The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed…, Recorder, test_a_digest_must_be_twenty_bytes() (+11 more)

### Community 162 - "test_identity_throttle.py"
Cohesion: 0.19
Nodes (18): _fail(), UserFactory, Sign-in throttling per (identifier, source address)., Otherwise a password holder gets unlimited challenges, and so unlimited code…, Barriered concurrent attempts: no more than the limit reach password…, An attacker elsewhere cannot lock the user out., Throttling must not reveal whether an account exists., test_a_password_alone_does_not_reset_the_count_when_mfa_follows() (+10 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "ActionRegistry"
Cohesion: 0.13
Nodes (18): ActionRegistry, The set of actions this deployment records., Register the audit actions the syslog routes record. Safe to call more than…, register_syslog_actions(), fixture, registry(), db(), Any (+10 more)

### Community 165 - "lifecycle.py"
Cohesion: 0.16
Nodes (21): detail(), InvitationAcceptBody, no_store(), PasskeyRegistrationBody, PasskeyTokenBody, Any, What the browser passes to `navigator.credentials.create()` or `get()`., A `passkey_only` invitation accepted by registering a passkey; not signed in. (+13 more)

### Community 166 - "audit_router"
Cohesion: 0.11
Nodes (20): AwareDatetime, description, ExportFormat, max_length, Outcome, export(), Any, Record the export, then stream the matching rows in chain order. The export… (+12 more)

### Community 167 - "subprocess"
Cohesion: 0.23
Nodes (10): subprocess, _device_modules_after(), parametrize, Tripwire: warden uses fido2's relying-party side only, never its device code.…, test_importing_warden_loads_no_fido2_device_code(), test_the_probe_sees_device_code_when_it_is_loaded(), Tripwire: importing the key store loads no web stack. Audit verifies…, test_importing_the_key_store_loads_no_web_framework() (+2 more)

### Community 169 - "test_webauthn_credentials.py"
Cohesion: 0.18
Nodes (15): fido2_utils, LogCaptureFixture, parametrize, UserFactory, The credential store (list, rename, remove, count) and challenge pruning., test_an_invalid_nickname_is_refused(), test_another_users_credential_cannot_be_touched(), test_list_count_rename_and_remove() (+7 more)

### Community 171 - "Anchor"
Cohesion: 0.17
Nodes (16): Anchor, _b64url(), _b64url_decode(), _from_ndjson(), _int(), MalformedAnchor, Any, ValueError (+8 more)

### Community 172 - "test_cli_audit.py"
Cohesion: 0.24
Nodes (14): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up() (+6 more)

### Community 173 - "test_cli_audit_errors.py"
Cohesion: 0.19
Nodes (14): _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path, The warden audit CLI without a database: connection failures and grants. (+6 more)

### Community 174 - "mail.py"
Cohesion: 0.16
Nodes (15): html, _check(), _is_control(), _load(), MailDeliveryError, MailError, MailTemplate, _neutralise() (+7 more)

### Community 175 - "test_identity_reset.py"
Cohesion: 0.21
Nodes (17): parametrize, UserFactory, Password reset by emailed link: refusal paths, single use (#127), sessions…, #127 for reset tokens., _reasons(), test_a_failed_send_leaves_no_link(), test_a_link_is_refused_and_spent_if_the_account_changed_since(), test_a_new_request_revokes_earlier_links() (+9 more)

### Community 176 - "identity"
Cohesion: 0.09
Nodes (26): app(), audit_registry(), client(), identity(), keys(), mail(), make_user(), permissions() (+18 more)

### Community 177 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 178 - "test_audit_export.py"
Cohesion: 0.25
Nodes (16): csv, io, csv_lines(), ndjson_lines(), One JSON object per line., A header line, then one CSV record per row., _collect(), Any (+8 more)

### Community 179 - "register_warden_action"
Cohesion: 0.14
Nodes (12): Register one of warden's own actions. Internal to warden; not for products., register_warden_action(), The audit actions identity records, registered when ``Identity`` is constructed., register_actions(), register_actions(), register_actions(), register_actions(), _identity_actions() (+4 more)

### Community 180 - "MailMessage"
Cohesion: 0.14
Nodes (9): MailMessage, MailSender, Protocol, Hand a rendered message to the sender; ``MailDeliveryError`` if it fails., Render and deliver one message; returns what was sent., One rendered message, ready for the product's sender., Implemented by the product. Raise to report that a message was not delivered., FailingSender (+1 more)

### Community 181 - "PolicySettings"
Cohesion: 0.21
Nodes (10): PolicySettings, What an administrator sets on a policy: everything but its id, priority and…, _candidates(), The outcome of ``match``: the first match, and whether the range API could not…, Whether the password is refused: a match, or an unreachable API the policy…, The digests a password may be listed under: as typed and in NFC., The first watch list ``password`` is on under ``policy``; whether the API…, As ``match``, for a fingerprint's digest: every check but terms, which need the… (+2 more)

### Community 182 - "licence_audit.py"
Cohesion: 0.23
Nodes (14): packaging_requirements, packaging_utils, audit(), classify(), data_problems(), installed(), main(), _one() (+6 more)

### Community 183 - "SourceIp"
Cohesion: 0.16
Nodes (14): _address(), passkey_keys(), passkey_options_key(), Any, AsyncConnection, SourceIp, Take one passkey options request; False if the address has used up its window., Forget the pair's attempts; call in the transaction that issues a session. (+6 more)

### Community 184 - "require_user"
Cohesion: 0.19
Nodes (13): bearer_token(), Forbidden, installed_identity(), HTTPException, Request, A dependency requiring ``permission``; with ``scoped``, also the product's…, The signed-in user (by access token or API key), or the uniform 401 refusal., require_permission() (+5 more)

### Community 185 - "copy"
Cohesion: 0.22
Nodes (9): copy, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1() (+1 more)

### Community 186 - "bump_version.py"
Cohesion: 0.27
Nodes (9): _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``., stamp() (+1 more)

### Community 187 - "ConnectionSource"
Cohesion: 0.18
Nodes (8): ConnectionSource, AbstractAsyncContextManager, Any, AsyncConnection, Protocol, Anything that lends async connections; ``psycopg_pool.AsyncConnectionPool``…, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - "soft_authenticator.py"
Cohesion: 0.23
Nodes (11): Algorithm, CoseKey, fido2, fido2_cose, PrivateKey, decode_cose(), _new_key(), other_key() (+3 more)

### Community 191 - "HibpRangeClient"
Cohesion: 0.23
Nodes (7): HibpUnavailable, Exception, The breached-password range service could not be used. Always the same message:…, HibpRangeClient, _parse(), Asks a Pwned Passwords range endpoint whether a SHA-1 digest is known., Whether the service lists ``digest`` with a count above zero.

### Community 192 - "SignInThrottle"
Cohesion: 0.20
Nodes (7): PasswordPruning, Pruner, Protocol, What the pruner needs from password policies., ``webauthn`` is None where passkeys are not configured: nothing to prune.…, Delete records whose window has ended; returns how many., SignInThrottle

### Community 193 - ".sso_settings_router"
Cohesion: 0.18
Nodes (6): APIRouter, Invitation acceptance and password reset; mount under…, Administration routes; mount under ``config.http.admin_prefix``. ``permission``…, The public sign-in routes; mount under ``config.http.auth_prefix``., The single sign-on routes; mount under ``config.http.auth_prefix`` too., Single sign-on administration; mount under ``config.http.admin_prefix``.…

### Community 194 - "Notes"
Cohesion: 0.27
Nodes (4): Note, Notes, Any, The in-memory note store.

### Community 195 - "load_cursor"
Cohesion: 0.33
Nodes (9): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+1 more)

### Community 196 - "._handle"
Cohesion: 0.31
Nodes (3): Any, Request, Response

### Community 197 - "notes_router"
Cohesion: 0.33
Nodes (8): _audit(), notes_router(), create_note(), delete_note(), found(), update_note(), APIRouter, ``/notes`` routes; the sample mounts them under ``/api``.

### Community 198 - "NoteScope"
Cohesion: 0.22
Nodes (7): NoteScope, IPv4Address, IPv6Address, Request, The client address (already resolved by the trusted-proxy middleware), if it is…, The product's resource-scope hook (warden's ``ResourceScopeHook``). warden…, _source()

### Community 199 - "test_console_gaps.py"
Cohesion: 0.22
Nodes (5): Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap()

### Community 200 - "test_identity_totp_storage.py"
Cohesion: 0.36
Nodes (8): MemorySecrets, UserFactory, TOTP secrets are sealed at rest, bound to their user, and survive key rotation., _row(), test_a_secret_copied_to_another_user_does_not_open(), test_identity_refuses_to_start_without_a_totp_key(), test_rotation_keeps_enrolments_working_and_reseals(), test_the_stored_secret_is_sealed()

### Community 201 - "BaseModel"
Cohesion: 0.25
Nodes (8): AuditEventPage, AuditEventView, BrokenLinkView, ChainVerification, BaseModel, The verification report (documentation only)., One audit row, as listed and as exported in NDJSON (documentation only)., A page of events, newest first (documentation only).

### Community 202 - "neutralise"
Cohesion: 0.29
Nodes (7): neutralise(), Match, Replace every control character in ``value`` with a visible ``\\xNN`` escape., _replacement(), test_neutralise_leaves_ordinary_text_alone(), test_neutralise_replaces_c1_controls_and_unicode_line_separators(), test_neutralise_replaces_every_c0_control_and_del()

### Community 203 - "_structured_data"
Cohesion: 0.33
Nodes (6): _from_syslog(), The parameters of each SD-ELEMENT at the start of ``text`` (RFC 5424 section…, A PARAM-VALUE from ``pos`` up to its closing quote, unescaped., _scan_name(), _scan_value(), _structured_data()

### Community 204 - "escape_cell"
Cohesion: 0.40
Nodes (6): _csv_record(), escape_cell(), ``value``, made safe to open in a spreadsheet., parametrize, test_formula_leading_cells_are_escaped(), test_other_cells_are_unchanged()

### Community 205 - "_Section"
Cohesion: 0.33
Nodes (6): AuditConfig, DbConfig, BaseModel, Database settings. At runtime warden uses the product's pool, never this DSN., Audit trail settings., _Section

### Community 206 - "format_expiry"
Cohesion: 0.33
Nodes (5): format_expiry(), datetime, A time for a message: UTC, to the minute, such as ``4 November 2026 at 03:07…, Render one message to ``email``. Datetime values are formatted with…, test_format_expiry_is_utc_to_the_minute()

### Community 207 - "test_audit_chain_migration.py"
Cohesion: 0.60
Nodes (5): _columns(), _constraints(), The audit chain migration: reversible, and refuses rows it cannot chain., test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(), test_head_includes_the_chain_revision()

### Community 208 - "security.py"
Cohesion: 0.50
Nodes (4): content_security_policy(), _origin(), Security headers on every answer: a strict Content Security Policy and friends.…, The policy. ``provider_url`` is the identity provider a sign-in form may go to.

### Community 209 - "AuditSink"
Cohesion: 0.40
Nodes (3): AuditSink, Protocol, An in-process consumer of recorded events. The recorder offers an event only…

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 211 - "JwkSet"
Cohesion: 0.40
Nodes (5): JwkSet, OkpJwk, BaseModel, One published key, an RFC 8037 OKP JSON Web Key (documentation only)., An RFC 7517 JWK Set (documentation only).

### Community 213 - "openapi_text"
Cohesion: 0.50
Nodes (4): main(), openapi_text(), The document as committed: two-space indent, ASCII, one trailing newline., render()

### Community 217 - "AuditChainConflict"
Cohesion: 0.67
Nodes (3): AuditChainConflict, Exception, The row would have forked the chain, so nothing was written. Raised when the…

### Community 219 - "package"
Cohesion: 0.67
Nodes (3): package(), fixture, Install a throwaway template package under a unique name.

## Knowledge Gaps
- **109 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+104 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1782 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **27 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `build_console`, `typing`, `AuditEvent`, `KeyStore`, `RecordingSender`, `audit_rows`, `test_identity_roles.py`, `identity/__init__.py`, `contract.py`, `console_router`, `.__init__`, `passkey_support.py`, `SingleUseTokens`, `test_webauthn_mfa.py`, `SoftwareAuthenticator`, `Database`, `.install`, `SingleSignOn`, `pytest`, `invitations.py`, `test_identity_capabilities.py`, `test_webauthn_reset.py`, `json_response`, `SsoSettingsStore`, `test_identity_throttle.py`, `test_identity_key_publication.py`, `lifecycle.py`, `race`, `webauthn.py`, `mail.py`, `test_identity_reset.py`, `identity`, `WebAuthn`, `SecretBox`, `test_identity_prune.py`, `MailMessage`, `FakeIdp`, `require_user`, `Mailer`, `test_password_recheck.py`, `build_reference_app`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `SignInThrottle`, `.sso_settings_router`, `MemorySecrets`, `test_sso_live.py`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_identity_totp_storage.py`, `sso.py`, `test_passkey_options_throttle.py`, `PruneReport`, `roles.py`, `client_ip`, `test_identity_admin_routes.py`, `test_sso_capabilities.py`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`, `test_identity_sign_in.py`, `Cluster: test_sso_admin_routes.py`, `test_sso_issuer.py`, `test_passkey_invitation.py`, `Cluster: test_identity_lifecycle_routes.py`, `WardenConfig`, `parse_config`, `test_identity_mfa_mail.py`, `Cluster: test_identity_client_address.py`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `typing`, `ApiKeys`, `KeyStore`, `RecordingSender`, `audit_rows`, `AuditRecorder`, `test_webauthn_mfa.py`, `.__init__`, `passkey_support.py`, `test_audit_recorder.py`, `SoftwareAuthenticator`, `PasswordPolicies`, `invitations.py`, `test_webauthn_reset.py`, `Identity`, `SsoSettingsStore`, `test_audit_retention.py`, `test_syslog_forwarder.py`, `race`, `SyslogForwarder`, `warden/cli.py`, `WebAuthn`, `SyslogSettings`, `SecretBox`, `test_identity_prune.py`, `FakeIdp`, `Cluster: soft_authenticator.py`, `test_password_recheck.py`, `build_reference_app`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `MemorySecrets`, `test_sso_live.py`, `test_webauthn_live.py`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_passkey_options_throttle.py`, `roles.py`, `test_identity_admin_routes.py`, `Cluster: test_key_publication.py`, `AuditQuery`, `test_identity_sign_in.py`, `Cluster: test_sso_admin_routes.py`, `test_audit_router.py`, `test_audit_verify.py`, `attestation.py`, `test_sso_issuer.py`, `test_passkey_invitation.py`, `test_syslog_routes.py`, `Cluster: test_identity_lifecycle_routes.py`, `test_password_watch_lists.py`, `WardenConfig`, `test_audit_grants.py`, `parse_config`, `test_identity_mfa_mail.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `build_console`, `test_identity_roles.py`, `identity/__init__.py`, `test_password_policy_store.py`, `SingleUseTokens`, `test_a_purge_committing_during_verification_breaks_nothing`, `pytest`, `test_identity_capabilities.py`, `PasswordHistory`, `test_identity_throttle.py`, `ActionRegistry`, `test_webauthn_credentials.py`, `test_identity_reset.py`, `identity`, `ConnectionSource`, `HibpRangeClient`, `SignInThrottle`, `test_identity_totp_storage.py`, `AuditSink`?**
  _High betweenness centrality (0.096) - this node is a cross-community bridge._
- **Why does `WardenConfig` connect `WardenConfig` to `build_console`, `typing`, `_FieldProblems`, `identity/__init__.py`, `.__init__`, `passkey_support.py`, `Database`, `SingleSignOn`, `Invitations`, `pytest`, `invitations.py`, `test_identity_capabilities.py`, `Identity`, `test_config.py`, `SsoSettingsStore`, `test_config_webauthn.py`, `warden/cli.py`, `WebAuthn`, `identity`, `FakeIdp`, `test_config_fields.py`, `Cluster: soft_authenticator.py`, `test_password_recheck.py`, `build_reference_app`, `PermissionRegistry`, `MemorySecrets`, `test_sso_live.py`, `test_webauthn_live.py`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_identity_totp_storage.py`, `_Section`, `test_sso_capabilities.py`, `test_identity_sign_in.py`, `Cluster: test_sso_admin_routes.py`, `main`, `attestation.py`, `test_sso_issuer.py`, `test_passkey_invitation.py`, `parse_config`, `Cluster: test_identity_client_address.py`?**
  _High betweenness centrality (0.020) - this node is a cross-community bridge._
- **Are the 93 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 93 INFERRED edges - model-reasoned connections that need verification._
- **Are the 47 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 47 INFERRED edges - model-reasoned connections that need verification._
- **Are the 127 inferred relationships involving `KeyStore` (e.g. with `build_console()` and `Console`) actually correct?**
  _`KeyStore` has 127 INFERRED edges - model-reasoned connections that need verification._
- **What connects `STATUSES`, `METHODS`, `POLICY_FIELDS` to the rest of the system?**
  _109 weakly-connected nodes found - possible documentation gaps or missing edges._