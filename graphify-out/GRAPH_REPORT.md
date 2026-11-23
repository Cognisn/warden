# Graph Report - warden  (2026-11-23)

## Corpus Check
- 339 files · ~359,151 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 7238 nodes · 23719 edges · 246 communities (224 shown, 22 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2154 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `32381263`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- SyslogSettings
- FakeIdp
- AuditEvent
- UUID
- KeyStore
- RecordingSender
- PasswordResets
- AuditRecorder
- h
- test_webauthn_mfa.py
- contract.py
- password_admin.py
- sso_settings.py
- test_audit_recorder.py
- test_webauthn_reset.py
- SoftwareAuthenticator
- test_console_password_policy.py
- Database
- PasswordPolicies
- SingleSignOn
- Invitations
- WebAuthnError
- test_audit_anchor_format.py
- PasswordEnforcement
- UserError
- test_config_webauthn.py
- test_audit_chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- SsoSettingsStore
- CI Workflows
- test_console_browser.py
- format_message
- client_ip
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
- test_identity_policy.py
- WebAuthn
- test_audit_retention.py
- Cluster: syslog
- Mfa
- test_identity_prune.py
- User
- test_distributions.py
- test_config_fields.py
- warden/cli.py
- soft_authenticator.py
- mail.py
- test_console_passkeys.py
- export_openapi.py
- typing
- password_policy/__init__.py
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- audit_rows
- current_revision
- identity_support.py
- webauthn_live_support.py
- PolicyStore
- test_identity_dependencies.py
- test_passkey_registration_link.py
- Anchor
- build_console
- pathlib
- test_password_admin_routes.py
- PolicySettings
- SignInMethods
- test_identity_admin_routes.py
- test_webauthn_migration.py
- SecretBox
- test_key_publication.py
- test_sso_capabilities.py
- json
- test_openapi_contract.py
- test_identity_migration.py
- test_sso_migration.py
- test_identity_sign_in.py
- test_sso_admin_routes.py
- Cluster: Client-behaviour guide
- Cluster: warden design overview
- modules
- webauthn/service.py
- webauthn/challenges.py
- verify_chain
- main
- attestation.py
- test_db_schema.py
- identity/__init__.py
- test_sign_in_methods_sso.py
- test_sso_preset_label_only.py
- TokenPair
- Roles
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- bearer
- test_audit_source_ip_tripwire.py
- test_identity_lifecycle_routes.py
- WatchLists
- provider.py
- check_dist.py
- test_cli.py
- Cluster: Audit hash chain specification
- test_sso_source_ip.py
- collector.py
- identity/conftest.py
- test_audit_grants.py
- grants.py
- Cluster: with
- parse_config
- test_sso_issuer.py
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- test_webauthn_credentials.py
- assert_refused
- test_lifecycle_migration.py
- test_bump_version.py
- Sessions
- test_password_policy_migration.py
- test_password_set_points.py
- MemorySecrets
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- passkey_support.py
- certs.py
- SignInMethodChangeRefused
- require_permission
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- test_password_cli.py
- well_formed
- test_webauthn_live.py
- test_console_capabilities.py
- test_no_direct_environment.py
- Cluster: updates
- LiveBrowser
- test_a_purge_committing_during_verification_breaks_nothing
- test_audit_source_ip_routes.py
- test_identity_capabilities.py
- SourceIp
- ceremony.js
- PasswordHistory
- Cluster: verify
- test_sign_in_methods_migration.py
- console/settings.py
- Cluster: rsyslog
- HibpRangeClient
- Identity
- test_licence_audit.py
- test_console_gaps.py
- ApiKeys
- test_syslog_routes.py
- test_identity_throttle.py
- Cluster: examples/__init__.py
- AcceptedInvitation
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- test_cli_audit.py
- test_cli_audit_errors.py
- Principal
- BuiltinList
- test_config_passwords.py
- passkey_config
- test_console_source_ip.py
- canonical_json
- test_sign_in_methods_passkey.py
- StreamCollector
- licence_audit.py
- SignInThrottle
- test_identity_key_publication.py
- copy
- .finish_webauthn_registration
- ConnectionSource
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- _purge_prefix
- _LazySecrets
- race
- test_password_builtin.py
- SignInMethod
- .sso_settings_router
- SignInSettings
- Notes
- test_dependabot.py
- test_packaging.py
- AnchorSigner
- pytest
- SecondFactorKind
- _structured_data
- keys_router
- verify.py
- BlackholeCollector
- .finish
- test_database.py
- ActionRegistry
- The built-in common-password list
- FakeSettings
- test_a_key_registered_while_switching_to_sso_only_never_leaves_both
- _Abort
- test_tls_fail_closed.py
- _Prioritised
- test_readme.py
- PasskeyLinkRefused
- test_client_guide.py
- .record
- console/__init__.py
- _Abort
- FakeSecrets
- neutralise
- frame
- PolicyError
- .send_passkey_registration
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
- .verify_access_token
- Refused
- .__init__
- .name
- .loose_text
- .see
- package
- .use_sign_in_methods

## God Nodes (most connected - your core abstractions)
1. `Identity` - 687 edges
2. `Database` - 673 edges
3. `audit_rows()` - 222 edges
4. `RecordingSender` - 198 edges
5. `KeyStore` - 175 edges
6. `ActionRegistry` - 138 edges
7. `FakeIdp` - 135 edges
8. `AuditRecorder` - 134 edges
9. `AuditEvent` - 126 edges
10. `User` - 117 edges

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

## Communities (246 total, 22 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.14
Nodes (50): give_passkey(), passkey_assertion(), passkey_sign_in(), Register a credential for an active user straight through the ceremony., set_status(), other_key(), A key no credential holds, for signatures that must not verify., _admin() (+42 more)

### Community 1 - "SyslogSettings"
Cohesion: 0.03
Nodes (91): DatagramTransport, errno, pydantic, socket, format_test_message(), _header_field(), datetime, Match (+83 more)

### Community 2 - "FakeIdp"
Cohesion: 0.06
Nodes (66): jwt_algorithms, Discovery, JwksCache, ProviderHttp, ProviderMetadata, AsyncClient, The provider's metadata, cached per issuer., Fetch and check the metadata, bypassing the cache. (+58 more)

### Community 3 - "AuditEvent"
Cohesion: 0.05
Nodes (35): AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., ActionSpec, _check_summary(), A registered action: dotted name, severity and summary template., The one-line summary for ``event``; absent fields render as ``-``., AuditSink (+27 more)

### Community 4 - "UUID"
Cohesion: 0.12
Nodes (14): _Account, Any, AsyncConnection, UUID, Why this user may not register a passkey from a link now, or None., Set or clear a key's nickname; None if the user holds no such key. Raises…, Remove one of the signed-in user's keys; False if they hold no such key.…, A user's own setting, the method in force, and any pending change. (+6 more)

### Community 5 - "KeyStore"
Cohesion: 0.05
Nodes (67): Ed25519PrivateKey, KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., _b64url(), _b64url_decode(), key_id_for(), KeyStore, KeyStoreError (+59 more)

### Community 6 - "RecordingSender"
Cohesion: 0.07
Nodes (74): A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, The product's mail sender, recording instead of sending. ``fail`` makes it…, RecordingSender, _accept(), FakePins (+66 more)

### Community 7 - "PasswordResets"
Cohesion: 0.18
Nodes (16): _Account, _Checked, PasswordResets, Any, AsyncConnection, NoReturn, SourceIp, UUID (+8 more)

### Community 8 - "AuditRecorder"
Cohesion: 0.11
Nodes (62): AnchorRecord, An anchor written to the trail, and the id of the row that carries it., AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors(), age(), Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then… (+54 more)

### Community 9 - "h"
Cohesion: 0.07
Nodes (144): apiKeysScreen(), capabilities(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames() (+136 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.11
Nodes (71): enrol_totp(), Enrol and confirm TOTP for ``user``; returns the secret. Confirmation claims…, _amr(), _app(), _assertion(), _bearer(), _challenge(), http() (+63 more)

### Community 11 - "contract.py"
Cohesion: 0.04
Nodes (101): PasswordRejected, A new password was refused; ``failures`` names every reason. The message lists…, Public sign-in routes. The product mounts them under…, ChallengeBody, ChangePasswordBody, CodeBody, _Doc, EnrolmentBody (+93 more)

### Community 12 - "password_admin.py"
Cohesion: 0.06
Nodes (99): AffectedUsersProposalBody, BuiltinListBody, PasswordPolicyCreateBody, PasswordPolicyOrderBody, PasswordPolicyPinBody, PasswordPolicyPriorityBody, PasswordPolicyRoleBody, PasswordPolicyUpdateBody (+91 more)

### Community 13 - "sso_settings.py"
Cohesion: 0.09
Nodes (35): Any, The kept messages, newest first, as the outbox page shows them., detail(), _inline(), resolve(), json_body(), no_store(), Any (+27 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.14
Nodes (29): Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any (+21 more)

### Community 15 - "test_webauthn_reset.py"
Cohesion: 0.05
Nodes (60): _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``., stamp() (+52 more)

### Community 16 - "SoftwareAuthenticator"
Cohesion: 0.15
Nodes (44): One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, Any, parametrize, UserFactory, UUID, Registering a passkey or security key: the options, the checks and every…, _refused() (+36 more)

### Community 17 - "test_console_password_policy.py"
Cohesion: 0.10
Nodes (20): assert_strict_csp(), Response, _passwords_source(), The sample console's password policy support: routes, the development clock,…, Every (method, path) a screen sends to a warden router, path parameters as…, test_an_imported_list_explains_the_file_the_threshold_and_the_command_line(), test_the_built_in_list_is_said_to_need_no_loading_on_both_screens(), test_the_console_settings_carry_the_range_api_and_built_in_list_facts() (+12 more)

### Community 18 - "Database"
Cohesion: 0.12
Nodes (62): Body, functools, Database, warden's handle on the product's connection pool., Any, test_construction_writes_nothing_and_the_seeded_default_refuses_a_common_password(), test_prune_trims_history_and_expired_change_challenges(), accept() (+54 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.07
Nodes (48): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, A password policy, or a change to one, was refused. (+40 more)

### Community 20 - "SingleSignOn"
Cohesion: 0.11
Nodes (24): _challenge(), _hash(), _method_refusal(), _PinRefused, Any, AsyncConnection, Exception, NoReturn (+16 more)

### Community 21 - "Invitations"
Cohesion: 0.10
Nodes (27): Complete, Method, MethodCheck, Invitation, InvitationError, InvitationMismatch, Invitations, _Invitee (+19 more)

### Community 22 - "WebAuthnError"
Cohesion: 0.11
Nodes (27): PublicKeyCredentialDescriptor, Exception, A WebAuthn ceremony or credential change was refused. ``user_id`` and…, Whether the refusal reports a credential that may have been copied., WebAuthnError, _extension_results(), _parse(), Any (+19 more)

### Community 23 - "test_audit_anchor_format.py"
Cohesion: 0.16
Nodes (27): cryptography_hazmat_primitives_asymmetric_ed25519, The anchors in an export from a SIEM, one record per line, numbered from 1. Two…, read_anchors(), _anchor(), _ndjson(), Any, parametrize, Anchors: the signed payload, its domain separation, and reading anchors back… (+19 more)

### Community 24 - "PasswordEnforcement"
Cohesion: 0.06
Nodes (39): SetPlace, AcceptedPassword, _match_details(), PasswordAdvice, PasswordEnforcement, PasswordFailure, PendingChange, Any (+31 more)

### Community 25 - "UserError"
Cohesion: 0.12
Nodes (22): check_email(), Any, AsyncConnection, Composable, datetime, Exception, SourceIp, UUID (+14 more)

### Community 26 - "test_config_webauthn.py"
Cohesion: 0.11
Nodes (36): _certificate(), _parse(), Any, parametrize, Start-up validation of the WebAuthn settings (rulings P2, P3 and P7 of 6…, _refused(), _Secrets, test_a_malformed_passkey_registration_link_is_refused() (+28 more)

### Community 27 - "test_audit_chain.py"
Cohesion: 0.14
Nodes (22): address_text(), ChainRow, _fields(), IPv4Address, IPv6Address, The address as hashed: dotted quad, or eight four-digit lower-case hex groups.…, The SHA-256 row hash of ``row``., Every stored column of one audit row, as the hash covers it. (+14 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.09
Nodes (47): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+39 more)

### Community 29 - "test_config.py"
Cohesion: 0.14
Nodes (44): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, _load(), parametrize, Configuration contract: one typed object, validated at start-up., _sso_tree(), test_audit_only_deployment_needs_no_link_templates() (+36 more)

### Community 30 - "json_response"
Cohesion: 0.08
Nodes (79): json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), build_auth_router(), begin_enrolment() (+71 more)

### Community 31 - "SsoSettingsStore"
Cohesion: 0.07
Nodes (45): _from_config(), _plain(), Any, AsyncConnection, SourceIp, UUID, ValueError, Whether single sign-on works: enabled, with an issuer and a client id. (+37 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_console_browser.py"
Cohesion: 0.13
Nodes (20): code_for(), ConsoleBrowser, enrol_authenticator(), forced(), open_console(), plain(), Any, fixture (+12 more)

### Community 34 - "format_message"
Cohesion: 0.16
Nodes (36): AuditRecord, _clip(), format_message(), build(), The RFC 5424 message for ``record``, at most ``settings.max_message_bytes``…, One committed audit row, as the forwarder reads it., The longest prefix of ``value`` whose encoded UTF-8 form fits in ``budget``…, _sd_escape() (+28 more)

### Community 35 - "client_ip"
Cohesion: 0.14
Nodes (25): fastapi_responses, client_ip(), Network, Request, SourceIp, The client address, for audit events and the sign-in throttle key. Resolved by…, _body_field(), build_sso_router() (+17 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.13
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.12
Nodes (49): ForwarderFactory, dsn(), migrated_dsn(), pg_admin_url(), pool(), Any, fixture, Shared fixtures. Database tests use a real Postgres through testcontainers. (+41 more)

### Community 38 - "rules.py"
Cohesion: 0.05
Nodes (80): Each rule's result and any watch-list match. Never history; stores and audits…, _bool(), _classes(), _detail_tokens(), evaluate(), _int(), _local_part(), _longest_run() (+72 more)

### Community 39 - "current_code"
Cohesion: 0.09
Nodes (55): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), _challenge(), _enrolled(), _fresh_code() (+47 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.21
Nodes (27): open_transport(), Connect to the collector named in ``settings``; ``TransportError`` on failure., Authority, authority(), _hostile_record(), Any, fixture, parametrize (+19 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.06
Nodes (94): failing_transport(), handler(), listing_transport(), MockTransport, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., bearer(), Clock (+86 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.06
Nodes (34): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+26 more)

### Community 43 - "admin.py"
Cohesion: 0.09
Nodes (63): _api_key(), _assignment(), _BadRequest, build_admin_router(), assign_role(), capabilities(), create_key(), invite() (+55 more)

### Community 44 - "test_sso_sealing.py"
Cohesion: 0.15
Nodes (26): cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's…, The token sealed in ``sealed``, or None if it does not open to one. (+18 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (12): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+4 more)

### Community 46 - "test_identity_policy.py"
Cohesion: 0.24
Nodes (12): parametrize, Session policy: defaults from configuration, audited changes, cross-replica…, The product wraps its app's lifespan in ``identity.running()``., Replica B caches the policy for an hour, yet sees A's change at once via NOTIFY., _store(), test_a_change_reaches_another_replica_promptly(), test_defaults_come_from_configuration(), test_inconsistent_updates_are_refused() (+4 more)

### Community 47 - "WebAuthn"
Cohesion: 0.18
Nodes (38): The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, _enrolled(), Any, parametrize, UserFactory, UUID (+30 more)

### Community 48 - "test_audit_retention.py"
Cohesion: 0.12
Nodes (39): purge(), Exception, A purge was refused. The message carries row ids only., Delete audit rows older than ``retention_days`` behind a signed checkpoint., RetentionError, Any, Connection, Recompute every hash and link from the first surviving row's ``prev_hash``. (+31 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Mfa"
Cohesion: 0.11
Nodes (23): SecondFactor, Challenge, _hash_token(), Mfa, Any, AsyncConnection, ChallengePurpose, SourceIp (+15 more)

### Community 51 - "test_identity_prune.py"
Cohesion: 0.18
Nodes (16): _count(), _expire_all(), _fixtures(), Any, MonkeyPatch, UserFactory, Pruning (#134): expired refresh and single-use tokens, MFA challenges, throttle…, Move every row of ``table`` into the past, keeping its own constraints. (+8 more)

### Community 52 - "User"
Cohesion: 0.10
Nodes (75): User, callback(), completion(), handoff(), provider_code(), Any, AsyncClient, Response (+67 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.13
Nodes (33): dist(), _load(), _only(), fixture, ModuleType, MonkeyPatch, parametrize, Path (+25 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.14
Nodes (29): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+21 more)

### Community 55 - "warden/cli.py"
Cohesion: 0.07
Nodes (56): BinaryIO, sqlalchemy_exc, Register warden's audit actions. Idempotent., register_audit_actions(), AnchorError, Exception, An anchor could not be written. The message carries identifiers only., PurgeResult (+48 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.07
Nodes (39): Algorithm, AttestationFormat, CoseKey, fido2, fido2_cose, FLAG, PrivateKey, ca() (+31 more)

### Community 57 - "mail.py"
Cohesion: 0.07
Nodes (52): html, MailConfig, Mail settings. The product implements the sender., _check(), format_expiry(), _is_control(), _load(), MailDeliveryError (+44 more)

### Community 58 - "test_console_passkeys.py"
Cohesion: 0.18
Nodes (28): authenticator(), A software authenticator that makes passkeys: discoverable, verifying the user., amr(), browser(), link_token(), outbox_message(), passkey_sign_in(), Any (+20 more)

### Community 59 - "export_openapi.py"
Cohesion: 0.09
Nodes (24): build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), Any, AsyncConnection (+16 more)

### Community 60 - "typing"
Cohesion: 0.05
Nodes (83): collections_abc, contextlib, dataclasses, decimal, enum, NoteBody, BaseModel, The sample product's own resource: notes, gated by warden's permissions. It… (+75 more)

### Community 61 - "password_policy/__init__.py"
Cohesion: 0.04
Nodes (72): ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID, Forced-change challenges (ruling PW9). After a correct password and the second…, Use the challenge up; False if another request already did, or it lapsed. (+64 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.12
Nodes (30): ApiKeyError, Exception, An API key change was refused. Messages carry no values., make_config(), Any, _app(), _bearer(), client() (+22 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.08
Nodes (26): permissions(), The product's permission registry and role sets., PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role (+18 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.08
Nodes (32): Scope, ASGI middleware adding the policy and related headers to every HTTP answer., SecurityHeaders, with_headers(), Receive, Send, _address(), Any (+24 more)

### Community 65 - "audit_rows"
Cohesion: 0.10
Nodes (39): audit_rows(), test_a_reset_of_an_unknown_user_is_refused(), admin(), app(), assert_consistent(), has_password(), mailless(), Any (+31 more)

### Community 66 - "current_revision"
Cohesion: 0.09
Nodes (38): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), current_revision(), downgrade(), heads() (+30 more)

### Community 67 - "identity_support.py"
Cohesion: 0.07
Nodes (50): httpx, os, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, Helpers shared by identity tests (imported as ``identity_support``)., sso_config(), app(), config(), Any (+42 more)

### Community 68 - "webauthn_live_support.py"
Cohesion: 0.10
Nodes (19): admin(), browser(), config(), fixture, The administrator's own client, signed in over the same live server., server(), _b64(), _b64url() (+11 more)

### Community 69 - "PolicyStore"
Cohesion: 0.15
Nodes (12): PolicyStore, Any, AsyncConnection, Event, SourceIp, The effective session policy, cached per replica and invalidated over NOTIFY., Whether ``listen()`` currently holds a LISTEN on the policy channel., Forget the cached policy; the next ``current()`` re-reads it. (+4 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.13
Nodes (21): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, UserFactory (+13 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.20
Nodes (34): admin(), config(), _credential_count(), http(), _identity(), _link(), _options(), Any (+26 more)

### Community 72 - "Anchor"
Cohesion: 0.14
Nodes (20): Anchor, _b64url(), _b64url_decode(), _from_ndjson(), _int(), MalformedAnchor, Any, IPv4Address (+12 more)

### Community 73 - "build_console"
Cohesion: 0.07
Nodes (34): actor(), build_console(), Console, _mount_pages(), FastAPI, Request, Build the console over the product's open pool and konfig's secrets store.…, The built console: the app and the warden objects behind it. (+26 more)

### Community 74 - "pathlib"
Cohesion: 0.13
Nodes (20): pathlib, sys, client(), console(), make_console(), build(), Any, AsyncClient (+12 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.07
Nodes (68): bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests., app(), client() (+60 more)

### Community 76 - "PolicySettings"
Cohesion: 0.10
Nodes (27): RangeCache, Range answers for one recheck run, by prefix. Never kept beyond the run., PolicySettings, What an administrator sets on a policy: everything but its id, priority and…, The outcome of ``match``: the first match, and whether the range API could not…, Whether the password is refused: a match, or an unreachable API the policy…, The first watch list ``password`` is on under ``policy``; whether the API…, As ``match``, for a fingerprint's digest: every check but terms, which need the… (+19 more)

### Community 77 - "SignInMethods"
Cohesion: 0.18
Nodes (18): _LinkDue, _Outcome, Any, AsyncConnection, SourceIp, UUID, Send a link after its change committed; a failure is audited, never raised., The sign-in settings store and every change of a user's sign-in method. (+10 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "SecretBox"
Cohesion: 0.07
Nodes (34): _decode(), _key_id(), Exception, Protocol, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., A TOTP key is missing or malformed. Names the secret, never its value., Seals and opens small secrets with the current (and, while rotating, previous)… (+26 more)

### Community 81 - "test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "json"
Cohesion: 0.04
Nodes (104): AwareDatetime, csv, description, ExportFormat, io, json, max_length, datetime (+96 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.19
Nodes (15): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+7 more)

### Community 86 - "test_sso_migration.py"
Cohesion: 0.27
Nodes (10): Connection, parametrize, UUID, Single sign-on's migration: its tables, their constraints, and a tested…, _tables(), test_a_subject_is_pinned_to_one_user(), test_a_user_has_at_most_one_pin(), test_constraints() (+2 more)

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

### Community 91 - "modules"
Cohesion: 0.19
Nodes (20): Pattern, _docstring_nodes(), identifiers(), module_name(), modules(), AST, Path, Helpers for tripwires that read warden's own source. (+12 more)

### Community 92 - "webauthn/service.py"
Cohesion: 0.10
Nodes (30): StrEnum, UUID, Refusals from the WebAuthn ceremonies and the credential store. A refusal names…, Why a ceremony, or a change to a credential, was refused., WebAuthnRefusal, Passkeys and security keys (WebAuthn): the ceremonies and the credential store.…, StrEnum, The WebAuthn ceremonies: registering and signing in with passkeys and security… (+22 more)

### Community 93 - "webauthn/challenges.py"
Cohesion: 0.19
Nodes (13): Ceremony, Challenges, ConsumedChallenge, _hash(), IssuedChallenge, Any, AsyncConnection, StrEnum (+5 more)

### Community 94 - "verify_chain"
Cohesion: 0.19
Nodes (23): Verify the chain, from its first surviving row to ``through_id`` (or the head)., verify_chain(), ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id. (+15 more)

### Community 95 - "main"
Cohesion: 0.20
Nodes (22): main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests.…, _export(), FakeSecrets, FakeSettings, Any, CaptureFixture, fixture (+14 more)

### Community 96 - "attestation.py"
Cohesion: 0.13
Nodes (13): AttestationObject, Certificate, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca(), _issued_by() (+5 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.10
Nodes (11): _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range() (+3 more)

### Community 98 - "identity/__init__.py"
Cohesion: 0.03
Nodes (100): argon2, argon2_exceptions, asyncio, base64, binascii, cryptography_exceptions, The sample console's application: how a product wires warden into FastAPI. Read…, The sample's own routes, built on warden's public Python API. Where warden… (+92 more)

### Community 99 - "test_sign_in_methods_sso.py"
Cohesion: 0.13
Nodes (32): add_key(), app(), config(), enabled(), has_password(), idp(), keys_of(), live_sessions() (+24 more)

### Community 100 - "test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (16): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations() (+8 more)

### Community 101 - "TokenPair"
Cohesion: 0.12
Nodes (22): change_body(), Any, The signed-in response body, shared by every route that issues a session.…, The body for a newly issued token pair; ``extra`` fields follow the fixed ones.…, The forced-change answer (ruling PW9): no session, a challenge and the reason., The session, or the forced change a password sign-in must make first., session_body(), token_body() (+14 more)

### Community 102 - "Roles"
Cohesion: 0.12
Nodes (21): LastAdministratorError, lock_administrators(), Any, AsyncConnection, datetime, Exception, SourceIp, UUID (+13 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.05
Nodes (30): _base_origin(), _check_origin(), _check_secret_name(), _check_template(), _check_url(), _FieldProblems, HttpConfig, _is_domain() (+22 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (30): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+22 more)

### Community 106 - "bearer"
Cohesion: 0.14
Nodes (42): bearer(), make_user(), AsyncClient, sign_in(), link_token(), Any, AsyncClient, Path (+34 more)

### Community 107 - "test_audit_source_ip_tripwire.py"
Cohesion: 0.19
Nodes (16): collections, _constants(), _is_warden(), _missing(), _owner(), expr, Tripwire: every warden audit event carries the client address, unless it has no…, The class and method, or the function, a call sits in (nested routes keep their… (+8 more)

### Community 108 - "test_identity_lifecycle_routes.py"
Cohesion: 0.20
Nodes (18): app(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory, Public lifecycle routes: accept an invitation, request and complete a password… (+10 more)

### Community 109 - "WatchLists"
Cohesion: 0.06
Nodes (67): ValueError, Errors raised by password policies and watch lists. Messages carry field names,…, A watch list, or a change to one, was refused., No watch list has that id., The change clashes with the stored state: a list still attached to a policy., An import was refused or failed; the list is left as it was. ``line`` is the…, WatchListConflict, WatchListError (+59 more)

### Community 110 - "provider.py"
Cohesion: 0.13
Nodes (16): Exception, Single sign-on refusals. ``SsoError.reason`` is a fixed category, recorded in…, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic(), _https(), _KeySet, parse_metadata() (+8 more)

### Community 111 - "check_dist.py"
Cohesion: 0.11
Nodes (25): argparse, email_parser, dist_problems(), import_problems(), main(), _metadata_version(), Path, Check warden's built distributions, and the installed package, before… (+17 more)

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
Cohesion: 0.18
Nodes (5): ssl, Event, In-process syslog collectors for tests: stream (TCP or TLS), UDP and a…, UdpCollector, _UdpProtocol

### Community 116 - "identity/conftest.py"
Cohesion: 0.14
Nodes (22): app(), audit_registry(), client(), config(), db(), identity(), keys(), mail() (+14 more)

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
Cohesion: 0.18
Nodes (13): _format_errors(), parse_config(), Any, Protocol, What warden needs from konfig's ``Settings``., What warden needs from konfig's ``Secrets``., Accept a comma-separated string (as the environment supplies) for a list field., Validate a settings tree into ``WardenConfig`` or raise ``ConfigError``. (+5 more)

### Community 121 - "test_sso_issuer.py"
Cohesion: 0.13
Nodes (24): alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer(), Any (+16 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.19
Nodes (25): _assert_one_unforked_chain(), _event(), Any, The chained recorder: links, server-side order, the details cap, and…, Poll until backend ``pid`` waits on the chain's advisory lock., Row id order is commit order: the second inserter waits for the first's commit., A server default of REPEATABLE READ must not make warden's own writes conflict., _raw_insert() (+17 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 125 - "test_webauthn_credentials.py"
Cohesion: 0.18
Nodes (15): fido2_utils, LogCaptureFixture, parametrize, UserFactory, The credential store (list, rename, remove, count) and challenge pruning., test_an_invalid_nickname_is_refused(), test_another_users_credential_cannot_be_touched(), test_list_count_rename_and_remove() (+7 more)

### Community 126 - "assert_refused"
Cohesion: 0.21
Nodes (27): assert_refused(), passkey_options(), Response, The uniform refusal, byte for byte., _challenges(), elsewhere(), here(), _passkey_failures() (+19 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (15): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+7 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.18
Nodes (16): importlib_util, init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch. (+8 more)

### Community 129 - "Sessions"
Cohesion: 0.21
Nodes (12): _hash(), Any, AsyncConnection, NoReturn, SourceIp, UUID, The user's email if the session is live and the user active, else None., Open a session (a new family) inside the caller's transaction. Read ``policy``… (+4 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "test_password_set_points.py"
Cohesion: 0.13
Nodes (20): _administrator(), _change(), _codes(), _create(), _forced(), _hash(), _http_failures(), _invitation() (+12 more)

### Community 132 - "MemorySecrets"
Cohesion: 0.10
Nodes (30): new_totp_key(), A fresh 256-bit key, encoded for the secrets store., MemorySecrets, cli_secrets(), fp_identity(), fixture, MemorySecrets, _forms() (+22 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "passkey_support.py"
Cohesion: 0.17
Nodes (19): http_client(), passkey_app(), AsyncClient, FastAPI, UUID, Helpers shared by the passkey tests (imported as ``passkey_support``). An…, Change the sign-in method behind the services' back (no rule applies)., set_method() (+11 more)

### Community 136 - "certs.py"
Cohesion: 0.11
Nodes (17): cryptography, cryptography_hazmat_primitives, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, cryptography_x509_oid, main(), Write a throwaway CA and a TLS keystore for the stub identity provider. python…, Issued (+9 more)

### Community 137 - "SignInMethodChangeRefused"
Cohesion: 0.11
Nodes (16): PendingSignInMethod, _purpose(), datetime, The link that lets a user create the credential a new method needs., The link a move to ``method`` mails; None for ``sso_only``, which links on…, A change waiting for its credential; ``from_method`` stays in force meanwhile., What completes the change: a link, or (None) the first single sign-on., A sign-in method change cannot be made now. ``reason`` is the audited reason.… (+8 more)

### Community 138 - "require_permission"
Cohesion: 0.27
Nodes (10): bearer_token(), Forbidden, installed_identity(), HTTPException, Request, A dependency requiring ``permission``; with ``scoped``, also the product's…, The signed-in user (by access token or API key), or the uniform 401 refusal., require_permission() (+2 more)

### Community 139 - "test_examples_public_surface.py"
Cohesion: 0.26
Nodes (12): ast, _private(), _private_path(), Path, Tripwire: the sample console uses only warden's public surface. The sample…, Every reach into a private warden module or name in ``source``., sample_sources(), test_nothing_under_examples_reaches_into_warden_internals() (+4 more)

### Community 140 - "console_router"
Cohesion: 0.17
Nodes (17): _anchor_report(), console_router(), anchor_head(), change_policy(), check_anchors(), import_sample(), move_clock(), recheck_passwords() (+9 more)

### Community 141 - "test_no_private_imports.py"
Cohesion: 0.36
Nodes (8): ImportFrom, _from_warden(), _private(), Tripwire: no warden module reaches into another module's private names. A…, Local names bound by an import from warden (modules or anything else)., test_no_module_reaches_into_another_modules_private_names(), _violations(), _warden_bindings()

### Community 142 - "test_password_policy_store.py"
Cohesion: 0.17
Nodes (23): Any, parametrize, UUID, The password policy store (rulings PW1, PW2 and PW11): policies, priorities,…, _settings(), test_a_change_notifies_in_its_own_transaction(), test_a_change_on_one_replica_reaches_a_listening_replica(), test_a_role_the_product_no_longer_declares_grants_nothing() (+15 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.16
Nodes (27): Purpose, StrEnum, Delete expired tokens, whatever their state; returns how many., Tokens in ``warden.single_use_tokens``. Every method works in the caller's…, SingleUseTokens, The token in a sent message's link (the test links end ``?t=<token>``)., _consume(), _issue() (+19 more)

### Community 144 - "test_password_cli.py"
Cohesion: 0.24
Nodes (22): _banned(), _entries(), FakeSettings, _policy(), Any, CaptureFixture, Path, UUID (+14 more)

### Community 145 - "well_formed"
Cohesion: 0.15
Nodes (18): IssuedToken, _live_token(), LiveToken, Any, AsyncConnection, datetime, TypeGuard, UUID (+10 more)

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
Cohesion: 0.15
Nodes (32): FixtureRequest, work(), address(), admin(), app(), _bearer(), client(), _last_id() (+24 more)

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.18
Nodes (30): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, anonymous(), bearer(), deployment(), make(), member() (+22 more)

### Community 154 - "SourceIp"
Cohesion: 0.12
Nodes (10): _credential_id(), SourceIp, The options for registering a passkey with an administrator's link. Resident…, Register a passkey with an administrator's link, using the link up. No session.…, The options for accepting a ``passkey_only`` invitation with a passkey.…, Change the default sign-in method, the allowed second factors, or both. See…, Cancel a pending change; the user stays on the method in force., The credential id a sign-in response names, for the throttle; None if… (+2 more)

### Community 155 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.10
Nodes (26): PasswordHistory, Any, AsyncConnection, datetime, UUID, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password., Whether ``password`` matches any of the user's last ``count`` passwords. (+18 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "test_sign_in_methods_migration.py"
Cohesion: 0.21
Nodes (19): _method(), _pending(), Any, Conn, parametrize, UUID, The sign-in methods migration (rulings CS13 and CS16), with a tested downgrade.…, _refused() (+11 more)

### Community 159 - "console/settings.py"
Cohesion: 0.13
Nodes (24): _init(), Namespace, KonfigSecrets, load_settings(), Any, Path, The sample's configuration: written for a sandbox, read through konfig. A…, Put the secrets warden needs in konfig's store, keeping any already there. The… (+16 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "HibpRangeClient"
Cohesion: 0.07
Nodes (37): AsyncBaseTransport, PasswordsConfig, Password policies: the fingerprint key and the breached-password range API.…, Whether a policy may enable the sealed fingerprint (ruling PW8)., HibpUnavailable, Exception, The breached-password range service could not be used. Always the same message:…, password_digest() (+29 more)

### Community 162 - "Identity"
Cohesion: 0.06
Nodes (75): Identity, FastAPI, warden's identity subsystem for one deployment., Make this Identity the one ``require_user`` and ``require_permission`` use., Run identity's background work (the session and password policy listeners) for…, Delete sign-in throttle records whose window has ended., test_running_also_listens_for_password_policy_changes(), test_the_services_are_attributes_built_at_construction() (+67 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "test_console_gaps.py"
Cohesion: 0.18
Nodes (7): Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., Question 39 was a defect in the admin route, fixed in warden 0.1.0., test_forbid_user_details_is_no_longer_a_gap(), test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap()

### Community 165 - "ApiKeys"
Cohesion: 0.09
Nodes (25): AuditConfig, DbConfig, IdentityConfig, BaseModel, Database settings. At runtime warden uses the product's pool, never this DSN., Audit trail settings., _Section, ApiKey (+17 more)

### Community 166 - "test_syslog_routes.py"
Cohesion: 0.27
Nodes (18): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), _audit_rows(), authorise(), _client(), Any (+10 more)

### Community 167 - "test_identity_throttle.py"
Cohesion: 0.19
Nodes (18): _fail(), UserFactory, Sign-in throttling per (identifier, source address)., Otherwise a password holder gets unlimited challenges, and so unlimited code…, Barriered concurrent attempts: no more than the limit reach password…, An attacker elsewhere cannot lock the user out., Throttling must not reveal whether an account exists., test_a_password_alone_does_not_reset_the_count_when_mfa_follows() (+10 more)

### Community 169 - "AcceptedInvitation"
Cohesion: 0.10
Nodes (17): AcceptedInvitation, check(), complete(), check(), PasskeyRegistration, Protocol, Single sign-on's subject pinning, run inside the acceptance transaction.…, The WebAuthn registration, run inside the acceptance transaction. Called with… (+9 more)

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "test_cli_audit.py"
Cohesion: 0.24
Nodes (14): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up() (+6 more)

### Community 173 - "test_cli_audit_errors.py"
Cohesion: 0.19
Nodes (14): _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path, The warden audit CLI without a database: connection failures and grants. (+6 more)

### Community 174 - "Principal"
Cohesion: 0.12
Nodes (9): Principal, The signed-in user behind a request. For a request made with an API key,…, Start TOTP enrolment, for a signed-in user or under an enrolment challenge., Start registering a key as a second factor, signed in or under an enrolment…, The signed-in user's security keys and passkeys, oldest first., The principal behind a live access token, or ``AuthenticationRefused``. Checks…, The policy a new password must meet at one of the four places it is set. Bound…, A candidate's result against the policy of one of the four places (ruling… (+1 more)

### Community 175 - "BuiltinList"
Cohesion: 0.15
Nodes (11): console_settings(), BuiltinList, _bundled(), bundled_list(), _check(), Path, Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled…, The bundled list, shared by every ``Identity`` in the process so it loads once. (+3 more)

### Community 176 - "test_config_passwords.py"
Cohesion: 0.22
Nodes (18): _parse(), Any, parametrize, Start-up validation of the password settings (rulings PW2, PW7 and PW8 of 10…, _refused(), test_a_fingerprint_key_name_makes_the_fingerprint_available(), test_a_malformed_secret_name_is_refused(), test_a_previous_key_needs_a_current_key() (+10 more)

### Community 177 - "passkey_config"
Cohesion: 0.15
Nodes (15): expire_challenge_of(), passkey_config(), Any, Expire only the challenge a browser response answers, as if its lifetime had…, The identity tests' configuration, with the passkey registration link., config(), http(), AsyncClient (+7 more)

### Community 178 - "test_console_source_ip.py"
Cohesion: 0.33
Nodes (13): client(), headers(), Any, AsyncClient, fixture, Response, The sample console's own routes pass the client address, as a product should…, _recorded() (+5 more)

### Community 179 - "canonical_json"
Cohesion: 0.15
Nodes (17): JsonValue, canonical_json(), cap_details(), _encode(), _number(), Any, The canonical UTF-8 JSON text of ``value``., ``details``, or the truncation marker if its canonical form exceeds… (+9 more)

### Community 180 - "test_sign_in_methods_passkey.py"
Cohesion: 0.27
Nodes (15): config(), has_password(), http(), live_sessions(), AsyncClient, fixture, UserFactory, UUID (+7 more)

### Community 181 - "StreamCollector"
Cohesion: 0.14
Nodes (10): Framing, SSLContext, Complete frames in ``raw`` and the incomplete remainder., A TCP (or, with ``ssl``, TLS) collector that records raw bytes and frames., Stop listening and drop every open connection, as a stopped collector would., split_frames(), StreamCollector, collector() (+2 more)

### Community 182 - "licence_audit.py"
Cohesion: 0.23
Nodes (14): packaging_requirements, packaging_utils, audit(), classify(), data_problems(), installed(), main(), _one() (+6 more)

### Community 183 - "SignInThrottle"
Cohesion: 0.06
Nodes (35): PasswordPruning, Pruner, PruneReport, Identifier, Protocol, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., What the pruner needs from password policies. (+27 more)

### Community 184 - "test_identity_key_publication.py"
Cohesion: 0.26
Nodes (14): jwt, PyJWK, _access_token(), _b64(), _decode(), keys_client(), _published_key(), Any (+6 more)

### Community 185 - "copy"
Cohesion: 0.22
Nodes (9): copy, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1() (+1 more)

### Community 186 - ".finish_webauthn_registration"
Cohesion: 0.18
Nodes (8): ChallengePurpose, The options for completing an ``mfa_required`` challenge with a key. They list…, Register a key as a second factor. Under a challenge, also completes the sign-…, Issue codes to a user holding none, and audit the key, in ``tx``. The user's…, The live challenge and why its user may not continue (None if they may)., A security key or passkey registered as a second factor., Mail the MFA-enrolled notice, after the user's first second factor committed.…, WebAuthnEnrolled

### Community 187 - "ConnectionSource"
Cohesion: 0.18
Nodes (8): ConnectionSource, AbstractAsyncContextManager, Any, AsyncConnection, Protocol, Anything that lends async connections; ``psycopg_pool.AsyncConnectionPool``…, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - "_purge_prefix"
Cohesion: 0.16
Nodes (9): CheckpointSigner, _KeyLike, _purge_prefix(), Any, AsyncConnection, datetime, Protocol, What a purge needs from the key store: ``KeyStore`` fits. (+1 more)

### Community 191 - "_LazySecrets"
Cohesion: 0.29
Nodes (4): _LazySecrets, Any, AsyncConnection, konfig ``Secrets``, constructed only if a command actually needs a secret.

### Community 192 - "race"
Cohesion: 0.12
Nodes (29): race(), Run ``calls`` as concurrent tasks released together by a barrier. Every task…, _admins(), UserFactory, Role assignments: audited, expiring, and never leaving no administrator., Two administrators demoting each other at once: exactly one demotion succeeds., test_an_administrator_role_cannot_expire(), test_an_expired_assignment_grants_nothing() (+21 more)

### Community 193 - "test_password_builtin.py"
Cohesion: 0.32
Nodes (10): _digests(), parametrize, Path, The built-in common-password list (ruling PW12): sorted SHA-1 digests, loaded…, test_a_listed_digest_is_found_and_others_are_not(), test_a_malformed_file_is_refused(), test_an_empty_list_matches_nothing(), test_the_bundled_list_ships() (+2 more)

### Community 194 - "SignInMethod"
Cohesion: 0.25
Nodes (9): Set a user's own method; None has them follow the default. At once when the…, Cancel a pending change: the user stays on the method in force. The user's own…, _resolve(), SignInMethodState, _value(), allows_passkey_sign_in(), StrEnum, Whether a method may sign in with a passkey alone: every one but ``sso_only``. (+1 more)

### Community 195 - ".sso_settings_router"
Cohesion: 0.18
Nodes (6): APIRouter, Invitation acceptance and password reset; mount under…, Administration routes; mount under ``config.http.admin_prefix``. ``permission``…, The public sign-in routes; mount under ``config.http.auth_prefix``., The single sign-on routes; mount under ``config.http.auth_prefix`` too., Single sign-on administration; mount under ``config.http.admin_prefix``.…

### Community 196 - "SignInSettings"
Cohesion: 0.25
Nodes (6): The default sign-in method and the allowed second factors (cached briefly)., The settings, cached for ``identity.policy_cache_seconds``., The settings, read now on ``conn`` (no cache)., The settings, read now (no cache)., _settings(), SignInSettings

### Community 197 - "Notes"
Cohesion: 0.10
Nodes (19): _audit(), Note, Notes, notes_router(), create_note(), delete_note(), found(), update_note() (+11 more)

### Community 198 - "test_dependabot.py"
Cohesion: 0.24
Nodes (7): _blocks(), Dependabot keeps the pinned GitHub Actions current. Pinning every action to a…, test_dependabot_watches_github_actions_weekly(), Tripwire: every GitHub Action is pinned to a full commit SHA. A tag such as…, _references(), test_every_action_is_pinned_to_a_commit_sha(), test_workflows_reference_actions()

### Community 199 - "test_packaging.py"
Cohesion: 0.20
Nodes (4): importlib, packaging_version, warden: identity and audit for Python web applications. The public API lives in…, Packaging: one version source, typed marker, distribution metadata.

### Community 200 - "AnchorSigner"
Cohesion: 0.24
Nodes (5): AnchorSigner, _KeyLike, Protocol, What anchoring needs from the key store: ``KeyStore`` fits., _SignatureLike

### Community 201 - "pytest"
Cohesion: 0.29
Nodes (8): pytest, _columns(), _constraints(), The audit chain migration: reversible, and refuses rows it cannot chain., test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(), test_head_includes_the_chain_revision(), test_upgrade_refuses_unchained_rows(), Fixtures for password policy tests: identity's audit actions are registered, as…

### Community 202 - "SecondFactorKind"
Cohesion: 0.22
Nodes (9): _factors(), _method(), StrEnum, ValueError, A second factor an administrator may allow (ruling CS14)., A settings value is not valid. The message names fields, never values., SecondFactorKind, SignInSettingsError (+1 more)

### Community 203 - "_structured_data"
Cohesion: 0.33
Nodes (6): _from_syslog(), The parameters of each SD-ELEMENT at the start of ``text`` (RFC 5424 section…, A PARAM-VALUE from ``pos`` up to its closing quote, unescaped., _scan_name(), _scan_value(), _structured_data()

### Community 204 - "keys_router"
Cohesion: 0.25
Nodes (9): _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter, Response (+1 more)

### Community 205 - "verify.py"
Cohesion: 0.07
Nodes (38): BreakReason, ExternalAnchor, An anchor found in an export: its line, its own row id when known, and the…, _b64url(), _b64url_decode(), Checkpoint, HistoricalVerifier, _int() (+30 more)

### Community 206 - "BlackholeCollector"
Cohesion: 0.25
Nodes (4): BlackholeCollector, StreamReader, StreamWriter, Accepts connections and never reads, so a sender's buffers fill and stall.

### Community 207 - ".finish"
Cohesion: 0.25
Nodes (6): _b64(), _json(), A signed access token and its lifetime in seconds., Sign the access token for a committed session., suspended_meanwhile(), reset_meanwhile()

### Community 208 - "test_database.py"
Cohesion: 0.46
Nodes (7): _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 209 - "ActionRegistry"
Cohesion: 0.08
Nodes (26): ActionRegistry, The set of actions this deployment records., Register a product action. Re-registering an identical spec is a no-op. Actions…, The spec for ``action``; ``KeyError`` if it was never registered., Register the audit actions the syslog routes record. Safe to call more than…, register_syslog_actions(), register_actions(), complete() (+18 more)

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 211 - "FakeSettings"
Cohesion: 0.50
Nodes (3): FakeSettings, Any, A settings source holding one nested tree, as konfig's get_section returns.

### Community 213 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends an acceptance transaction without committing it.

### Community 214 - "test_tls_fail_closed.py"
Cohesion: 0.46
Nodes (7): _findings(), _is_cert_required(), _is_true(), expr, Tripwire: nothing in warden turns TLS verification off. Fails on any use of…, test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 216 - "test_readme.py"
Cohesion: 0.43
Nodes (5): README.md is the PyPI project description, so it must render there without…, _targets(), test_every_link_is_absolute(), test_link_check_refuses_relative_link_and_image(), test_readme_has_links()

### Community 217 - "PasskeyLinkRefused"
Cohesion: 0.33
Nodes (5): PasskeyLinkRefused, Exception, No registration link for this user: ``sso_only``, or not active (ruling P8).…, Abandons a transaction whose refusal must also undo earlier writes., _Rollback

### Community 218 - "test_client_guide.py"
Cohesion: 0.47
Nodes (4): _contract_routes(), The client-behaviour guide (docs/guide/clients.md) and the contract agree on…, test_every_contract_route_is_linked_from_the_guide(), test_every_route_the_guide_names_is_in_the_contract()

### Community 219 - ".record"
Cohesion: 0.60
Nodes (3): Any, AsyncConnection, Record ``event`` and return its row id. With ``conn``, the row is written…

### Community 221 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends a transaction without committing it.

### Community 223 - "neutralise"
Cohesion: 0.40
Nodes (5): neutralise(), Replace every control character in ``value`` with a visible ``\\xNN`` escape., test_neutralise_leaves_ordinary_text_alone(), test_neutralise_replaces_c1_controls_and_unicode_line_separators(), test_neutralise_replaces_every_c0_control_and_del()

### Community 224 - "frame"
Cohesion: 0.40
Nodes (5): frame(), Frame ``message`` for a stream transport (RFC 6587)., test_lf_framing_appends_a_newline(), test_lf_framing_refuses_a_message_that_holds_a_newline(), test_octet_counting_prefixes_the_byte_length()

### Community 225 - "PolicyError"
Cohesion: 0.40
Nodes (4): PolicyError, ValueError, A policy change was refused., The same rules configuration applies at start-up.

### Community 226 - ".send_passkey_registration"
Cohesion: 0.40
Nodes (3): datetime, Mail a pending change's set-up link again; when the new link expires., Mail a user a single-use link for registering a passkey; when it expires. For a…

### Community 238 - ".verify_access_token"
Cohesion: 0.50
Nodes (3): AccessClaims, The claims of a validly signed, unexpired token, or None. No session check., _unb64()

### Community 239 - "Refused"
Cohesion: 0.67
Nodes (3): HTTPException, Raised by dependencies; FastAPI's default handler renders the uniform refusal., Refused

### Community 244 - "package"
Cohesion: 0.67
Nodes (3): package(), fixture, Install a throwaway template package under a unique name.

## Knowledge Gaps
- **110 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+105 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2034 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **22 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `AuditEvent`, `UUID`, `KeyStore`, `RecordingSender`, `test_webauthn_mfa.py`, `contract.py`, `password_admin.py`, `sso_settings.py`, `test_webauthn_reset.py`, `SoftwareAuthenticator`, `Database`, `SingleSignOn`, `PasswordEnforcement`, `UserError`, `test_identity_totp_reset.py`, `json_response`, `SsoSettingsStore`, `client_ip`, `rules.py`, `current_code`, `test_password_sign_in.py`, `admin.py`, `test_identity_policy.py`, `WebAuthn`, `Mfa`, `test_identity_prune.py`, `User`, `warden/cli.py`, `mail.py`, `export_openapi.py`, `typing`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `audit_rows`, `identity_support.py`, `webauthn_live_support.py`, `PolicyStore`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `build_console`, `test_password_admin_routes.py`, `PolicySettings`, `SignInMethods`, `test_identity_admin_routes.py`, `SecretBox`, `test_sso_capabilities.py`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `identity/__init__.py`, `test_sign_in_methods_sso.py`, `TokenPair`, `Roles`, `test_passkey_invitation.py`, `test_identity_lifecycle_routes.py`, `test_sso_source_ip.py`, `identity/conftest.py`, `test_sso_issuer.py`, `Cluster: test_identity_client_address.py`, `assert_refused`, `Sessions`, `test_password_set_points.py`, `MemorySecrets`, `passkey_support.py`, `require_permission`, `console_router`, `SingleUseTokens`, `test_password_cli.py`, `test_webauthn_live.py`, `test_audit_source_ip_routes.py`, `test_identity_capabilities.py`, `SourceIp`, `PasswordHistory`, `test_identity_throttle.py`, `Principal`, `passkey_config`, `test_sign_in_methods_passkey.py`, `SignInThrottle`, `test_identity_key_publication.py`, `.finish_webauthn_registration`, `race`, `SignInMethod`, `.sso_settings_router`, `SignInSettings`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`, `.send_passkey_registration`, `.__init__`?**
  _High betweenness centrality (0.132) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `SyslogSettings`, `AuditEvent`, `KeyStore`, `RecordingSender`, `PasswordResets`, `AuditRecorder`, `test_webauthn_mfa.py`, `test_audit_recorder.py`, `test_webauthn_reset.py`, `SoftwareAuthenticator`, `SingleSignOn`, `Invitations`, `PasswordEnforcement`, `UserError`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `test_syslog_forwarder.py`, `rules.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `test_identity_policy.py`, `WebAuthn`, `test_audit_retention.py`, `test_identity_prune.py`, `User`, `warden/cli.py`, `soft_authenticator.py`, `export_openapi.py`, `typing`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `audit_rows`, `identity_support.py`, `PolicyStore`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `build_console`, `test_password_admin_routes.py`, `PolicySettings`, `test_identity_admin_routes.py`, `SecretBox`, `test_key_publication.py`, `json`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `webauthn/service.py`, `webauthn/challenges.py`, `verify_chain`, `attestation.py`, `identity/__init__.py`, `test_sign_in_methods_sso.py`, `Roles`, `test_passkey_invitation.py`, `test_identity_lifecycle_routes.py`, `WatchLists`, `test_sso_source_ip.py`, `identity/conftest.py`, `test_audit_grants.py`, `test_sso_issuer.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `test_webauthn_credentials.py`, `assert_refused`, `test_password_set_points.py`, `MemorySecrets`, `passkey_support.py`, `SignInMethodChangeRefused`, `test_password_policy_store.py`, `SingleUseTokens`, `test_password_cli.py`, `test_webauthn_live.py`, `test_a_purge_committing_during_verification_breaks_nothing`, `test_audit_source_ip_routes.py`, `test_identity_capabilities.py`, `PasswordHistory`, `Identity`, `ApiKeys`, `test_syslog_routes.py`, `test_identity_throttle.py`, `BuiltinList`, `passkey_config`, `test_sign_in_methods_passkey.py`, `SignInThrottle`, `ConnectionSource`, `race`, `verify.py`, `test_database.py`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`, `.__init__`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Why does `AuditEvent` connect `AuditEvent` to `SyslogSettings`, `Sessions`, `UUID`, `PasswordResets`, `AuditRecorder`, `password_admin.py`, `test_audit_recorder.py`, `PasswordPolicies`, `SingleSignOn`, `Invitations`, `test_a_purge_committing_during_verification_breaks_nothing`, `PasswordEnforcement`, `UserError`, `SourceIp`, `SsoSettingsStore`, `format_message`, `ApiKeys`, `test_syslog_routes.py`, `test_syslog_forwarder.py`, `SyslogForwarder`, `test_audit_retention.py`, `Mfa`, `typing`, `password_policy/__init__.py`, `_purge_prefix`, `Notes`, `PolicyStore`, `Anchor`, `SignInMethods`, `json`, `.record`, `verify_chain`, `identity/__init__.py`, `.send_passkey_registration`, `TokenPair`, `Roles`, `WatchLists`, `test_audit_grants.py`, `test_audit_chain_recorder.py`?**
  _High betweenness centrality (0.024) - this node is a cross-community bridge._
- **Are the 59 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 59 INFERRED edges - model-reasoned connections that need verification._
- **Are the 94 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 94 INFERRED edges - model-reasoned connections that need verification._
- **Are the 165 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 165 INFERRED edges - model-reasoned connections that need verification._
- **What connects `STATUSES`, `METHODS`, `POLICY_FIELDS` to the rest of the system?**
  _110 weakly-connected nodes found - possible documentation gaps or missing edges._