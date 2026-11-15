# Graph Report - warden  (2026-11-16)

## Corpus Check
- 332 files · ~344,679 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 6991 nodes · 22754 edges · 236 communities (211 shown, 25 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2066 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `022f856e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- syslog/__init__.py
- test_sso_provider.py
- test_audit_registry.py
- SourceIp
- KeyStore
- RecordingSender
- Sessions
- AuditRecorder
- h
- test_webauthn_mfa.py
- contract.py
- build_password_admin_router
- lifecycle.py
- test_audit_recorder.py
- test_webauthn_reset.py
- SoftwareAuthenticator
- test_console_password_policy.py
- test_sso_invitations.py
- PasswordPolicies
- SingleSignOn
- Invitations
- WebAuthnError
- test_audit_anchor_format.py
- AuditEvent
- SignInMethod
- test_config_webauthn.py
- test_audit_chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- SsoSettingsStore
- CI Workflows
- test_console_browser.py
- ActionRegistry
- client_ip
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
- WardenConfig
- WebAuthn
- SyslogSettings
- Cluster: syslog
- Mfa
- test_identity_prune.py
- FakeIdp
- test_distributions.py
- test_config_fields.py
- warden/cli.py
- soft_authenticator.py
- mail.py
- test_console_passkeys.py
- build_reference_app
- typing
- PasswordStates
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- test_audit_export.py
- current_revision
- pytest
- test_webauthn_live.py
- PolicyStore
- test_identity_dependencies.py
- test_passkey_registration_link.py
- Anchor
- build_console
- examples/conftest.py
- test_password_admin_routes.py
- .rotate
- ._lead
- test_identity_admin_routes.py
- test_webauthn_migration.py
- SecretBox
- test_key_publication.py
- test_sso_capabilities.py
- test_audit_router.py
- test_openapi_contract.py
- test_identity_migration.py
- test_sso_migration.py
- audit_rows
- test_sso_admin_routes.py
- Cluster: Client-behaviour guide
- Cluster: warden design overview
- modules
- WebAuthnCredentials
- Challenges
- test_audit_verify.py
- test_cli_audit_anchor.py
- attestation.py
- test_db_schema.py
- identity/__init__.py
- AuditQuery
- test_sso_preset_label_only.py
- .register
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
- audit_router
- test_only_the_purger_role_can_purge
- grants.py
- Cluster: with
- parse_config
- test_sso_issuer.py
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- test_webauthn_credentials.py
- test_passkey_options_throttle.py
- test_lifecycle_migration.py
- test_bump_version.py
- console/cli.py
- test_password_policy_migration.py
- test_password_set_points.py
- identity_support.py
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- passkey_support.py
- IdentityConfig
- Discovery
- require_user
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- test_password_cli.py
- well_formed
- HttpConfig
- test_console_capabilities.py
- test_no_direct_environment.py
- Cluster: updates
- WebAuthnConfig
- _AfterFirstQuery
- Database
- test_identity_capabilities.py
- new_totp_key
- ceremony.js
- PasswordHistory
- Cluster: verify
- JwksCache
- load_settings
- Cluster: rsyslog
- test_password_hibp.py
- Identity
- test_licence_audit.py
- pathlib
- PasswordsConfig
- Outbox
- subprocess
- Cluster: examples/__init__.py
- ._accept
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- main
- test_connection_failure_prints_a_fixed_message_and_exits_1
- ProviderHttp
- BaseModel
- test_config_passwords.py
- ._handle
- test_console_source_ip.py
- timestamp_text
- JwkSet
- bump_version.py
- licence_audit.py
- SignInThrottle
- .too_soon
- copy
- test_bundled_data.py
- ConnectionSource
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- rsa_key
- _LazySecrets
- race
- test_console_password_rules.py
- tests/conftest.py
- build_sso_settings_router
- test_password_fingerprint.py
- Notes
- _Invalid
- WebAuthnRefusal
- AnchorSigner
- test_resolution_order_is_pin_then_highest_priority_role_then_default
- keys
- _structured_data
- escape_cell
- AnchorCheck
- source_wheel
- matching_step
- .open_challenge
- test_password_actions.py
- The built-in common-password list
- FakeSettings
- test_a_key_registered_while_switching_to_sso_only_never_leaves_both
- _Abort
- fp_identity
- _Prioritised
- FakeSettings
- .client
- ._ordered
- .where
- console/__init__.py
- _Abort
- FakeSecrets
- .record_failure
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
1. `Identity` - 633 edges
2. `Database` - 632 edges
3. `audit_rows()` - 203 edges
4. `RecordingSender` - 184 edges
5. `KeyStore` - 173 edges
6. `ActionRegistry` - 136 edges
7. `AuditRecorder` - 134 edges
8. `FakeIdp` - 126 edges
9. `AuditEvent` - 123 edges
10. `User` - 117 edges

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
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/__init__.py`
- 4-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`
- 5-file cycle: `src/warden/identity/__init__.py -> src/warden/identity/apikeys.py -> src/warden/identity/dependencies.py -> src/warden/identity/service.py -> src/warden/identity/mfa.py -> src/warden/identity/__init__.py`

## Hyperedges (group relationships)
- **Audit tamper-evidence mechanisms** — docs_design_audit_chain_audit_hash_chain, docs_design_audit_chain_retention_checkpoint, docs_design_audit_chain_anchor, docs_design_audit_chain_audit_database_roles, docs_design_overview_tamper_evidence [EXTRACTED 1.00]
- **Release and publication pipeline** — docs_releasing_bump_version, github_workflows_publish, docs_releasing_check_dist, docs_releasing_trusted_publishing, claude_integration_procedure [EXTRACTED 1.00]
- **Tripwire tests guarding architecture rules** — docs_design_overview_single_audit_writer, docs_design_overview_audit_independence, examples_console_readme_public_surface_tripwire, claude_mutation_checked_guards [INFERRED 0.85]

## Communities (236 total, 25 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.13
Nodes (47): passkey_assertion(), passkey_sign_in(), AsyncClient, UUID, Change the sign-in method behind the services' back (no rule applies)., set_method(), set_status(), _admin() (+39 more)

### Community 1 - "syslog/__init__.py"
Cohesion: 0.04
Nodes (42): DatagramTransport, errno, socket, format_test_message(), _header_field(), datetime, A NOTICE message with MSGID ``test``, for checking the path to the collector., A header field: PRINTUSASCII only, at most ``limit`` characters, never empty. (+34 more)

### Community 2 - "test_sso_provider.py"
Cohesion: 0.26
Nodes (22): ProviderMetadata, IdTokenValidator, ec_key(), check(), Discovery, JWKS caching and id_token validation, against a local fake provider., test_a_critical_header_is_refused(), test_a_key_is_used_only_with_its_own_algorithm(), test_a_valid_id_token_is_accepted() (+14 more)

### Community 3 - "test_audit_registry.py"
Cohesion: 0.07
Nodes (22): ActionSpec, _check_summary(), A registered action: dotted name, severity and summary template., The one-line summary for ``event``; absent fields render as ``-``., Register a product action. Re-registering an identical spec is a no-op. Actions…, The spec for ``action``; ``KeyError`` if it was never registered., complete(), parametrize (+14 more)

### Community 4 - "SourceIp"
Cohesion: 0.03
Nodes (79): Principal, The signed-in user behind a request. For a request made with an API key,…, MfaError, Exception, An MFA enrolment change was refused. Messages carry identifiers only., Enrolment, LastSecondFactorError, Passkeys and security keys are not configured for this deployment.… (+71 more)

### Community 5 - "KeyStore"
Cohesion: 0.06
Nodes (52): KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., KeyStore, KeyStoreError, Any, AsyncConnection, Composable, Exception (+44 more)

### Community 6 - "RecordingSender"
Cohesion: 0.07
Nodes (71): A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., StagedGrant, VerifiedIdentity, The product's mail sender, recording instead of sending. ``fail`` makes it…, RecordingSender, _accept(), FakePins (+63 more)

### Community 7 - "Sessions"
Cohesion: 0.08
Nodes (28): Protocol, SecretStore, Protocol, The product's resource-level check, consulted by ``require_permission(...,…, ResourceScopeHook, _Account, PasswordResets, Any (+20 more)

### Community 8 - "AuditRecorder"
Cohesion: 0.12
Nodes (62): AnchorRecord, ExternalAnchor, An anchor written to the trail, and the id of the row that carries it., An anchor found in an export: its line, its own row id when known, and the…, AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors() (+54 more)

### Community 9 - "h"
Cohesion: 0.07
Nodes (144): apiKeysScreen(), capabilities(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames() (+136 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.12
Nodes (69): _amr(), _app(), _assertion(), _bearer(), _challenge(), http(), _key_sign_in(), _options() (+61 more)

### Community 11 - "contract.py"
Cohesion: 0.04
Nodes (94): Public sign-in routes. The product mounts them under…, AffectedUsersProposalBody, BuiltinListBody, ChallengeBody, ChangePasswordBody, CodeBody, _Doc, EnrolmentBody (+86 more)

### Community 12 - "build_password_admin_router"
Cohesion: 0.09
Nodes (69): build_password_admin_router(), actor(), add_entries(), add_terms(), affected(), attach_list(), attached_to(), attachment() (+61 more)

### Community 13 - "lifecycle.py"
Cohesion: 0.07
Nodes (44): fastapi_responses, detail(), _inline(), resolve(), InvitationAcceptBody, json_body(), LinkPasswordCheckBody, LinkTokenBody (+36 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.15
Nodes (27): BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any, AsyncConnection, fixture (+19 more)

### Community 15 - "test_webauthn_reset.py"
Cohesion: 0.17
Nodes (26): _admin(), _bearer(), http(), Any, AsyncClient, fixture, MonkeyPatch, Response (+18 more)

### Community 16 - "SoftwareAuthenticator"
Cohesion: 0.15
Nodes (44): One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, Any, parametrize, UserFactory, UUID, Registering a passkey or security key: the options, the checks and every…, _refused() (+36 more)

### Community 17 - "test_console_password_policy.py"
Cohesion: 0.09
Nodes (21): assert_strict_csp(), Response, Helpers shared by the sample console's tests (imported as ``console_support``)., _passwords_source(), The sample console's password policy support: routes, the development clock,…, Every (method, path) a screen sends to a warden router, path parameters as…, test_an_imported_list_explains_the_file_the_threshold_and_the_command_line(), test_the_built_in_list_is_said_to_need_no_loading_on_both_screens() (+13 more)

### Community 18 - "test_sso_invitations.py"
Cohesion: 0.11
Nodes (58): Body, functools, Started, accept(), acceptance_rows(), app(), _bodies(), handoffs_of() (+50 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.06
Nodes (58): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, ValueError (+50 more)

### Community 20 - "SingleSignOn"
Cohesion: 0.07
Nodes (36): AcceptedInvitation, Single sign-on's subject pinning, run inside the acceptance transaction.…, SubjectPin, _challenge(), ConfigurationCheck, ConfigurationReport, _hash(), InvitationAcceptance (+28 more)

### Community 21 - "Invitations"
Cohesion: 0.11
Nodes (23): Method, Invitation, InvitationError, Invitations, _Invitee, PendingInvitation, Any, AsyncConnection (+15 more)

### Community 22 - "WebAuthnError"
Cohesion: 0.10
Nodes (28): PublicKeyCredentialDescriptor, Exception, A WebAuthn ceremony or credential change was refused. ``user_id`` and…, Whether the refusal reports a credential that may have been copied., WebAuthnError, _extension_results(), _parse(), Any (+20 more)

### Community 23 - "test_audit_anchor_format.py"
Cohesion: 0.16
Nodes (27): cryptography_hazmat_primitives_asymmetric_ed25519, The anchors in an export from a SIEM, one record per line, numbered from 1. Two…, read_anchors(), _anchor(), _ndjson(), Any, Anchors: the signed payload, its domain separation, and reading anchors back…, SIEMs often prepend their own receive time and host, or keep the octet count. (+19 more)

### Community 24 - "AuditEvent"
Cohesion: 0.03
Nodes (69): SetPlace, AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., AuditChainConflict, Any, AsyncConnection, Exception (+61 more)

### Community 25 - "SignInMethod"
Cohesion: 0.13
Nodes (20): InvitationMismatch, The invitation is valid but was accepted the wrong way; it stays usable.…, Any, AsyncConnection, Composable, datetime, SourceIp, StrEnum (+12 more)

### Community 26 - "test_config_webauthn.py"
Cohesion: 0.11
Nodes (36): _certificate(), _parse(), Any, parametrize, Start-up validation of the WebAuthn settings (rulings P2, P3 and P7 of 6…, _refused(), _Secrets, test_a_malformed_passkey_registration_link_is_refused() (+28 more)

### Community 27 - "test_audit_chain.py"
Cohesion: 0.13
Nodes (27): JsonValue, canonical_json(), cap_details(), The canonical UTF-8 JSON text of ``value``., The SHA-256 row hash of ``row``., ``details``, or the truncation marker if its canonical form exceeds…, row_hash(), Any (+19 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.10
Nodes (44): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+36 more)

### Community 29 - "test_config.py"
Cohesion: 0.14
Nodes (44): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, _load(), parametrize, Configuration contract: one typed object, validated at start-up., _sso_tree(), test_audit_only_deployment_needs_no_link_templates() (+36 more)

### Community 30 - "json_response"
Cohesion: 0.07
Nodes (90): json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), build_auth_router(), begin_enrolment() (+82 more)

### Community 31 - "SsoSettingsStore"
Cohesion: 0.13
Nodes (21): _from_config(), _plain(), Any, AsyncConnection, SourceIp, ValueError, The effective settings, cached for ``max_age`` seconds., The effective settings, read now on ``conn`` (no cache). (+13 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_console_browser.py"
Cohesion: 0.09
Nodes (22): ConsoleBrowser, run(), enrol_authenticator(), forced(), open_console(), plain(), Any, fixture (+14 more)

### Community 34 - "ActionRegistry"
Cohesion: 0.10
Nodes (48): ActionRegistry, The set of actions this deployment records., AuditRecord, _clip(), format_message(), build(), neutralise(), Match (+40 more)

### Community 35 - "client_ip"
Cohesion: 0.10
Nodes (31): client_ip(), Network, Request, SourceIp, The client address, for audit events and the sign-in throttle key. Resolved by…, HandoffBody, A new session. Every route that issues one answers with this body., A new session after a forced enrolment, with the recovery codes, shown once. (+23 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.13
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.20
Nodes (39): ForwarderFactory, _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader() (+31 more)

### Community 38 - "test_password_rules.py"
Cohesion: 0.09
Nodes (43): _bool(), _int(), _opt_int(), PassphraseRule, Any, When a password counts as a passphrase (PW4)., The versioned JSON shape a browser evaluates., Rebuild rules from ``describe()``'s shape; refuses another version. (+35 more)

### Community 39 - "current_code"
Cohesion: 0.09
Nodes (55): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), code_for(), current_code(), _challenge(), _enrolled() (+47 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.08
Nodes (51): cryptography_hazmat_primitives, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, cryptography_x509_oid, frame(), open_transport(), SSLContext, Connect to the collector named in ``settings``; ``TransportError`` on failure. (+43 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.06
Nodes (95): failing_transport(), handler(), listing_transport(), MockTransport, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., bearer() (+87 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.07
Nodes (35): Begin competing for the forwarder lock and, once held, forwarding., Stop forwarding, release the lock and close the transport. Idempotent., Switch to new settings; the next send opens a transport with them. Waits for an…, The snapshot plus the stored cursor and the lag behind it. Read from the…, Try for the lock; lead until stopped or the session ends. True if it led., How many of ``ids`` may be sent now, given the gaps in front of them., Record the gap ``start..end``; returns when any part of it was first seen., Forwards committed audit rows to syslog. Start it at boot; stop it at shutdown. (+27 more)

### Community 43 - "admin.py"
Cohesion: 0.08
Nodes (64): A dependency requiring ``permission``; with ``scoped``, also the product's…, require_permission(), _api_key(), _assignment(), _BadRequest, build_admin_router(), assign_role(), capabilities() (+56 more)

### Community 44 - "test_sso_sealing.py"
Cohesion: 0.15
Nodes (26): cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's…, The token sealed in ``sealed``, or None if it does not open to one. (+18 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (11): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+3 more)

### Community 46 - "WardenConfig"
Cohesion: 0.07
Nodes (48): warden's whole configuration: one object, validated once at start-up., WardenConfig, sso_config(), config(), config(), config(), app(), config() (+40 more)

### Community 47 - "WebAuthn"
Cohesion: 0.19
Nodes (36): The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, _enrolled(), Any, parametrize, UserFactory, UUID (+28 more)

### Community 48 - "SyslogSettings"
Cohesion: 0.07
Nodes (40): Any, BaseModel, field_validator, model_validator, Self, Build settings from the shared ``SyslogConfig``. ``secrets`` looks up a konfig…, Everything the forwarder, formatter and transports need., SyslogSettings (+32 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Mfa"
Cohesion: 0.14
Nodes (18): SecondFactor, Mfa, Any, AsyncConnection, SourceIp, UUID, Re-seal every secret not sealed with the current key; returns how many. Run…, Hold the user's row until the transaction ends; whether the user exists. ``FOR… (+10 more)

### Community 51 - "test_identity_prune.py"
Cohesion: 0.18
Nodes (16): _count(), _expire_all(), _fixtures(), Any, MonkeyPatch, UserFactory, Pruning (#134): expired refresh and single-use tokens, MFA challenges, throttle…, Move every row of ``table`` into the past, keeping its own constraints. (+8 more)

### Community 52 - "FakeIdp"
Cohesion: 0.12
Nodes (70): User, FakeIdp, callback(), completion(), handoff(), provider_code(), Any, AsyncClient (+62 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.14
Nodes (30): importlib_util, io, _load(), _only(), ModuleType, MonkeyPatch, parametrize, Path (+22 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.14
Nodes (28): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+20 more)

### Community 55 - "warden/cli.py"
Cohesion: 0.02
Nodes (159): argparse, BinaryIO, BreakReason, ExportFormat, sqlalchemy_exc, The audit actions warden's own audit subsystem records., Register warden's audit actions. Idempotent., register_audit_actions() (+151 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.12
Nodes (26): CoseKey, fido2, fido2_cose, ca(), make_webauthn(), factory(), Any, fixture (+18 more)

### Community 57 - "mail.py"
Cohesion: 0.06
Nodes (56): html, MailConfig, Mail settings. The product implements the sender., _check(), format_expiry(), _is_control(), _load(), MailDeliveryError (+48 more)

### Community 58 - "test_console_passkeys.py"
Cohesion: 0.17
Nodes (29): authenticator(), Any, A software authenticator that makes passkeys: discoverable, verifying the user., amr(), browser(), link_token(), outbox_message(), passkey_sign_in() (+21 more)

### Community 59 - "build_reference_app"
Cohesion: 0.06
Nodes (39): PyJWK, build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), Any (+31 more)

### Community 60 - "typing"
Cohesion: 0.03
Nodes (155): argon2, argon2_exceptions, asyncio, base64, binascii, collections_abc, contextlib, cryptography_exceptions (+147 more)

### Community 61 - "PasswordStates"
Cohesion: 0.05
Nodes (62): ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID, Use the challenge up; False if another request already did, or it lapsed., Count a refused attempt against the challenge, in its own transaction. (+54 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.14
Nodes (26): ApiKeyError, Exception, An API key change was refused. Messages carry no values., _app(), _bearer(), client(), AsyncClient, FastAPI (+18 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.09
Nodes (19): PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role, fixture, parametrize (+11 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.12
Nodes (25): _address(), Any, Network, _Scope, Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``., The client address, given the peer and every ``X-Forwarded-For`` value in order., ASGI middleware setting ``scope["client"]`` to the resolved client address., resolve_client_ip() (+17 more)

### Community 65 - "test_audit_export.py"
Cohesion: 0.28
Nodes (15): csv, csv_lines(), ndjson_lines(), One JSON object per line., A header line, then one CSV record per row., _collect(), Any, Export formatting: CSV formula-injection escaping and NDJSON (no database). (+7 more)

### Community 66 - "current_revision"
Cohesion: 0.08
Nodes (46): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), current_revision(), downgrade(), heads() (+38 more)

### Community 67 - "pytest"
Cohesion: 0.09
Nodes (40): httpx, os, pytest, Helpers shared by single sign-on tests (imported as ``sso_support``)., app(), Any, AsyncClient, FastAPI (+32 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.06
Nodes (47): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+39 more)

### Community 69 - "PolicyStore"
Cohesion: 0.06
Nodes (32): PolicyError, PolicyStore, Any, AsyncConnection, Event, SourceIp, ValueError, The effective session policy, cached per replica and invalidated over NOTIFY. (+24 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (22): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, Request (+14 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.20
Nodes (34): admin(), config(), _credential_count(), http(), _identity(), _link(), _options(), Any (+26 more)

### Community 72 - "Anchor"
Cohesion: 0.13
Nodes (22): Anchor, _b64url(), _b64url_decode(), _from_ndjson(), _int(), MalformedAnchor, Any, IPv4Address (+14 more)

### Community 73 - "build_console"
Cohesion: 0.09
Nodes (16): actor(), build_console(), Console, _mount_pages(), FastAPI, Request, Build the console over the product's open pool and konfig's secrets store.…, The built console: the app and the warden objects behind it. (+8 more)

### Community 74 - "examples/conftest.py"
Cohesion: 0.18
Nodes (14): client(), console(), make_console(), build(), Any, AsyncClient, fixture, MemorySecrets (+6 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.07
Nodes (68): bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests., app(), client() (+60 more)

### Community 76 - ".rotate"
Cohesion: 0.13
Nodes (15): Ed25519PrivateKey, _b64url(), _b64url_decode(), key_id_for(), PublicKey, Generate a key and make it the signing key. Earlier keys keep verifying., The key that signs now: the newest unretired, unrevoked key., Published keys, newest first. A revoked key is never included. (+7 more)

### Community 77 - "._lead"
Cohesion: 0.14
Nodes (16): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+8 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "test_webauthn_migration.py"
Cohesion: 0.21
Nodes (24): _challenge(), _credential(), Any, Conn, parametrize, UUID, WebAuthn's migration: credentials, user handles and challenges, with a tested…, ``statement(conn)`` raises a check or unique violation, on its own connection. (+16 more)

### Community 80 - "SecretBox"
Cohesion: 0.14
Nodes (13): _key_id(), ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., Seals and opens small secrets with the current (and, while rotating, previous)…, SecretBox, _key(), Encryption of TOTP secrets at rest. No database., Copying one user's ciphertext onto another user's row must not work. (+5 more)

### Community 81 - "test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "test_audit_router.py"
Cohesion: 0.16
Nodes (21): client(), exporter(), NoKeys, Any, AsyncClient, fixture, parametrize, Audit routers: list, export and verify, behind the product's own authorisation. (+13 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.20
Nodes (14): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+6 more)

### Community 86 - "test_sso_migration.py"
Cohesion: 0.26
Nodes (11): Connection, parametrize, UUID, Single sign-on's migration: its tables, their constraints, and a tested…, _tables(), test_a_subject_is_pinned_to_one_user(), test_a_user_has_at_most_one_pin(), test_constraints() (+3 more)

### Community 87 - "audit_rows"
Cohesion: 0.09
Nodes (41): statistics, audit_rows(), _config(), fp_identity(), Any, fixture, Request, Response (+33 more)

### Community 88 - "test_sso_admin_routes.py"
Cohesion: 0.17
Nodes (22): app(), authorise(), idp(), Any, AsyncClient, FastAPI, fixture, parametrize (+14 more)

### Community 89 - "Cluster: Client-behaviour guide"
Cohesion: 0.13
Nodes (23): warden changelog, Passkey sign-in and passkey_only method (0.1.0b11), WebAuthn security keys and passkeys as second factor (0.1.0b10), OIDC single sign-on with PKCE, pre-provisioned accounts, HTTP contract docs/contract/openapi.json, Product-declared permissions and roles (D5), Rotating refresh-token families with reuse detection, Trusted-proxy middleware (+15 more)

### Community 90 - "Cluster: warden design overview"
Cohesion: 0.11
Nodes (23): fido2 runtime dependency (0.1.0b9), Integration procedure (merge, re-chain, stamp), Migrations across parallel workstreams, Mutation-checked guard and tripwire tests, warden project working agreement (CLAUDE.md), Single-use credentials consumed by one guarded atomic write, Acceptance tests from Termograph hardening findings, Argon2id passwords with legacy PBKDF2 rehash (D15) (+15 more)

### Community 91 - "modules"
Cohesion: 0.15
Nodes (27): Pattern, _docstring_nodes(), identifiers(), module_name(), modules(), AST, Path, Helpers for tripwires that read warden's own source. (+19 more)

### Community 92 - "WebAuthnCredentials"
Cohesion: 0.20
Nodes (13): check_nickname(), credential_from_row(), Any, AsyncConnection, UUID, The user's credential, or None if they hold no credential with that id., Set or clear the nickname; None if the user holds no such credential., Remove one of the user's credentials; whether it existed. (+5 more)

### Community 93 - "Challenges"
Cohesion: 0.17
Nodes (10): Challenges, ConsumedChallenge, _hash(), IssuedChallenge, Any, AsyncConnection, UUID, Delete expired challenges, used or not; returns how many. (+2 more)

### Community 94 - "test_audit_verify.py"
Cohesion: 0.19
Nodes (21): ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id., A forger who recomputes the altered row's hash is caught at the next row., Swap every stored column of two rows except their ids. (+13 more)

### Community 95 - "test_cli_audit_anchor.py"
Cohesion: 0.20
Nodes (20): _export(), FakeSecrets, FakeSettings, Any, CaptureFixture, fixture, Path, The warden CLI: audit anchor, and audit verify --anchors, against a real… (+12 more)

### Community 96 - "attestation.py"
Cohesion: 0.13
Nodes (14): AttestationObject, Certificate, cryptography, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca() (+6 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.10
Nodes (11): _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range() (+3 more)

### Community 98 - "identity/__init__.py"
Cohesion: 0.03
Nodes (103): Creating the first administrator. warden's own CLI cannot do this, because the…, The sample's own routes, built on warden's public Python API. Where warden…, A mail sender that keeps messages in memory, so the console can show them.…, The sample product's own permissions, roles and audit actions. warden hardcodes…, warden's identity subsystem: users, sign-in, sessions, roles and permissions,…, PasswordFailure, PasswordFeedback, PasswordRejected (+95 more)

### Community 99 - "AuditQuery"
Cohesion: 0.20
Nodes (20): AuditQuery, list_events(), BaseModel, A filter over the audit trail. Every given field must match. ``since`` is…, A page of matching rows, newest first, older than ``before_id`` if given., _collect(), _ids(), Any (+12 more)

### Community 100 - "test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (16): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations() (+8 more)

### Community 101 - ".register"
Cohesion: 0.16
Nodes (13): Algorithm, AttestationFormat, FLAG, PrivateKey, _new_key(), Any, AuthenticatorData, CollectedClientData (+5 more)

### Community 102 - "Roles"
Cohesion: 0.12
Nodes (22): LastAdministratorError, lock_administrators(), Any, AsyncConnection, datetime, Exception, SourceIp, UUID (+14 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.15
Nodes (10): _check_secret_name(), _check_url(), field_validator, ValueError, A konfig secret name: letters, digits, '.', '_', '/' and '-'., Validate an absolute http(s) URL; plain http only for loopback hosts. The value…, Syslog forwarding: every field ``SyslogSettings`` needs.…, SsoConfig (+2 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (30): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+22 more)

### Community 106 - "bearer"
Cohesion: 0.14
Nodes (43): create_administrator(), Create an active user with ``password`` holding the administrator role. Running…, bearer(), make_user(), AsyncClient, sign_in(), link_token(), Any (+35 more)

### Community 107 - "test_audit_source_ip_tripwire.py"
Cohesion: 0.19
Nodes (16): collections, _constants(), _is_warden(), _missing(), _owner(), expr, Tripwire: every warden audit event carries the client address, unless it has no…, The class and method, or the function, a call sits in (nested routes keep their… (+8 more)

### Community 108 - "test_identity_lifecycle_routes.py"
Cohesion: 0.20
Nodes (18): app(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory, Public lifecycle routes: accept an invitation, request and complete a password… (+10 more)

### Community 109 - "WatchLists"
Cohesion: 0.05
Nodes (72): BuiltinList, _bundled(), _check(), Path, Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled…, _read(), _check_label(), _iterate() (+64 more)

### Community 110 - "provider.py"
Cohesion: 0.15
Nodes (14): Exception, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic(), _https(), parse_metadata(), Talking to the identity provider: HTTP, discovery and the JWKS cache. Discovery…, HTTP Basic credentials for the token endpoint: each part form-encoded first… (+6 more)

### Community 111 - "check_dist.py"
Cohesion: 0.21
Nodes (15): email_parser, dist_problems(), import_problems(), main(), _metadata_version(), Path, Check warden's built distributions, and the installed package, before…, Exactly one wheel and one sdist, each of them good. (+7 more)

### Community 112 - "test_cli.py"
Cohesion: 0.22
Nodes (12): FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: migrate and keys rotate., _settings(), test_invalid_configuration_fails_before_doing_anything(), test_keys_rotate_adds_a_key_and_prints_only_its_id() (+4 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (17): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+9 more)

### Community 114 - "test_sso_source_ip.py"
Cohesion: 0.16
Nodes (18): app(), authorise(), idp(), Any, AsyncClient, FastAPI, fixture, parametrize (+10 more)

### Community 115 - "collector.py"
Cohesion: 0.08
Nodes (13): Framing, ssl, BlackholeCollector, Event, SSLContext, StreamReader, StreamWriter, In-process syslog collectors for tests: stream (TCP or TLS), UDP and a… (+5 more)

### Community 116 - "audit_router"
Cohesion: 0.12
Nodes (17): AwareDatetime, description, max_length, Outcome, Any, A row as a JSON-ready object: ISO timestamps (UTC), hex hashes., row_to_json(), _address_or_none() (+9 more)

### Community 117 - "test_only_the_purger_role_can_purge"
Cohesion: 0.17
Nodes (12): _as(), MemorySecrets, _pool(), Any, parametrize, _refused(), _registry(), test_only_the_purger_role_can_purge() (+4 more)

### Community 118 - "grants.py"
Cohesion: 0.44
Nodes (11): append_only_grants(), _application(), _forwarder(), _ident(), _purger(), Composable, Composed, Identifier (+3 more)

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "parse_config"
Cohesion: 0.14
Nodes (17): _format_errors(), load_config(), parse_config(), Any, Protocol, What warden needs from konfig's ``Settings``., What warden needs from konfig's ``Secrets``., Accept a comma-separated string (as the environment supplies) for a list field. (+9 more)

### Community 121 - "test_sso_issuer.py"
Cohesion: 0.13
Nodes (24): alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer(), Any (+16 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.17
Nodes (27): _assert_one_unforked_chain(), _event(), Any, fixture, The chained recorder: links, server-side order, the details cap, and…, Poll until backend ``pid`` waits on the chain's advisory lock., Row id order is commit order: the second inserter waits for the first's commit., A server default of REPEATABLE READ must not make warden's own writes conflict. (+19 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (15): app(), config(), AsyncClient, FastAPI, fixture, UserFactory, Identity's client address comes from the trusted-proxy resolver. Behind a…, _source_ips() (+7 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 125 - "test_webauthn_credentials.py"
Cohesion: 0.18
Nodes (15): fido2_utils, LogCaptureFixture, parametrize, UserFactory, The credential store (list, rename, remove, count) and challenge pruning., test_an_invalid_nickname_is_refused(), test_another_users_credential_cannot_be_touched(), test_list_count_rename_and_remove() (+7 more)

### Community 126 - "test_passkey_options_throttle.py"
Cohesion: 0.21
Nodes (28): assert_refused(), passkey_options(), Response, The uniform refusal, byte for byte., other_key(), A key no credential holds, for signatures that must not verify., _challenges(), elsewhere() (+20 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (14): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+6 more)

### Community 128 - "test_bump_version.py"
Cohesion: 0.22
Nodes (14): init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch., test_accepts_release_forms() (+6 more)

### Community 129 - "console/cli.py"
Cohesion: 0.17
Nodes (21): _create_admin(), work(), _dsn(), _init(), main(), _parser(), Any, ArgumentParser (+13 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "test_password_set_points.py"
Cohesion: 0.13
Nodes (21): _administrator(), _change(), _codes(), _create(), _forced(), _hash(), _http_failures(), _invitation() (+13 more)

### Community 132 - "identity_support.py"
Cohesion: 0.07
Nodes (49): enrol_totp(), make_config(), MemorySecrets, Helpers shared by identity tests (imported as ``identity_support``)., Enrol and confirm TOTP for ``user``; returns the secret. Confirmation claims…, test_keys_may_be_unexpiring_when_no_maximum_is_set(), test_the_configured_prefix_is_used(), _identity() (+41 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "passkey_support.py"
Cohesion: 0.10
Nodes (36): expire_challenge_of(), give_passkey(), http_client(), passkey_app(), passkey_config(), Any, FastAPI, Helpers shared by the passkey tests (imported as ``passkey_support``). An… (+28 more)

### Community 136 - "IdentityConfig"
Cohesion: 0.26
Nodes (5): _FieldProblems, IdentityConfig, model_validator, Self, Cross-field problems, each with a path relative to the failing model.

### Community 137 - "Discovery"
Cohesion: 0.18
Nodes (12): Discovery, The provider's metadata, cached per issuer., Fetch and check the metadata, bypassing the cache., Any, parametrize, reason_of(), test_discovery_failure_is_not_cached(), test_discovery_reads_the_provider_metadata() (+4 more)

### Community 138 - "require_user"
Cohesion: 0.22
Nodes (11): bearer_token(), Forbidden, installed_identity(), HTTPException, Request, The signed-in user (by access token or API key), or the uniform 401 refusal., dependency(), require_user() (+3 more)

### Community 139 - "test_examples_public_surface.py"
Cohesion: 0.26
Nodes (12): ast, _private(), _private_path(), Path, Tripwire: the sample console uses only warden's public surface. The sample…, Every reach into a private warden module or name in ``source``., sample_sources(), test_nothing_under_examples_reaches_into_warden_internals() (+4 more)

### Community 140 - "console_router"
Cohesion: 0.16
Nodes (18): _anchor_report(), console_router(), anchor_head(), change_policy(), check_anchors(), console_settings(), import_sample(), move_clock() (+10 more)

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
Cohesion: 0.31
Nodes (20): _banned(), _entries(), _policy(), CaptureFixture, Path, UUID, warden passwords import and recheck against a real database (rulings PW7 and…, run_cli() (+12 more)

### Community 145 - "well_formed"
Cohesion: 0.15
Nodes (18): IssuedToken, _live_token(), LiveToken, Any, AsyncConnection, datetime, TypeGuard, UUID (+10 more)

### Community 146 - "HttpConfig"
Cohesion: 0.18
Nodes (7): _check_template(), HttpConfig, Validate a UI link template: a path or URL using exactly ``placeholders``., Where the product exposes warden (design D9). Mount prefixes are where the…, The OIDC redirect URI, derived so it cannot disagree with the mount., An absolute URL for a path under the public base URL., Fill a link template, percent-encoding every value.

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

### Community 151 - "_AfterFirstQuery"
Cohesion: 0.33
Nodes (4): _AfterFirstQuery, _HookedPool, Any, Delegates to a connection, running ``hook`` once after the checkpoint listing.

### Community 152 - "Database"
Cohesion: 0.11
Nodes (44): FixtureRequest, Database, warden's handle on the product's connection pool., work(), _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given() (+36 more)

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.08
Nodes (52): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, app(), audit_registry(), client(), config(), db() (+44 more)

### Community 154 - "new_totp_key"
Cohesion: 0.19
Nodes (13): _decode(), new_totp_key(), Exception, A TOTP key is missing or malformed. Names the secret, never its value., A fresh 256-bit key, encoded for the secrets store., Read the keys from konfig's secrets store; fails if the current key is…, SecretKeyError, test_a_configured_fingerprint_key_must_be_in_the_secrets_store() (+5 more)

### Community 155 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.13
Nodes (21): PasswordHistory, Password history (ruling PW6). Each password a user sets is kept as its…, Previous Argon2id hashes per user., PasswordHasher, Argon2id hashing with legacy PBKDF2 verification. The defaults are…, An Argon2id hash of ``password``., Spend the time one Argon2id verification takes, for a user who has no hash.…, history() (+13 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "JwksCache"
Cohesion: 0.18
Nodes (7): JwksCache, _KeySet, The provider's signing keys, by key id., The JWK with ``kid``, or None if the provider does not publish it., Fetch the key set afresh, without touching the cache (for configuration tests)., _usable(), test_jwks_returns_a_known_key_from_cache()

### Community 159 - "load_settings"
Cohesion: 0.15
Nodes (21): KonfigSecrets, load_settings(), Any, Path, Put the secrets warden needs in konfig's store, keeping any already there. The…, konfig's ``Secrets``, typed as the store warden expects (``get`` and ``set``)., Write ``<sandbox>/console.yaml`` from the template and return its path., Read the configuration file through konfig and validate warden's section. A… (+13 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "test_password_hibp.py"
Cohesion: 0.20
Nodes (18): _client(), LogCaptureFixture, parametrize, Request, Response, The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed…, Recorder, test_a_digest_must_be_twenty_bytes() (+10 more)

### Community 162 - "Identity"
Cohesion: 0.06
Nodes (76): Identity, FastAPI, warden's identity subsystem for one deployment., Make this Identity the one ``require_user`` and ``require_permission`` use., Run identity's background work (the session and password policy listeners) for…, Delete sign-in throttle records whose window has ended., test_running_also_listens_for_password_policy_changes(), test_the_services_are_attributes_built_at_construction() (+68 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.12
Nodes (17): _load(), _pkg(), ModuleType, parametrize, Path, The licence audit enforces the licence policy for runtime dependencies. No…, test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() (+9 more)

### Community 164 - "pathlib"
Cohesion: 0.07
Nodes (24): pathlib, Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., Question 39 was a defect in the admin route, fixed in warden 0.1.0., test_forbid_user_details_is_no_longer_a_gap(), test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap() (+16 more)

### Community 165 - "PasswordsConfig"
Cohesion: 0.12
Nodes (11): AsyncBaseTransport, AuditConfig, DbConfig, PasswordsConfig, BaseModel, Database settings. At runtime warden uses the product's pool, never this DSN., Audit trail settings., Password policies: the fingerprint key and the breached-password range API.… (+3 more)

### Community 166 - "Outbox"
Cohesion: 0.13
Nodes (10): Outbox, Any, A ``MailSender`` holding the last ``limit`` messages, newest last., The kept messages, newest first, as the outbox page shows them., Scope, ASGI middleware adding the policy and related headers to every HTTP answer., SecurityHeaders, with_headers() (+2 more)

### Community 167 - "subprocess"
Cohesion: 0.13
Nodes (14): subprocess, parametrize, The public import surface, fixed as a snapshot. warden's public API is whatever…, test_every_exported_name_resolves_once(), test_the_public_names_match_the_snapshot(), _device_modules_after(), parametrize, Tripwire: warden uses fido2's relying-party side only, never its device code.… (+6 more)

### Community 169 - "._accept"
Cohesion: 0.15
Nodes (11): Complete, MethodCheck, check(), complete(), PasskeyRegistration, Protocol, The WebAuthn registration, run inside the acceptance transaction. Called with…, Accept with a new password. The password is checked against the invitation's… (+3 more)

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "main"
Cohesion: 0.22
Nodes (17): _dsn(), main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests.…, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database. (+9 more)

### Community 173 - "test_connection_failure_prints_a_fixed_message_and_exits_1"
Cohesion: 0.18
Nodes (13): _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path, One synthetic anchor row, as an NDJSON export holds it. (+5 more)

### Community 174 - "ProviderHttp"
Cohesion: 0.21
Nodes (9): ProviderHttp, Any, AsyncClient, The one HTTP client single sign-on uses to reach the provider. Redirects are…, http(), idp(), metadata(), fixture (+1 more)

### Community 175 - "BaseModel"
Cohesion: 0.25
Nodes (8): AuditEventPage, AuditEventView, BrokenLinkView, ChainVerification, BaseModel, The verification report (documentation only)., One audit row, as listed and as exported in NDJSON (documentation only)., A page of events, newest first (documentation only).

### Community 176 - "test_config_passwords.py"
Cohesion: 0.22
Nodes (18): _parse(), Any, parametrize, Start-up validation of the password settings (rulings PW2, PW7 and PW8 of 10…, _refused(), test_a_fingerprint_key_name_makes_the_fingerprint_available(), test_a_malformed_secret_name_is_refused(), test_a_previous_key_needs_a_current_key() (+10 more)

### Community 177 - "._handle"
Cohesion: 0.31
Nodes (3): Any, Request, Response

### Community 178 - "test_console_source_ip.py"
Cohesion: 0.33
Nodes (13): client(), headers(), Any, AsyncClient, fixture, Response, The sample console's own routes pass the client address, as a product should…, _recorded() (+5 more)

### Community 179 - "timestamp_text"
Cohesion: 0.17
Nodes (13): address_text(), _encode(), _fields(), _number(), Any, datetime, IPv4Address, IPv6Address (+5 more)

### Community 180 - "JwkSet"
Cohesion: 0.40
Nodes (5): JwkSet, OkpJwk, BaseModel, One published key, an RFC 8037 OKP JSON Web Key (documentation only)., An RFC 7517 JWK Set (documentation only).

### Community 181 - "bump_version.py"
Cohesion: 0.27
Nodes (9): _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``., stamp() (+1 more)

### Community 182 - "licence_audit.py"
Cohesion: 0.13
Nodes (17): importlib, packaging_requirements, packaging_utils, packaging_version, audit(), classify(), data_problems(), installed() (+9 more)

### Community 183 - "SignInThrottle"
Cohesion: 0.06
Nodes (35): PasswordPruning, Pruner, PruneReport, Identifier, Protocol, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., What the pruner needs from password policies. (+27 more)

### Community 184 - ".too_soon"
Cohesion: 0.29
Nodes (7): Any, AsyncConnection, datetime, UUID, Keep ``password_hash`` (Argon2id only) as the user's newest previous password., Whether ``password`` matches any of the user's last ``count`` passwords., Whether the current password is younger than ``min_age_hours``.

### Community 185 - "copy"
Cohesion: 0.22
Nodes (9): copy, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1() (+1 more)

### Community 186 - "test_bundled_data.py"
Cohesion: 0.24
Nodes (9): tarfile, built(), fixture, Path, TempPathFactory, The built-in common-password list (ruling PW12) ships in the wheel and the…, test_the_sdist_carries_the_list_and_its_readme(), test_the_wheel_carries_the_list_and_its_readme() (+1 more)

### Community 187 - "ConnectionSource"
Cohesion: 0.18
Nodes (8): ConnectionSource, AbstractAsyncContextManager, Any, AsyncConnection, Protocol, Anything that lends async connections; ``psycopg_pool.AsyncConnectionPool``…, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - "rsa_key"
Cohesion: 0.22
Nodes (8): rsa_key(), SigningKey, Clock, test_discovery_is_cached_for_its_period(), test_jwks_expires_after_its_cache_period(), test_jwks_ignores_symmetric_and_encryption_keys(), test_jwks_refetch_for_unknown_ids_is_rate_limited(), test_jwks_refetches_once_for_an_unknown_key_id()

### Community 191 - "_LazySecrets"
Cohesion: 0.22
Nodes (7): _LazySecrets, _OneConnection, Any, AsyncConnection, A connection source lending a single connection, for one CLI command., konfig ``Secrets``, constructed only if a command actually needs a secret., _rotate()

### Community 192 - "race"
Cohesion: 0.11
Nodes (30): Any, race(), Run ``calls`` as concurrent tasks released together by a barrier. Every task…, _admins(), UserFactory, Role assignments: audited, expiring, and never leaving no administrator., Two administrators demoting each other at once: exactly one demotion succeeds., test_an_administrator_role_cannot_expire() (+22 more)

### Community 193 - "test_console_password_rules.py"
Cohesion: 0.26
Nodes (11): answers(), cases(), node(), Any, fixture, parametrize, TempPathFactory, The browser's password rules against warden's test vectors. The checklist in… (+3 more)

### Community 194 - "tests/conftest.py"
Cohesion: 0.31
Nodes (8): dsn(), migrated_dsn(), pg_admin_url(), pool(), Any, fixture, Shared fixtures. Database tests use a real Postgres through testcontainers., A fresh, empty database for one test.

### Community 195 - "build_sso_settings_router"
Cohesion: 0.14
Nodes (18): build_sso_settings_router(), actor_id(), get_settings(), put_client_secret(), put_settings(), reset_settings(), source(), test_configuration() (+10 more)

### Community 196 - "test_password_fingerprint.py"
Cohesion: 0.36
Nodes (8): _key(), Sealed password fingerprints (ruling PW8): SHA-1 sealed per user, rotating keys., test_a_sealed_fingerprint_does_not_show_its_bytes(), test_rotation_opens_with_the_previous_key_and_reseals_with_the_current(), test_seal_and_open_round_trip_bound_to_the_user(), test_sealing_twice_gives_different_ciphertexts(), test_tampering_or_an_unknown_key_does_not_open(), test_the_digest_is_the_sha1_of_the_password_as_typed()

### Community 197 - "Notes"
Cohesion: 0.10
Nodes (19): _audit(), Note, Notes, notes_router(), create_note(), delete_note(), found(), update_note() (+11 more)

### Community 198 - "_Invalid"
Cohesion: 0.67
Nodes (3): _Invalid, Exception, A policy body refused, with each field at fault and a fixed message.

### Community 199 - "WebAuthnRefusal"
Cohesion: 0.33
Nodes (6): StrEnum, UUID, Why a ceremony, or a change to a credential, was refused., WebAuthnRefusal, BaseException, refusal()

### Community 200 - "AnchorSigner"
Cohesion: 0.24
Nodes (5): AnchorSigner, _KeyLike, Protocol, What anchoring needs from the key store: ``KeyStore`` fits., _SignatureLike

### Community 202 - "keys"
Cohesion: 0.29
Nodes (4): keys(), MemorySecrets, fixture, registry()

### Community 203 - "_structured_data"
Cohesion: 0.33
Nodes (6): _from_syslog(), The parameters of each SD-ELEMENT at the start of ``text`` (RFC 5424 section…, A PARAM-VALUE from ``pos`` up to its closing quote, unescaped., _scan_name(), _scan_value(), _structured_data()

### Community 204 - "escape_cell"
Cohesion: 0.40
Nodes (6): _csv_record(), escape_cell(), ``value``, made safe to open in a spreadsheet., parametrize, test_formula_leading_cells_are_escaped(), test_other_cells_are_unchanged()

### Community 205 - "AnchorCheck"
Cohesion: 0.40
Nodes (4): AnchorCheck, _check_anchor(), result(), The outcome for one external anchor. Carries identifiers only, never row…

### Community 206 - "source_wheel"
Cohesion: 0.40
Nodes (6): dist(), fixture, TempPathFactory, The sdist, and the wheel built from it, as the release workflow builds them., A wheel built straight from the source tree, as `python -m build --wheel` does., source_wheel()

### Community 207 - "matching_step"
Cohesion: 0.50
Nodes (4): matching_step(), parse_code(), ``code`` if it is exactly six ASCII digits, otherwise None., The step within the window whose code is ``code``, or None. Every candidate is…

### Community 208 - ".open_challenge"
Cohesion: 0.50
Nodes (3): _hash_token(), ChallengePurpose, The live challenge ``token`` names, or None. Does not consume it.

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 211 - "FakeSettings"
Cohesion: 0.50
Nodes (3): FakeSettings, Any, A settings source holding one nested tree, as konfig's get_section returns.

### Community 213 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends an acceptance transaction without committing it.

### Community 214 - "fp_identity"
Cohesion: 0.50
Nodes (4): cli_secrets(), fp_identity(), fixture, MemorySecrets

### Community 221 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends a transaction without committing it.

## Knowledge Gaps
- **110 isolated node(s):** `STATUSES`, `METHODS`, `POLICY_FIELDS`, `session`, `listeners` (+105 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1971 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **25 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `test_password_set_points.py`, `SourceIp`, `KeyStore`, `identity_support.py`, `Sessions`, `RecordingSender`, `passkey_support.py`, `require_user`, `contract.py`, `console_router`, `lifecycle.py`, `test_webauthn_mfa.py`, `SingleUseTokens`, `test_password_cli.py`, `SoftwareAuthenticator`, `test_sso_invitations.py`, `test_webauthn_reset.py`, `SingleSignOn`, `AuditEvent`, `test_identity_capabilities.py`, `SignInMethod`, `new_totp_key`, `PasswordHistory`, `Database`, `json_response`, `test_identity_totp_reset.py`, `client_ip`, `current_code`, `test_password_sign_in.py`, `admin.py`, `WardenConfig`, `WebAuthn`, `Mfa`, `test_identity_prune.py`, `FakeIdp`, `SignInThrottle`, `mail.py`, `build_reference_app`, `typing`, `PasswordStates`, `test_identity_apikeys.py`, `PermissionRegistry`, `race`, `build_sso_settings_router`, `pytest`, `PolicyStore`, `test_identity_dependencies.py`, `test_webauthn_live.py`, `test_passkey_registration_link.py`, `build_console`, `test_password_admin_routes.py`, `test_identity_admin_routes.py`, `SecretBox`, `test_sso_capabilities.py`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`, `fp_identity`, `audit_rows`, `test_sso_admin_routes.py`, `identity/__init__.py`, `Roles`, `test_passkey_invitation.py`, `bearer`, `test_identity_lifecycle_routes.py`, `test_sso_source_ip.py`, `parse_config`, `test_sso_issuer.py`, `Cluster: test_identity_client_address.py`, `test_passkey_options_throttle.py`?**
  _High betweenness centrality (0.145) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `KeyStore`, `RecordingSender`, `Sessions`, `AuditRecorder`, `test_webauthn_mfa.py`, `test_audit_recorder.py`, `test_webauthn_reset.py`, `SoftwareAuthenticator`, `test_sso_invitations.py`, `PasswordPolicies`, `SingleSignOn`, `AuditEvent`, `SignInMethod`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `ActionRegistry`, `test_syslog_forwarder.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `WardenConfig`, `WebAuthn`, `SyslogSettings`, `test_identity_prune.py`, `FakeIdp`, `warden/cli.py`, `soft_authenticator.py`, `build_reference_app`, `typing`, `PasswordStates`, `test_identity_apikeys.py`, `PermissionRegistry`, `pytest`, `test_webauthn_live.py`, `PolicyStore`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `build_console`, `test_password_admin_routes.py`, `test_identity_admin_routes.py`, `SecretBox`, `test_key_publication.py`, `test_audit_router.py`, `audit_rows`, `test_sso_admin_routes.py`, `WebAuthnCredentials`, `Challenges`, `test_audit_verify.py`, `identity/__init__.py`, `AuditQuery`, `Roles`, `test_passkey_invitation.py`, `test_identity_lifecycle_routes.py`, `WatchLists`, `test_sso_source_ip.py`, `test_only_the_purger_role_can_purge`, `parse_config`, `test_sso_issuer.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `test_webauthn_credentials.py`, `test_passkey_options_throttle.py`, `test_password_set_points.py`, `identity_support.py`, `passkey_support.py`, `test_password_policy_store.py`, `SingleUseTokens`, `test_password_cli.py`, `test_identity_capabilities.py`, `new_totp_key`, `PasswordHistory`, `Identity`, `SignInThrottle`, `ConnectionSource`, `_LazySecrets`, `race`, `keys`, `fp_identity`?**
  _High betweenness centrality (0.117) - this node is a cross-community bridge._
- **Why does `KeyStore` connect `KeyStore` to `test_passkey_sign_in.py`, `identity_support.py`, `Sessions`, `AuditRecorder`, `passkey_support.py`, `console_router`, `test_identity_capabilities.py`, `new_totp_key`, `Identity`, `test_password_sign_in.py`, `warden/cli.py`, `build_reference_app`, `typing`, `_LazySecrets`, `PolicyStore`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `build_console`, `keys`, `.rotate`, `test_key_publication.py`, `fp_identity`, `audit_rows`, `test_only_the_purger_role_can_purge`, `parse_config`, `Cluster: test_identity_client_address.py`, `test_passkey_options_throttle.py`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Are the 94 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 94 INFERRED edges - model-reasoned connections that need verification._
- **Are the 154 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 154 INFERRED edges - model-reasoned connections that need verification._
- **What connects `STATUSES`, `METHODS`, `POLICY_FIELDS` to the rest of the system?**
  _110 weakly-connected nodes found - possible documentation gaps or missing edges._