# Graph Report - warden  (2026-11-07)

## Corpus Check
- 271 files · ~229,755 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 5, .css 1, .mako 1)

## Summary
- 5372 nodes · 18329 edges · 196 communities (168 shown, 28 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 2343 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `5aaac851`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- typing
- SSO Provider Discovery
- AuditEvent
- Identity Service Operations
- Signing Key Store
- Invitation and Reset Tests
- Identity
- Audit Anchors
- Sample Console Front End
- WebAuthn Second Factor Tests
- Identity HTTP Contract
- SSO Sign-In Flow Tests
- InvitationAcceptance
- Audit Recorder Tests
- Syslog Transport
- WebAuthn Registration Tests
- test_audit_query.py
- SSO Invitation Tests
- WebAuthn Credential Store
- Single Sign-On Service
- Invitations
- WebAuthn Ceremonies
- Audit Anchor Format
- Purpose
- Users and Sign-In Methods
- Second Factor Reset Tests
- Audit Hash Chain
- TOTP Reset Tests
- Configuration
- Auth Router Helpers
- SSO Settings Store
- CI Workflows
- Audit Retention
- Syslog Formatter
- Key Publication (JWKS)
- Password Hashing
- Syslog Forwarder
- Password Resets and Links
- TOTP MFA Tests
- Cluster: test_syslog_transport.py
- Cluster: lifecycle.py
- Cluster: SyslogForwarder
- Cluster: build_admin_router()
- Cluster: test_config_webauthn.py
- Cluster: alembic
- Cluster: warden/cli.py
- Cluster: test_webauthn_authentication.py
- Cluster: pathlib
- Cluster: syslog
- Cluster: Mfa
- test_identity_prune.py
- Cluster: httpx
- Cluster: test_distributions.py
- Cluster: test_config_fields.py
- Cluster: Checkpoint
- Cluster: soft_authenticator.py
- Cluster: Mailer
- Cluster: SecretBox
- Cluster: test_identity_tokens.py
- Cluster: test_sso_sealing.py
- Cluster: console/cli.py
- Cluster: test_identity_apikeys.py
- Cluster: PermissionRegistry
- Cluster: test_proxy.py
- Cluster: identity_support.py
- Cluster: current_revision()
- webauthn.py
- test_webauthn_live.py
- Cluster: Sessions
- scoped_client
- test_passkey_registration_link.py
- app.py
- Cluster: sso.py
- Cluster: PolicyStore
- Cluster: build_console()
- bump_version.py
- identity/__init__.py
- Cluster: test_identity_admin_routes.py
- Cluster: test_webauthn_migration.py
- Cluster: test_cli_audit_anchor.py
- Cluster: test_key_publication.py
- Cluster: test_console_app.py
- Cluster: json
- Cluster: test_openapi_contract.py
- Cluster: psycopg
- Cluster: migrate.py
- Cluster: test_identity_sign_in.py
- Cluster: test_sso_admin_routes.py
- Cluster: Client-behaviour guide
- Cluster: warden design overview
- Cluster: modules()
- Cluster: .sign_in()
- Cluster: test_audit_router.py
- Cluster: test_audit_verify.py
- Cluster: main()
- Cluster: field_validator
- Cluster: test_db_schema.py
- Cluster: asyncio
- Cluster: test_sso_issuer.py
- Cluster: test_sso_preset_label_only.py
- Cluster: .register()
- Cluster: test_syslog_sd_id.py
- Cluster: publish-pypi
- Cluster: WebAuthnConfig
- test_passkey_invitation.py
- test_console_passkeys.py
- Cluster: test_syslog_routes.py
- Cluster: test_identity_lifecycle_routes.py
- Cluster: test_cli_audit_errors.py
- Cluster: test_licence_audit.py
- Cluster: check_dist.py
- Cluster: test_cli.py
- Cluster: Audit hash chain specification
- Cluster: MailMessage
- Cluster: collector.py
- Cluster: test_sso_break_glass_live.py
- Cluster: test_audit_grants.py
- Cluster: grants.py
- Cluster: with
- Cluster: parse_config()
- Cluster: WardenConfig
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- Cluster: SyslogConfig
- Cluster: test_lifecycle_migration.py
- pytest
- Cluster: console_router()
- Cluster: HttpConfig
- Cluster: test_sso_invitation_sealing_migration.py
- provider.py
- Cluster: test_cli_errors.py
- Cluster: test_anchored_patterns.py
- Cluster: licence_audit.py
- forwarder.py
- sso_settings.py
- Cluster: test_sso_invitation_migration.py
- Cluster: test_examples_public_surface.py
- Cluster: require_user()
- Cluster: ast
- router.py
- SingleUseTokens
- ._accept
- Cluster: test_identity_mfa_mail.py
- Cluster: BlackholeCollector
- SyslogSettings
- Cluster: test_no_direct_environment.py
- Cluster: updates
- ActionRegistry
- Cluster: _AfterFirstQuery
- Cluster: test_webauthn_unconfigured.py
- identity/conftest.py
- Cluster: test_tls_fail_closed.py
- examples/conftest.py
- Cluster: test_database.py
- Cluster: verify
- Cluster: _Section
- Cluster: KonfigSecrets
- Cluster: rsyslog
- Cluster: test_client_guide.py
- test_identity_throttle.py
- mail.py
- Cluster: MemorySecrets
- Cluster: types
- Cluster: _Abort
- .consume
- test_webauthn_credentials.py
- Cluster: cognisn-warden
- attestation.py
- subprocess
- ceremony.js
- fastapi
- neutralise
- test_console_gaps.py
- _from_syslog
- .pruning
- PasskeyLinkRefused
- source_wheel
- test_fido2_device_free.py
- Refused
- test_a_key_registered_while_switching_to_sso_only_never_leaves_both
- _Abort
- test_the_import_check_reports_a_module_that_fails
- build
- _load

## God Nodes (most connected - your core abstractions)
1. `Identity` - 497 edges
2. `Database` - 482 edges
3. `KeyStore` - 158 edges
4. `RecordingSender` - 145 edges
5. `audit_rows()` - 143 edges
6. `AuditRecorder` - 130 edges
7. `ActionRegistry` - 129 edges
8. `FakeIdp` - 115 edges
9. `AuditEvent` - 103 edges
10. `WebAuthn` - 99 edges

## Surprising Connections (you probably didn't know these)
- `test_identity_defaults_are_the_values_identity_used_before()` --uses--> `IdentityConfig`  [INFERRED]
  tests/test_config_fields.py → src/warden/config.py
- `test_the_configuration_keeps_the_slash()` --uses--> `WardenConfig`  [INFERRED]
  tests/identity/sso/test_sso_issuer.py → src/warden/config.py
- `test_every_forwarder_setting_has_a_config_counterpart()` --uses--> `SyslogConfig`  [INFERRED]
  tests/test_config_fields.py → src/warden/config.py
- `test_a_run_time_issuer_keeps_the_slash()` --uses--> `SingleSignOn`  [INFERRED]
  tests/identity/sso/test_sso_issuer.py → src/warden/identity/sso/service.py
- `test_event_defaults_to_now_in_utc()` --calls--> `AuditEvent`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/events.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Audit tamper-evidence mechanisms** — docs_design_audit_chain_audit_hash_chain, docs_design_audit_chain_retention_checkpoint, docs_design_audit_chain_anchor, docs_design_audit_chain_audit_database_roles, docs_design_overview_tamper_evidence [EXTRACTED 1.00]
- **Release and publication pipeline** — docs_releasing_bump_version, github_workflows_publish, docs_releasing_check_dist, docs_releasing_trusted_publishing, claude_integration_procedure [EXTRACTED 1.00]
- **Tripwire tests guarding architecture rules** — docs_design_overview_single_audit_writer, docs_design_overview_audit_independence, examples_console_readme_public_surface_tripwire, claude_mutation_checked_guards [INFERRED 0.85]

## Communities (196 total, 28 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.10
Nodes (45): expire_challenge_of(), give_passkey(), http_client(), passkey_app(), passkey_assertion(), passkey_config(), passkey_options(), passkey_sign_in() (+37 more)

### Community 1 - "typing"
Cohesion: 0.05
Nodes (22): _now(), Severity, AuditChainConflict, get_recorder(), _check_summary(), register_warden_action(), table(), register_actions() (+14 more)

### Community 2 - "SSO Provider Discovery"
Cohesion: 0.07
Nodes (50): Discovery, JwksCache, ProviderHttp, ProviderMetadata, IdTokenValidator, _Drop, ec_key(), FakeIdp (+42 more)

### Community 3 - "AuditEvent"
Cohesion: 0.11
Nodes (6): AuditEvent, ActionSpec, AuditSink, complete(), test_summary_renders_from_the_event(), test_summary_renders_missing_fields_as_a_dash()

### Community 4 - "Identity Service Operations"
Cohesion: 0.05
Nodes (10): Principal, Challenge, _Account, _credential_id(), _link_refusal(), SignInResult, WebAuthnEnrolled, TokenPair (+2 more)

### Community 5 - "Signing Key Store"
Cohesion: 0.07
Nodes (43): KeysConfig, _b64url(), _b64url_decode(), KeyStore, KeyStoreError, PublicKey, _raw_public(), _row_to_key() (+35 more)

### Community 6 - "Invitation and Reset Tests"
Cohesion: 0.10
Nodes (35): StagedGrant, VerifiedIdentity, RecordingSender, _accept(), FakePins, _invite(), _status(), test_a_bad_token_is_refused_and_audited() (+27 more)

### Community 7 - "Identity"
Cohesion: 0.04
Nodes (60): Identity, test_a_key_is_prefixed_and_stored_only_as_its_hash(), test_revoking_a_key(), _app(), _bearer(), test_a_scoped_permission_without_a_hook_fails_closed(), test_require_permission(), test_require_user() (+52 more)

### Community 8 - "Audit Anchors"
Cohesion: 0.10
Nodes (46): AnchorRecord, AuditRecorder, verify_anchors(), age(), rechain(), stored(), _aged_then_anchored(), _anchor() (+38 more)

### Community 9 - "Sample Console Front End"
Cohesion: 0.12
Nodes (87): apiKeysScreen(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames(), ssoScreen() (+79 more)

### Community 10 - "WebAuthn Second Factor Tests"
Cohesion: 0.12
Nodes (52): _amr(), _app(), _assertion(), _bearer(), _challenge(), http(), _key_sign_in(), _options() (+44 more)

### Community 11 - "Identity HTTP Contract"
Cohesion: 0.06
Nodes (51): require_permission(), LastAdministratorError, RoleError, _BadRequest, build_admin_router(), list_roles(), ChallengeBody, ChangePasswordBody (+43 more)

### Community 12 - "SSO Sign-In Flow Tests"
Cohesion: 0.11
Nodes (52): User, callback(), completion(), handoff(), provider_code(), sign_in(), start(), alice() (+44 more)

### Community 13 - "InvitationAcceptance"
Cohesion: 0.18
Nodes (4): PasskeyRegistration, SubjectPin, InvitationAcceptance, SecretWriter

### Community 14 - "Audit Recorder Tests"
Cohesion: 0.14
Nodes (23): set_recorder(), BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), RecordingSink, registry() (+15 more)

### Community 15 - "Syslog Transport"
Cohesion: 0.05
Nodes (18): format_test_message(), _header_field(), _timestamp(), send_test_message(), syslog_test(), TestSendResult, classify_error(), frame() (+10 more)

### Community 16 - "WebAuthn Registration Tests"
Cohesion: 0.15
Nodes (37): SoftwareAuthenticator, _refused(), test_a_credential_with_rk_reported_is_discoverable(), test_a_malformed_registration_is_refused(), test_a_passkey_reported_as_not_discoverable_is_refused(), test_a_refused_response_uses_its_challenge_up(), test_a_registration_round_trip(), test_a_replayed_registration_is_refused() (+29 more)

### Community 17 - "test_audit_query.py"
Cohesion: 0.14
Nodes (13): AuditQuery, list_events(), _collect(), _ids(), registry(), test_a_large_export_streams_across_batches(), test_an_empty_or_inverted_time_range_is_refused(), test_an_export_is_itself_audited_before_it_streams() (+5 more)

### Community 18 - "SSO Invitation Tests"
Cohesion: 0.12
Nodes (43): Database, Started, accept(), acceptance_rows(), app(), _bodies(), config(), handoffs_of() (+35 more)

### Community 19 - "WebAuthn Credential Store"
Cohesion: 0.09
Nodes (8): WebAuthnRefusal, WebAuthnAssertion, WebAuthnPurpose, WebAuthnRegistration, check_nickname(), credential_from_row(), WebAuthnCredential, WebAuthnCredentials

### Community 20 - "Single Sign-On Service"
Cohesion: 0.09
Nodes (13): _hash(), _PinRefused, SecretReader, SingleSignOn, pin(), _token(), IdTokenClaims, race() (+5 more)

### Community 21 - "Invitations"
Cohesion: 0.18
Nodes (4): Invitation, InvitationError, Invitations, _Invitee

### Community 22 - "WebAuthn Ceremonies"
Cohesion: 0.11
Nodes (6): WebAuthnError, _extension_results(), _parse(), _reported_resident_key(), _Stored, _transports()

### Community 23 - "Audit Anchor Format"
Cohesion: 0.10
Nodes (29): Anchor, _b64url(), _b64url_decode(), _from_ndjson(), _int(), MalformedAnchor, read_anchors(), _row_id() (+21 more)

### Community 24 - "Purpose"
Cohesion: 0.16
Nodes (6): IssuedToken, _live_token(), LiveToken, Purpose, token_hash(), test_malformed_tokens_are_refused_cleanly()

### Community 25 - "Users and Sign-In Methods"
Cohesion: 0.09
Nodes (7): record_audit(), lock_administrators(), check_email(), _row_to_user(), SignInMethodConflict, UserError, Users

### Community 26 - "Second Factor Reset Tests"
Cohesion: 0.18
Nodes (14): _admin(), _bearer(), http(), _register(), _state(), test_a_reset_between_storing_a_key_and_its_codes_leaves_neither(), reset_meanwhile(), test_a_reset_is_idempotent_and_still_audited() (+6 more)

### Community 27 - "Audit Hash Chain"
Cohesion: 0.08
Nodes (28): address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields(), _number(), row_hash() (+20 more)

### Community 28 - "TOTP Reset Tests"
Cohesion: 0.10
Nodes (31): audit_rows(), _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), _signed_in() (+23 more)

### Community 29 - "Configuration"
Cohesion: 0.11
Nodes (42): ConfigError, FakeSecrets, FakeSettings, _load(), _sso_tree(), test_audit_only_deployment_needs_no_link_templates(), test_complete_sso_configuration_loads(), test_configuration_is_immutable() (+34 more)

### Community 30 - "Auth Router Helpers"
Cohesion: 0.10
Nodes (45): json_response(), read_object(), refusal(), build_auth_router(), begin_enrolment(), change_password(), confirm_enrolment(), passkey_options() (+37 more)

### Community 31 - "SSO Settings Store"
Cohesion: 0.10
Nodes (20): _from_config(), _plain(), revoke_sso_sessions(), SsoSettings, SsoSettingsError, SsoSettingsStore, _typed(), config() (+12 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "Audit Retention"
Cohesion: 0.08
Nodes (33): Checkpoint, CheckpointSigner, _KeyLike, purge(), _purge_prefix(), RetentionError, _SignatureLike, verify_chain() (+25 more)

### Community 34 - "Syslog Formatter"
Cohesion: 0.19
Nodes (26): AuditRecord, _clip(), format_message(), _oversized(), _parse(), _record(), _settings(), test_a_message_under_the_cap_is_not_marked_truncated() (+18 more)

### Community 35 - "Key Publication (JWKS)"
Cohesion: 0.07
Nodes (21): build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), reference_config(), render() (+13 more)

### Community 36 - "Password Hashing"
Cohesion: 0.14
Nodes (11): Verification, _verify_legacy(), _legacy(), test_argon2_hash_verifies_the_right_password_only(), test_argon2_hash_with_weaker_parameters_needs_rehash(), test_dummy_verify_never_succeeds(), test_legacy_pbkdf2_verifies_and_always_needs_rehash(), test_malformed_hashes_fail_closed() (+3 more)

### Community 37 - "Syslog Forwarder"
Cohesion: 0.20
Nodes (32): _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader(), _raw_insert() (+24 more)

### Community 38 - "Password Resets and Links"
Cohesion: 0.14
Nodes (5): AuthenticationRefused, _Account, PasswordResets, _refusal(), PasskeyInvitationAccepted

### Community 39 - "TOTP MFA Tests"
Cohesion: 0.14
Nodes (26): current_code(), _challenge(), _enrolled(), _fresh_code(), test_a_challenge_completes_at_most_one_sign_in(), test_a_challenge_dies_after_five_wrong_codes(), test_a_code_is_accepted_once_per_step(), test_a_recovery_code_is_not_used_up_when_the_challenge_is_lost() (+18 more)

### Community 40 - "Cluster: test_syslog_transport.py"
Cohesion: 0.11
Nodes (24): open_transport(), main(), Authority, Issued, _key_pem(), _name(), server_context(), main() (+16 more)

### Community 41 - "Cluster: lifecycle.py"
Cohesion: 0.15
Nodes (13): _inline(), resolve(), InvitationAcceptBody, json_body(), PasskeyRegistrationBody, PasskeyTokenBody, ResetCompleteBody, ResetRequestBody (+5 more)

### Community 43 - "Cluster: build_admin_router()"
Cohesion: 0.16
Nodes (30): _api_key(), _assignment(), assign_role(), create_key(), invite(), list_invitations(), list_keys(), list_users() (+22 more)

### Community 44 - "Cluster: test_config_webauthn.py"
Cohesion: 0.11
Nodes (33): _certificate(), _parse(), _refused(), _Secrets, test_a_malformed_passkey_registration_link_is_refused(), test_a_malformed_rp_id_is_refused(), test_a_malformed_rp_name_is_refused(), test_a_registrable_suffix_of_the_origin_host_is_accepted() (+25 more)

### Community 45 - "Cluster: alembic"
Cohesion: 0.06
Nodes (4): _run(), upgrade(), upgrade(), upgrade()

### Community 46 - "Cluster: warden/cli.py"
Cohesion: 0.08
Nodes (26): register_audit_actions(), AnchorError, ExternalAnchor, PurgeResult, AnchorReport, VerificationReport, _anchor_actor(), _audit() (+18 more)

### Community 47 - "Cluster: test_webauthn_authentication.py"
Cohesion: 0.19
Nodes (30): WebAuthn, _enrolled(), _refused(), test_a_counter_that_does_not_increase_is_a_suspected_clone(), test_a_counter_that_increases_is_accepted_and_stored(), test_a_discoverable_passkey_round_trip(), test_a_discoverable_sign_in_always_requires_user_verification(), test_a_discoverable_sign_in_needs_the_owners_user_handle() (+22 more)

### Community 48 - "Cluster: pathlib"
Cohesion: 0.15
Nodes (9): _targets(), test_every_link_is_absolute(), test_link_check_refuses_relative_link_and_image(), test_readme_has_links(), _blocks(), test_dependabot_watches_github_actions_weekly(), _references(), test_every_action_is_pinned_to_a_commit_sha() (+1 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Cluster: Mfa"
Cohesion: 0.08
Nodes (10): Mfa, code_at(), generate_recovery_codes(), generate_secret(), hash_recovery_code(), matching_step(), parse_code(), parse_recovery_code() (+2 more)

### Community 51 - "test_identity_prune.py"
Cohesion: 0.18
Nodes (10): _count(), _expire_all(), _fixtures(), test_a_failed_run_does_not_stop_the_schedule(), test_a_used_refresh_token_is_kept_until_it_expires(), test_ended_throttle_windows_are_pruned(), test_expired_rows_are_pruned_and_live_ones_kept(), test_pruning_runs_on_a_schedule() (+2 more)

### Community 52 - "Cluster: httpx"
Cohesion: 0.14
Nodes (13): sso_config(), accept_through_sso(), test_live_invitation_accepted_through_sso_then_sign_in_by_subject(), app(), browser_to_idp(), config(), provider_login(), reasons() (+5 more)

### Community 53 - "Cluster: test_distributions.py"
Cohesion: 0.21
Nodes (17): _only(), _sdist(), test_a_directory_with_two_wheels_or_no_sdist_fails(), test_a_minimal_good_wheel_and_sdist_pass(), test_a_version_other_than_the_expected_one_fails(), test_a_wheel_built_from_source_holds_only_the_warden_package(), test_a_wheel_missing_a_required_file_fails(), test_a_wheel_with_anything_outside_warden_fails() (+9 more)

### Community 54 - "Cluster: test_config_fields.py"
Cohesion: 0.13
Nodes (26): _parse(), _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart(), test_from_config_carries_every_field(), test_from_config_refuses_a_ca_secret_it_cannot_read(), test_from_config_uses_the_local_host_name_when_none_is_configured() (+18 more)

### Community 55 - "Cluster: Checkpoint"
Cohesion: 0.07
Nodes (18): _b64url(), _b64url_decode(), HistoricalVerifier, _int(), MalformedCheckpoint, _str(), AuditPage, iter_events() (+10 more)

### Community 56 - "Cluster: soft_authenticator.py"
Cohesion: 0.13
Nodes (13): ca(), make_webauthn(), factory(), rogue_ca(), strict_webauthn(), webauthn(), webauthn_config(), _certificate() (+5 more)

### Community 57 - "Cluster: Mailer"
Cohesion: 0.22
Nodes (16): MailConfig, Mailer, MailKind, test_a_delivery_failure_is_reported_without_the_sender_s_detail(), test_a_missing_template_package_fails_at_start_up(), test_a_product_template_replaces_warden_s_template_by_template(), test_a_template_that_is_not_a_mail_template_fails_at_start_up(), test_default_invitation() (+8 more)

### Community 58 - "Cluster: SecretBox"
Cohesion: 0.13
Nodes (12): _decode(), SecretBox, SecretKeyError, _key(), test_a_malformed_previous_key_fails_too(), test_a_missing_or_malformed_key_fails_at_start_up(), test_a_sealed_secret_is_bound_to_its_context(), test_each_seal_uses_a_fresh_nonce() (+4 more)

### Community 59 - "Cluster: test_identity_tokens.py"
Cohesion: 0.15
Nodes (24): _b64(), _parts(), _signed_in(), test_a_refresh_token_never_outlives_its_session(), test_a_retired_key_refuses_live_tokens(), test_a_revoked_key_refuses_live_tokens(), test_access_token_carries_kid_and_claims(), test_an_expired_access_token_is_refused() (+16 more)

### Community 60 - "Cluster: test_sso_sealing.py"
Cohesion: 0.13
Nodes (17): _derive_key(), open_invitation(), seal_invitation(), binding(), _sha(), state_hash(), test_a_database_reader_cannot_open_it(), test_a_sealed_token_opens_with_its_binding_and_state() (+9 more)

### Community 61 - "Cluster: console/cli.py"
Cohesion: 0.10
Nodes (21): create_administrator(), _create_admin(), work(), _dsn(), _init(), main(), _parser(), _run() (+13 more)

### Community 62 - "Cluster: test_identity_apikeys.py"
Cohesion: 0.17
Nodes (14): _app(), _bearer(), client(), _reasons(), test_a_key_cannot_sign_out_or_change_a_password(), test_a_key_expires_within_the_configured_maximum(), test_a_key_is_accepted_by_require_user_and_require_permission(), test_a_key_is_refused_once_its_user_is_inactive() (+6 more)

### Community 63 - "Cluster: PermissionRegistry"
Cohesion: 0.13
Nodes (11): PermissionRegistry, registry(), test_a_role_may_only_use_registered_permissions(), test_administrator_roles_are_listed(), test_permission_names_are_dotted_lower_case(), test_permissions_for_several_roles_are_the_union(), test_redefinition_must_match(), test_role_names_are_validated() (+3 more)

### Community 64 - "Cluster: test_proxy.py"
Cohesion: 0.12
Nodes (15): _address(), resolve_client_ip(), _trusted(), TrustedProxyMiddleware, _App, _noop(), _scope(), test_middleware_ignores_other_forwarding_headers() (+7 more)

### Community 65 - "Cluster: identity_support.py"
Cohesion: 0.11
Nodes (20): new_totp_key(), make_config(), MemorySecrets, test_keys_may_be_unexpiring_when_no_maximum_is_set(), test_the_configured_prefix_is_used(), _identity(), test_the_challenge_failure_limit_comes_from_configuration(), test_the_challenge_lifetime_comes_from_configuration() (+12 more)

### Community 66 - "Cluster: current_revision()"
Cohesion: 0.15
Nodes (18): heads(), migrate(), _columns(), _objects_outside_warden(), _tables(), test_a_revoked_key_must_also_be_retired(), test_baseline_signing_key_constraints(), test_chain_has_a_single_head() (+10 more)

### Community 67 - "webauthn.py"
Cohesion: 0.13
Nodes (14): EnrolmentBody, WardenSignedIn, WardenSignedInAfterEnrolment, WardenSignedInAfterWebAuthnRegistration, WardenWebAuthnCredentialEnvelope, WardenWebAuthnCredentialList, WardenWebAuthnOptions, WardenWebAuthnRegistrationConfirmed (+6 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.07
Nodes (24): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+16 more)

### Community 69 - "Cluster: Sessions"
Cohesion: 0.13
Nodes (6): AccessClaims, _b64(), _hash(), _json(), Sessions, _unb64()

### Community 70 - "scoped_client"
Cohesion: 0.25
Nodes (4): CaseScope, scope(), scoped_client(), test_scoped_permission_consults_the_product_hook()

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.19
Nodes (28): assert_refused(), admin(), config(), _credential_count(), http(), _identity(), _link(), _options() (+20 more)

### Community 72 - "app.py"
Cohesion: 0.05
Nodes (15): _audit(), Note, NoteBody, Notes, notes_router(), create_note(), delete_note(), found() (+7 more)

### Community 73 - "Cluster: sso.py"
Cohesion: 0.18
Nodes (16): HandoffBody, SsoInvitationBody, _body_field(), build_sso_router(), callback(), clear_cookie(), failed(), handoff() (+8 more)

### Community 74 - "Cluster: PolicyStore"
Cohesion: 0.13
Nodes (3): PolicyError, PolicyStore, SessionPolicy

### Community 75 - "Cluster: build_console()"
Cohesion: 0.08
Nodes (8): actor(), build_console(), Console, _mount_pages(), work(), permissions(), register_actions(), ConnectionSource

### Community 76 - "bump_version.py"
Cohesion: 0.27
Nodes (4): _current_branch(), main(), stamp(), StampRefused

### Community 77 - "identity/__init__.py"
Cohesion: 0.04
Nodes (23): IdentityConfig, ApiKey, ApiKeyError, ApiKeys, _hash(), NewApiKey, _row_to_key(), SecretStore (+15 more)

### Community 78 - "Cluster: test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (19): admin(), app(), _bearer(), client(), test_an_undeliverable_invitation_is_a_502(), test_api_keys_are_created_listed_and_revoked(), test_bad_api_keys_are_refused(), test_bad_invitations_are_refused() (+11 more)

### Community 79 - "Cluster: test_webauthn_migration.py"
Cohesion: 0.22
Nodes (17): _challenge(), _credential(), _refused(), _revisions(), _tables(), test_a_counter_at_the_32_bit_ceiling_is_stored(), test_a_credential_round_trips_and_its_id_is_unique(), test_a_user_handle_is_64_bytes_and_unique() (+9 more)

### Community 80 - "Cluster: test_cli_audit_anchor.py"
Cohesion: 0.19
Nodes (16): _dsn(), main(), _export(), FakeSecrets, FakeSettings, secrets(), _seed(), _settings() (+8 more)

### Community 81 - "Cluster: test_key_publication.py"
Cohesion: 0.16
Nodes (16): client(), FakeSecrets, _kids(), secrets(), store(), test_a_retired_key_is_published_only_for_historical_verification(), test_a_revoked_key_is_never_published(), test_a_rotated_key_is_published_at_once() (+8 more)

### Community 82 - "Cluster: test_console_app.py"
Cohesion: 0.18
Nodes (19): assert_strict_csp(), bearer(), make_user(), sign_in(), link_token(), static_files(), test_a_password_sign_in_round_trip(), test_a_product_route_refused_without_its_permission_and_allowed_with_it() (+11 more)

### Community 83 - "Cluster: json"
Cohesion: 0.16
Nodes (17): csv_lines(), _csv_record(), escape_cell(), ndjson_lines(), row_to_json(), list_audit_events(), test_the_session_id_is_never_in_the_body(), _collect() (+9 more)

### Community 84 - "Cluster: test_openapi_contract.py"
Cohesion: 0.13
Nodes (12): document(), _load(), _operations(), test_every_documented_response_has_a_description(), test_every_json_body_route_documents_its_request_body(), test_every_operation_documents_a_failure_response(), test_every_operation_has_a_summary_a_description_and_a_tag(), test_routes_that_refuse_uniformly_point_at_the_uniform_refusal() (+4 more)

### Community 85 - "Cluster: psycopg"
Cohesion: 0.19
Nodes (9): _tables(), test_a_used_step_requires_a_confirmed_enrolment(), test_deleting_a_user_removes_their_identity_rows(), test_email_is_unique_regardless_of_case(), test_identity_migration_downgrades_and_upgrades_again(), test_identity_tables_exist_at_head(), test_sealed_totp_secret_length_is_checked(), test_user_constraints() (+1 more)

### Community 86 - "Cluster: migrate.py"
Cohesion: 0.12
Nodes (11): _config(), downgrade(), migrate_connection(), _sqlalchemy_url(), _tables(), test_a_subject_is_pinned_to_one_user(), test_a_user_has_at_most_one_pin(), test_constraints() (+3 more)

### Community 87 - "Cluster: test_identity_sign_in.py"
Cohesion: 0.20
Nodes (13): _assert_refusal(), _refusal_cases(), _sign_in(), test_a_failed_legacy_sign_in_keeps_the_legacy_hash(), test_an_identifier_that_is_not_an_email_address_is_not_audited(), test_an_unconfirmed_enrolment_is_not_mfa(), test_confirmed_totp_turns_sign_in_into_a_challenge(), test_every_sign_in_failure_is_byte_identical() (+5 more)

### Community 88 - "Cluster: test_sso_admin_routes.py"
Cohesion: 0.17
Nodes (14): app(), authorise(), config(), idp(), test_a_bad_client_secret_is_refused(), test_an_invalid_change_names_the_field(), test_disabling_through_the_route_ends_sso_sessions(), test_every_route_needs_the_product_authorisation() (+6 more)

### Community 89 - "Cluster: Client-behaviour guide"
Cohesion: 0.13
Nodes (22): warden changelog, Passkey sign-in and passkey_only method (0.1.0b11), WebAuthn security keys and passkeys as second factor (0.1.0b10), OIDC single sign-on with PKCE, pre-provisioned accounts, HTTP contract docs/contract/openapi.json, Rotating refresh-token families with reuse detection, Trusted-proxy middleware, Administrator's MFA and TOTP reset (+14 more)

### Community 90 - "Cluster: warden design overview"
Cohesion: 0.11
Nodes (12): fido2 runtime dependency (0.1.0b9), Integration procedure (merge, re-chain, stamp), warden project working agreement (CLAUDE.md), Acceptance tests from Termograph hardening findings, Delivery plan milestones M0 to M6, Cache invalidation over Postgres LISTEN/NOTIFY, record_audit single writer tripwire, Termograph (design reference and v0.8.0 adopter) (+4 more)

### Community 91 - "Cluster: modules()"
Cohesion: 0.19
Nodes (12): _docstring_nodes(), identifiers(), module_name(), modules(), string_literals(), _matching(), test_no_module_edits_audit_rows(), test_only_the_retention_purge_deletes_audit_rows() (+4 more)

### Community 92 - "Cluster: .sign_in()"
Cohesion: 0.09
Nodes (7): Pruner, PruneReport, scheduled(), loop(), passkey_keys(), SignInThrottle, throttle_key()

### Community 93 - "Cluster: test_audit_router.py"
Cohesion: 0.16
Nodes (15): client(), exporter(), NoKeys, reader(), registry(), test_an_unknown_export_format_is_refused_and_not_audited(), test_csv_export_is_audited_with_actor_and_real_client_address(), test_every_route_needs_the_products_authorisation() (+7 more)

### Community 94 - "Cluster: test_audit_verify.py"
Cohesion: 0.19
Nodes (13): ids(), NoKeys, registry(), _sql(), test_altering_any_column_names_that_row(), test_an_empty_trail_verifies(), test_an_intact_chain_verifies(), test_deleting_a_row_names_the_row_after_it() (+5 more)

### Community 95 - "Cluster: main()"
Cohesion: 0.24
Nodes (11): FakeSecrets, FakeSettings, _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up(), test_purge_below_the_minimum_is_refused(), test_purge_uses_the_configured_retention_and_signs_a_checkpoint(), test_purge_with_nothing_old_enough() (+3 more)

### Community 96 - "Cluster: field_validator"
Cohesion: 0.13
Nodes (3): _check_secret_name(), _check_url(), SsoConfig

### Community 97 - "Cluster: test_db_schema.py"
Cohesion: 0.11
Nodes (7): _lock_keys(), _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range(), test_every_allocated_key_is_recorded_in_the_allocation_table(), test_no_module_defines_a_schema_name_of_its_own(), test_the_scan_finds_every_known_lock_key()

### Community 98 - "Cluster: asyncio"
Cohesion: 0.17
Nodes (9): dsn(), migrated_dsn(), pg_admin_url(), pool(), run(), _lines_with(), test_the_forwarder_delivers_to_a_real_collector(), test_tls_to_a_real_collector_fails_closed_with_the_wrong_ca() (+1 more)

### Community 99 - "Cluster: test_sso_issuer.py"
Cohesion: 0.16
Nodes (14): alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer(), _refusals() (+6 more)

### Community 100 - "Cluster: test_sso_preset_label_only.py"
Cohesion: 0.19
Nodes (13): imported_modules(), Module, _names_identity(), test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations(), preset_names(), scanned() (+5 more)

### Community 101 - "Cluster: .register()"
Cohesion: 0.15
Nodes (3): _new_key(), _sign(), StoredCredential

### Community 102 - "Cluster: test_syslog_sd_id.py"
Cohesion: 0.15
Nodes (11): SyslogConfig, _config(), _sd_ids(), test_a_product_override_is_honoured(), test_config_and_settings_default_to_warden_at_67382(), test_start_up_no_longer_requires_an_sd_id_when_syslog_is_enabled(), test_start_up_still_requires_host_and_port_when_syslog_is_enabled(), test_the_default_appears_in_the_test_message() (+3 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "Cluster: WebAuthnConfig"
Cohesion: 0.13
Nodes (5): _base_origin(), _check_origin(), _is_domain(), _serialise_origin(), WebAuthnConfig

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (22): passkey_authenticator(), _accept(), admin(), config(), http(), _invite(), _options(), _status() (+14 more)

### Community 106 - "test_console_passkeys.py"
Cohesion: 0.18
Nodes (21): authenticator(), amr(), browser(), link_token(), outbox_message(), passkey_sign_in(), register_key(), test_a_key_is_offered_beside_the_code_when_mfa_is_required() (+13 more)

### Community 107 - "Cluster: test_syslog_routes.py"
Cohesion: 0.14
Nodes (12): syslog_router(), split_frames(), StreamCollector, _audit_rows(), authorise(), _client(), collector(), _settings() (+4 more)

### Community 108 - "Cluster: test_identity_lifecycle_routes.py"
Cohesion: 0.21
Nodes (11): app(), client(), test_a_bad_invitation_gets_the_uniform_refusal(), test_a_bad_reset_token_gets_the_uniform_refusal(), test_a_failed_send_still_answers_the_same(), test_a_non_json_body_gets_the_uniform_refusal(), test_a_password_for_an_sso_only_invitation_is_a_409(), test_a_reset_request_looks_the_same_whoever_asks() (+3 more)

### Community 109 - "Cluster: test_cli_audit_errors.py"
Cohesion: 0.19
Nodes (8): _anchors_file(), FakeSecrets, FakeSettings, _settings(), test_anchor_refuses_an_actor_too_long_to_forward_whole(), test_connection_failure_prints_a_fixed_message_and_exits_1(), test_grants_prints_sql_without_needing_a_database(), test_grants_refuses_a_shared_role()

### Community 110 - "Cluster: test_licence_audit.py"
Cohesion: 0.12
Nodes (12): _load(), _pkg(), test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception(), test_an_unnamed_weak_copyleft_package_fails(), test_audit_walks_the_runtime_tree_and_reports_copyleft(), test_both_named_exceptions_pass(), test_fido2s_declared_licences_need_the_named_exception() (+4 more)

### Community 111 - "Cluster: check_dist.py"
Cohesion: 0.20
Nodes (7): dist_problems(), import_problems(), main(), _metadata_version(), sdist_problems(), source_version(), wheel_problems()

### Community 112 - "Cluster: test_cli.py"
Cohesion: 0.18
Nodes (11): current_revision(), FakeSecrets, FakeSettings, _settings(), test_console_script_runs_migrate_from_a_config_file(), test_invalid_configuration_fails_before_doing_anything(), test_keys_rotate_adds_a_key_and_prints_only_its_id(), test_keys_rotate_twice_keeps_both_keys() (+3 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (15): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+7 more)

### Community 114 - "Cluster: MailMessage"
Cohesion: 0.14
Nodes (4): with_headers(), MailMessage, FailingSender, RecordingSender

### Community 115 - "Cluster: collector.py"
Cohesion: 0.27
Nodes (3): UdpCollector, _UdpProtocol, test_udp_sends_one_message_per_datagram_without_framing()

### Community 116 - "Cluster: test_sso_break_glass_live.py"
Cohesion: 0.09
Nodes (10): _local_hostname(), app(), config(), secrets(), test_an_invitation_completes_with_a_password_while_sso_fails(), test_password_sign_in_works_while_sso_fails(), test_the_provider_is_stopped(), test_malformed_codes_are_refused_cleanly() (+2 more)

### Community 117 - "Cluster: test_audit_grants.py"
Cohesion: 0.21
Nodes (10): _as(), MemorySecrets, _pool(), _refused(), _registry(), test_only_the_purger_role_can_purge(), test_the_application_role_cannot_edit_or_delete_audit_rows(), test_the_application_role_keeps_its_other_tables() (+2 more)

### Community 118 - "Cluster: grants.py"
Cohesion: 0.28
Nodes (8): append_only_grants(), _application(), _forwarder(), grants_sql(), _ident(), _purger(), _reset(), roles()

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "Cluster: parse_config()"
Cohesion: 0.19
Nodes (7): _format_errors(), load_config(), parse_config(), _resolve_secrets(), SecretSource, SettingsSource, _split_list()

### Community 121 - "Cluster: WardenConfig"
Cohesion: 0.22
Nodes (10): WardenConfig, _store(), test_a_change_reaches_another_replica_promptly(), test_defaults_come_from_configuration(), test_inconsistent_updates_are_refused(), test_reset_returns_to_configuration(), test_running_starts_and_stops_the_listener(), test_update_is_stored_and_audited() (+2 more)

### Community 122 - "test_audit_chain_recorder.py"
Cohesion: 0.18
Nodes (21): _assert_one_unforked_chain(), _event(), _raw_insert(), _stored(), test_a_later_writer_never_commits_before_an_earlier_one(), second_writer(), test_a_stale_repeatable_read_snapshot_fails_closed_rather_than_forking(), test_chain_hashes_are_required_and_32_bytes() (+13 more)

### Community 123 - "Cluster: test_identity_client_address.py"
Cohesion: 0.29
Nodes (10): app(), config(), _source_ips(), test_a_spoofed_header_from_an_untrusted_peer_is_ignored_in_the_audit_record(), test_a_spoofed_header_from_an_untrusted_peer_is_ignored_in_the_throttle_key(), test_the_rightmost_untrusted_entry_from_a_trusted_proxy_is_recorded(), test_two_clients_behind_one_proxy_are_throttled_separately(), untrusted() (+2 more)

### Community 124 - "Cluster: publish.yml"
Cohesion: 0.14
Nodes (14): check_dist.py distribution checks, Releasing warden procedure, PyPI trusted publishing (no tokens), concurrency, cancel-in-progress, group, name, on (+6 more)

### Community 127 - "Cluster: test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (10): _lifecycle_revisions(), _tables(), test_a_single_use_token_cannot_expire_before_it_is_created(), test_a_token_is_either_consumed_or_revoked_never_both(), test_api_key_constraints(), test_deleting_a_user_removes_their_tokens_grants_and_keys(), test_downgrade_removes_only_the_lifecycle_tables(), test_lifecycle_tables_exist_at_head() (+2 more)

### Community 128 - "pytest"
Cohesion: 0.09
Nodes (22): test_dependencies_need_an_installed_identity(), test_inviting_an_existing_address_is_refused(), test_action_names_are_validated(), test_conflicting_registration_fails(), test_event_defaults_to_now_in_utc(), test_event_details_must_be_json(), test_event_is_immutable(), test_event_outcome_is_constrained() (+14 more)

### Community 129 - "Cluster: console_router()"
Cohesion: 0.18
Nodes (7): _anchor_report(), console_router(), change_policy(), check_anchors(), reset_policy(), show_policy(), _policy()

### Community 131 - "Cluster: test_sso_invitation_sealing_migration.py"
Cohesion: 0.20
Nodes (13): _columns(), _constraints(), test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(), test_head_includes_the_chain_revision(), test_upgrade_refuses_unchained_rows(), _columns(), _insert(), _revisions() (+5 more)

### Community 132 - "provider.py"
Cohesion: 0.12
Nodes (8): SsoError, _basic(), _https(), _KeySet, parse_metadata(), _strings(), _usable(), _number()

### Community 133 - "Cluster: test_cli_errors.py"
Cohesion: 0.24
Nodes (5): FakeSecrets, FakeSettings, _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1(), test_migrate_connection_failure_prints_a_fixed_message_and_exits_1()

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (7): _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), test_dollar_detection(), test_no_anchored_pattern_relies_on_match_or_dollar(), test_the_scan_sees_the_patterns_it_guards()

### Community 135 - "Cluster: licence_audit.py"
Cohesion: 0.27
Nodes (7): audit(), classify(), installed(), main(), _one(), Package, Report

### Community 136 - "forwarder.py"
Cohesion: 0.12
Nodes (7): initialise_cursor(), load_cursor(), store_cursor(), ForwarderSnapshot, ForwarderStatus, _LeadershipLost, test_the_stored_cursor_never_moves_backwards()

### Community 137 - "sso_settings.py"
Cohesion: 0.11
Nodes (17): client_ip(), SsoClientSecretBody, WardenSsoReport, build_sso_settings_router(), actor_id(), get_settings(), put_client_secret(), put_settings() (+9 more)

### Community 138 - "Cluster: test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (7): _columns(), _insert(), _revisions(), _tables(), test_a_transaction_may_carry_an_invitation_hash(), test_downgrade_removes_only_the_invitation_hash(), test_the_invitation_hash_is_a_sha256_digest()

### Community 139 - "Cluster: test_examples_public_surface.py"
Cohesion: 0.29
Nodes (8): _private(), _private_path(), sample_sources(), test_nothing_under_examples_reaches_into_warden_internals(), test_the_check_sees_each_kind_of_private_reach(), test_the_sample_has_python_to_check(), violations(), _warden()

### Community 140 - "Cluster: require_user()"
Cohesion: 0.31
Nodes (5): bearer_token(), Forbidden, installed_identity(), dependency(), require_user()

### Community 141 - "Cluster: ast"
Cohesion: 0.36
Nodes (5): _from_warden(), _private(), test_no_module_reaches_into_another_modules_private_names(), _violations(), _warden_bindings()

### Community 142 - "router.py"
Cohesion: 0.06
Nodes (14): anchor(), AnchorSigner, _KeyLike, _SignatureLike, export(), _address_or_none(), audit_router(), export_audit_events() (+6 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.19
Nodes (14): SingleUseTokens, _consume(), _issue(), test_a_token_is_consumed_once(), test_a_token_is_stored_only_as_its_hash(), test_a_token_serves_only_its_own_purpose(), test_an_expired_token_is_refused(), test_concurrent_consumes_use_a_token_once() (+6 more)

### Community 144 - "._accept"
Cohesion: 0.16
Nodes (4): AcceptedInvitation, check(), complete(), complete()

### Community 145 - "Cluster: test_identity_mfa_mail.py"
Cohesion: 0.40
Nodes (7): _confirmed_at(), _signed_in(), test_a_failed_notice_does_not_undo_the_enrolment(), test_a_signed_in_enrolment_sends_the_notice(), test_a_wrong_code_sends_nothing(), test_an_enrolment_under_a_challenge_sends_the_notice(), test_without_a_sender_the_notice_is_skipped()

### Community 147 - "SyslogSettings"
Cohesion: 0.13
Nodes (10): SyslogSettings, reset(), _base(), test_backoff_cap_must_not_be_below_the_initial_delay(), test_bad_sd_ids_are_refused(), test_defaults(), test_invalid_values_are_refused(), test_sd_id_defaults_to_the_registered_enterprise_number() (+2 more)

### Community 148 - "Cluster: test_no_direct_environment.py"
Cohesion: 0.29
Nodes (5): _enclosing_functions(), visit(), _findings(), test_no_module_reads_the_environment_or_files_directly(), test_the_anchors_file_exemption_covers_exactly_one_read()

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "ActionRegistry"
Cohesion: 0.12
Nodes (12): ActionRegistry, _summary(), register_syslog_actions(), registry(), registry(), registry(), test_the_syslog_actions_register_idempotently(), test_a_product_cannot_pre_empt_a_warden_action() (+4 more)

### Community 152 - "Cluster: test_webauthn_unconfigured.py"
Cohesion: 0.31
Nodes (5): bare(), _config(), http(), test_it_boots_without_webauthn(), test_password_and_totp_sign_in_are_unchanged()

### Community 153 - "identity/conftest.py"
Cohesion: 0.16
Nodes (12): app(), audit_registry(), client(), config(), db(), identity(), keys(), mail() (+4 more)

### Community 154 - "Cluster: test_tls_fail_closed.py"
Cohesion: 0.46
Nodes (5): _findings(), _is_cert_required(), _is_true(), test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 155 - "examples/conftest.py"
Cohesion: 0.15
Nodes (8): client(), console(), make_console(), build(), secrets(), console_config(), MemorySecrets, soft_authenticator()

### Community 156 - "Cluster: test_database.py"
Cohesion: 0.46
Nodes (5): _count(), test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "Cluster: _Section"
Cohesion: 0.29
Nodes (3): AuditConfig, DbConfig, _Section

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "Cluster: test_client_guide.py"
Cohesion: 0.47
Nodes (3): _contract_routes(), test_every_contract_route_is_linked_from_the_guide(), test_every_route_the_guide_names_is_in_the_contract()

### Community 162 - "test_identity_throttle.py"
Cohesion: 0.19
Nodes (12): enrol_totp(), _fail(), test_a_password_alone_does_not_reset_the_count_when_mfa_follows(), test_a_successful_sign_in_resets_the_count(), test_another_address_is_not_affected(), test_attempts_beyond_the_limit_are_refused_even_with_the_right_password(), test_completing_the_second_factor_resets_the_count(), test_expired_attempt_records_can_be_pruned() (+4 more)

### Community 163 - "mail.py"
Cohesion: 0.12
Nodes (10): _check(), format_expiry(), _is_control(), _load(), MailDeliveryError, MailError, MailTemplate, _neutralise() (+2 more)

### Community 164 - "Cluster: MemorySecrets"
Cohesion: 0.33
Nodes (3): MemorySecrets, test_a_purge_committing_during_verification_breaks_nothing(), purge_now()

### Community 167 - ".consume"
Cohesion: 0.14
Nodes (6): Ceremony, Challenges, ConsumedChallenge, _hash(), IssuedChallenge, _reason()

### Community 169 - "test_webauthn_credentials.py"
Cohesion: 0.18
Nodes (7): test_an_invalid_nickname_is_refused(), test_another_users_credential_cannot_be_touched(), test_list_count_rename_and_remove(), test_no_credential_material_reaches_logs_or_errors(), test_prune_removes_only_expired_challenges(), test_remove_all_removes_only_that_users_credentials(), expire_challenges()

### Community 175 - "attestation.py"
Cohesion: 0.15
Nodes (4): AttestationNotTrusted, _is_ca(), _issued_by(), TrustedRoots

### Community 176 - "subprocess"
Cohesion: 0.20
Nodes (8): test_every_exported_name_resolves_once(), test_identity_does_not_re_export_the_sso_presets(), test_the_public_names_match_the_snapshot(), test_the_root_package_names_the_subpackages_and_imports_none(), test_importing_audit_loads_no_identity_module(), test_importing_the_key_store_loads_no_web_framework(), test_the_probe_sees_the_web_framework_when_it_is_loaded(), _web_modules_after()

### Community 177 - "ceremony.js"
Cohesion: 0.24
Nodes (10): call(), create(), field(), flows, keep(), outcome, register(), state (+2 more)

### Community 178 - "fastapi"
Cohesion: 0.20
Nodes (3): JwkSet, _JwkSetResponse, OkpJwk

### Community 180 - "neutralise"
Cohesion: 0.29
Nodes (5): neutralise(), _replacement(), test_neutralise_leaves_ordinary_text_alone(), test_neutralise_replaces_c1_controls_and_unicode_line_separators(), test_neutralise_replaces_every_c0_control_and_del()

### Community 181 - "test_console_gaps.py"
Cohesion: 0.29
Nodes (3): test_every_gap_names_its_question(), test_every_gap_the_screens_use_is_defined(), test_the_totp_reset_is_no_longer_a_gap()

### Community 182 - "_from_syslog"
Cohesion: 0.33
Nodes (4): _from_syslog(), _scan_name(), _scan_value(), _structured_data()

### Community 186 - "test_fido2_device_free.py"
Cohesion: 0.47
Nodes (3): _device_modules_after(), test_importing_warden_loads_no_fido2_device_code(), test_the_probe_sees_device_code_when_it_is_loaded()

## Knowledge Gaps
- **14 isolated node(s):** `cognisn-warden`, `AuditChainConflict`, `Append-only audit database roles (INSERT and SELECT only)`, `Canonical JSON row form (warden.audit.row.v1)`, `Details cap and warden.truncated marker` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1524 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **28 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `pytest`, `Cluster: console_router()`, `typing`, `SSO Provider Discovery`, `Identity Service Operations`, `Signing Key Store`, `Invitation and Reset Tests`, `test_passkey_sign_in.py`, `sso_settings.py`, `WebAuthn Second Factor Tests`, `Identity HTTP Contract`, `Cluster: require_user()`, `SSO Sign-In Flow Tests`, `SingleUseTokens`, `WebAuthn Registration Tests`, `Cluster: test_identity_mfa_mail.py`, `SSO Invitation Tests`, `WebAuthn Credential Store`, `Single Sign-On Service`, `Purpose`, `Users and Sign-In Methods`, `identity/conftest.py`, `Second Factor Reset Tests`, `TOTP Reset Tests`, `Cluster: test_webauthn_unconfigured.py`, `Auth Router Helpers`, `SSO Settings Store`, `test_identity_throttle.py`, `Key Publication (JWKS)`, `mail.py`, `Password Resets and Links`, `TOTP MFA Tests`, `Cluster: lifecycle.py`, `Cluster: test_webauthn_authentication.py`, `Cluster: Mfa`, `.sso_settings_router`, `Cluster: httpx`, `test_identity_prune.py`, `.pruning`, `Cluster: Mailer`, `Cluster: SecretBox`, `Cluster: test_identity_tokens.py`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`, `Cluster: console/cli.py`, `Cluster: test_identity_apikeys.py`, `Cluster: PermissionRegistry`, `Cluster: identity_support.py`, `webauthn.py`, `test_webauthn_live.py`, `Cluster: Sessions`, `scoped_client`, `test_passkey_registration_link.py`, `Cluster: sso.py`, `Cluster: PolicyStore`, `Cluster: build_console()`, `identity/__init__.py`, `Cluster: test_identity_admin_routes.py`, `Cluster: test_identity_sign_in.py`, `Cluster: test_sso_admin_routes.py`, `Cluster: .sign_in()`, `Cluster: test_sso_issuer.py`, `test_passkey_invitation.py`, `Cluster: test_identity_lifecycle_routes.py`, `Cluster: test_sso_break_glass_live.py`, `Cluster: WardenConfig`, `Cluster: test_identity_client_address.py`?**
  _High betweenness centrality (0.129) - this node is a cross-community bridge._
- **Are the 45 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 45 INFERRED edges - model-reasoned connections that need verification._
- **What connects `cognisn-warden`, `AuditChainConflict`, `Append-only audit database roles (INSERT and SELECT only)` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `test_passkey_sign_in.py` be split into smaller, more focused modules?**
  _Cohesion score 0.10020703933747412 - nodes in this community are weakly interconnected._
- **Why does `Database` connect `SSO Invitation Tests` to `test_passkey_sign_in.py`, `typing`, `AuditEvent`, `Identity Service Operations`, `Signing Key Store`, `Invitation and Reset Tests`, `Identity`, `forwarder.py`, `Audit Anchors`, `WebAuthn Second Factor Tests`, `SSO Sign-In Flow Tests`, `router.py`, `SingleUseTokens`, `Audit Recorder Tests`, `test_audit_query.py`, `Cluster: test_identity_mfa_mail.py`, `WebAuthn Credential Store`, `Single Sign-On Service`, `WebAuthn Registration Tests`, `Purpose`, `identity/conftest.py`, `Second Factor Reset Tests`, `Cluster: test_webauthn_unconfigured.py`, `Cluster: test_database.py`, `TOTP Reset Tests`, `SSO Settings Store`, `Audit Retention`, `test_identity_throttle.py`, `Key Publication (JWKS)`, `Cluster: MemorySecrets`, `Syslog Forwarder`, `Password Resets and Links`, `.consume`, `TOTP MFA Tests`, `test_webauthn_credentials.py`, `Cluster: SyslogForwarder`, `Cluster: warden/cli.py`, `Cluster: test_webauthn_authentication.py`, `test_identity_prune.py`, `Cluster: httpx`, `Cluster: Checkpoint`, `Cluster: soft_authenticator.py`, `Cluster: SecretBox`, `Cluster: test_identity_tokens.py`, `Cluster: test_identity_apikeys.py`, `Cluster: PermissionRegistry`, `Cluster: identity_support.py`, `test_webauthn_live.py`, `scoped_client`, `test_passkey_registration_link.py`, `Cluster: PolicyStore`, `Cluster: build_console()`, `identity/__init__.py`, `Cluster: test_identity_admin_routes.py`, `Cluster: test_key_publication.py`, `Cluster: test_identity_sign_in.py`, `Cluster: test_sso_admin_routes.py`, `Cluster: .sign_in()`, `Cluster: test_audit_router.py`, `Cluster: test_audit_verify.py`, `Cluster: asyncio`, `Cluster: test_sso_issuer.py`, `test_passkey_invitation.py`, `Cluster: test_syslog_routes.py`, `Cluster: test_identity_lifecycle_routes.py`, `Cluster: test_sso_break_glass_live.py`, `Cluster: test_audit_grants.py`, `Cluster: WardenConfig`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`?**
  _High betweenness centrality (0.118) - this node is a cross-community bridge._
- **Are the 93 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 93 INFERRED edges - model-reasoned connections that need verification._
- **Should `typing` be split into smaller, more focused modules?**
  _Cohesion score 0.04724497811693413 - nodes in this community are weakly interconnected._