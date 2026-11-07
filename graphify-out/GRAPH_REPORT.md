# Graph Report - warden  (2026-11-07)

## Corpus Check
- 272 files · ~230,263 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 5, .css 1, .mako 1)

## Summary
- 5393 nodes · 18338 edges · 190 communities (161 shown, 29 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 2312 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `602824d0`
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
- contract.py
- SSO Sign-In Flow Tests
- http_client
- Audit Recorder Tests
- Syslog Transport
- WebAuthn Registration Tests
- test_audit_query.py
- SSO Invitation Tests
- identity/__init__.py
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
- ActionRegistry
- test_identity_key_publication.py
- Password Hashing
- Syslog Forwarder
- Password Resets and Links
- TOTP MFA Tests
- Cluster: test_syslog_transport.py
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
- Checkpoint
- Cluster: soft_authenticator.py
- Cluster: Mailer
- Cluster: SecretBox
- build_reference_app
- Cluster: test_sso_sealing.py
- Cluster: console/cli.py
- Cluster: test_identity_apikeys.py
- Cluster: PermissionRegistry
- Cluster: test_proxy.py
- Cluster: identity_support.py
- Cluster: current_revision()
- test_identity_reset.py
- test_webauthn_live.py
- Cluster: Sessions
- test_identity_dependencies.py
- test_passkey_registration_link.py
- notes_router
- Cluster: sso.py
- Cluster: PolicyStore
- ConnectionSource
- bump_version.py
- Roles
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
- .transaction
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
- collector.py
- Cluster: test_sso_break_glass_live.py
- test_audit_grants.py
- Cluster: grants.py
- Cluster: with
- Cluster: parse_config()
- Cluster: WardenConfig
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- Cluster: publish.yml
- Cluster: SyslogConfig
- Cluster: test_lifecycle_migration.py
- test_bump_version.py
- TokenPair
- totp.py
- Cluster: test_sso_invitation_sealing_migration.py
- test_identity_roles.py
- Cluster: test_cli_errors.py
- Cluster: test_anchored_patterns.py
- Cluster: licence_audit.py
- _rotate
- test_identity_totp_unit.py
- Cluster: test_sso_invitation_migration.py
- Cluster: test_examples_public_surface.py
- Principal
- Cluster: ast
- audit_router
- SingleUseTokens
- ._accept
- passkey_support.py
- AnchorSigner
- SyslogSettings
- Cluster: test_no_direct_environment.py
- Cluster: updates
- .record
- Cluster: _AfterFirstQuery
- Cluster: test_webauthn_unconfigured.py
- identity/conftest.py
- Cluster: test_tls_fail_closed.py
- examples/conftest.py
- Cluster: test_database.py
- Cluster: verify
- BaseModel
- load_settings
- Cluster: rsyslog
- Cluster: test_client_guide.py
- test_identity_throttle.py
- format_expiry
- test_readme.py
- Cluster: _Abort
- _mount_pages
- test_webauthn_credentials.py
- Cluster: cognisn-warden
- subprocess
- ceremony.js
- fastapi
- test_console_gaps.py
- .prune
- source_wheel
- subprocess
- test_a_key_registered_while_switching_to_sso_only_never_leaves_both
- test_the_import_check_reports_a_module_that_fails
- _load

## God Nodes (most connected - your core abstractions)
1. `Identity` - 499 edges
2. `Database` - 481 edges
3. `KeyStore` - 158 edges
4. `RecordingSender` - 143 edges
5. `audit_rows()` - 143 edges
6. `AuditRecorder` - 130 edges
7. `ActionRegistry` - 129 edges
8. `FakeIdp` - 115 edges
9. `AuditEvent` - 103 edges
10. `WebAuthn` - 99 edges

## Surprising Connections (you probably didn't know these)
- `test_every_forwarder_setting_has_a_config_counterpart()` --uses--> `SyslogConfig`  [INFERRED]
  tests/test_config_fields.py → src/warden/config.py
- `test_the_configuration_keeps_the_slash()` --uses--> `WardenConfig`  [INFERRED]
  tests/identity/sso/test_sso_issuer.py → src/warden/config.py
- `test_registration_is_idempotent_for_an_identical_spec()` --calls--> `ActionRegistry`  [INFERRED]
  tests/test_audit_registry.py → src/warden/audit/registry.py
- `test_a_run_time_issuer_keeps_the_slash()` --uses--> `SingleSignOn`  [INFERRED]
  tests/identity/sso/test_sso_issuer.py → src/warden/identity/sso/service.py
- `test_identity_defaults_are_the_values_identity_used_before()` --uses--> `IdentityConfig`  [INFERRED]
  tests/test_config_fields.py → src/warden/config.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Audit tamper-evidence mechanisms** — docs_design_audit_chain_audit_hash_chain, docs_design_audit_chain_retention_checkpoint, docs_design_audit_chain_anchor, docs_design_audit_chain_audit_database_roles, docs_design_overview_tamper_evidence [EXTRACTED 1.00]
- **Release and publication pipeline** — docs_releasing_bump_version, github_workflows_publish, docs_releasing_check_dist, docs_releasing_trusted_publishing, claude_integration_procedure [EXTRACTED 1.00]
- **Tripwire tests guarding architecture rules** — docs_design_overview_single_audit_writer, docs_design_overview_audit_independence, examples_console_readme_public_surface_tripwire, claude_mutation_checked_guards [INFERRED 0.85]

## Communities (190 total, 29 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.16
Nodes (30): give_passkey(), passkey_assertion(), passkey_options(), passkey_sign_in(), _admin(), _amr(), _last_sign_in_failure(), _passkey_user() (+22 more)

### Community 1 - "typing"
Cohesion: 0.05
Nodes (20): HistoricalVerifier, _now(), AuditPage, get_recorder(), record_audit(), BrokenLink, IdentityConfig, table() (+12 more)

### Community 2 - "SSO Provider Discovery"
Cohesion: 0.05
Nodes (53): SsoError, _basic(), Discovery, _https(), JwksCache, _KeySet, parse_metadata(), ProviderHttp (+45 more)

### Community 3 - "AuditEvent"
Cohesion: 0.06
Nodes (24): AuditEvent, Severity, ActionSpec, _check_summary(), register_warden_action(), AuditSink, register_actions(), register_actions() (+16 more)

### Community 5 - "Signing Key Store"
Cohesion: 0.07
Nodes (45): KeysConfig, _b64url(), _b64url_decode(), key_id_for(), KeyStore, KeyStoreError, PublicKey, _raw_public() (+37 more)

### Community 6 - "Invitation and Reset Tests"
Cohesion: 0.10
Nodes (36): StagedGrant, VerifiedIdentity, RecordingSender, _accept(), FakePins, _invite(), _status(), test_a_bad_token_is_refused_and_audited() (+28 more)

### Community 7 - "Identity"
Cohesion: 0.06
Nodes (47): Identity, _b64(), _parts(), _signed_in(), test_a_refresh_token_never_outlives_its_session(), test_a_retired_key_refuses_live_tokens(), test_access_token_carries_kid_and_claims(), test_an_expired_access_token_is_refused() (+39 more)

### Community 8 - "Audit Anchors"
Cohesion: 0.10
Nodes (47): anchor(), AnchorRecord, export(), iter_events(), AuditRecorder, verify_anchors(), stored(), _aged_then_anchored() (+39 more)

### Community 9 - "Sample Console Front End"
Cohesion: 0.12
Nodes (87): apiKeysScreen(), chosen(), invitationsScreen(), METHODS, POLICY_FIELDS, policyScreen(), roleNames(), ssoScreen() (+79 more)

### Community 10 - "WebAuthn Second Factor Tests"
Cohesion: 0.11
Nodes (53): _amr(), _app(), _assertion(), _bearer(), _challenge(), http(), _key_sign_in(), _options() (+45 more)

### Community 11 - "contract.py"
Cohesion: 0.04
Nodes (78): _BadRequest, ChallengeBody, ChangePasswordBody, CodeBody, detail(), _Doc, EnrolmentBody, EnrolmentConfirmBody (+70 more)

### Community 12 - "SSO Sign-In Flow Tests"
Cohesion: 0.14
Nodes (41): User, FakeIdp, sign_in(), alice(), app(), config(), idp(), pin_of() (+33 more)

### Community 13 - "http_client"
Cohesion: 0.16
Nodes (12): http_client(), passkey_config(), other_key(), config(), http(), test_the_listed_passkey_value_matches_what_sign_in_does(), config(), http() (+4 more)

### Community 14 - "Audit Recorder Tests"
Cohesion: 0.11
Nodes (28): set_recorder(), Database, BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), RecordingSink (+20 more)

### Community 15 - "Syslog Transport"
Cohesion: 0.04
Nodes (22): AuditRecord, _clip(), build(), format_test_message(), _header_field(), _replacement(), _sd_escape(), _summary() (+14 more)

### Community 16 - "WebAuthn Registration Tests"
Cohesion: 0.16
Nodes (37): WebAuthn, SoftwareAuthenticator, _refused(), test_a_credential_with_rk_reported_is_discoverable(), test_a_malformed_registration_is_refused(), test_a_passkey_reported_as_not_discoverable_is_refused(), test_a_refused_response_uses_its_challenge_up(), test_a_registration_round_trip() (+29 more)

### Community 17 - "test_audit_query.py"
Cohesion: 0.14
Nodes (13): AuditQuery, list_events(), _collect(), _ids(), registry(), test_a_large_export_streams_across_batches(), test_an_empty_or_inverted_time_range_is_refused(), test_an_export_is_itself_audited_before_it_streams() (+5 more)

### Community 18 - "SSO Invitation Tests"
Cohesion: 0.12
Nodes (40): accept(), acceptance_rows(), app(), _bodies(), config(), handoffs_of(), idp(), invite() (+32 more)

### Community 19 - "identity/__init__.py"
Cohesion: 0.03
Nodes (26): NoteBody, Outbox, content_security_policy(), _origin(), Invitation, Enrolment, Role, ChallengeIssued (+18 more)

### Community 20 - "Single Sign-On Service"
Cohesion: 0.10
Nodes (11): _hash(), _PinRefused, SecretReader, SingleSignOn, pin(), _token(), IdTokenClaims, test_a_handoff_code_is_used_once_even_concurrently() (+3 more)

### Community 22 - "WebAuthn Ceremonies"
Cohesion: 0.11
Nodes (6): WebAuthnError, _extension_results(), _parse(), _reported_resident_key(), _Stored, _transports()

### Community 23 - "Audit Anchor Format"
Cohesion: 0.06
Nodes (40): _anchor_report(), console_router(), change_policy(), check_anchors(), reset_policy(), show_policy(), _policy(), Anchor (+32 more)

### Community 24 - "Purpose"
Cohesion: 0.17
Nodes (5): IssuedToken, _live_token(), LiveToken, token_hash(), test_malformed_tokens_are_refused_cleanly()

### Community 25 - "Users and Sign-In Methods"
Cohesion: 0.08
Nodes (9): SecretStore, PendingInvitation, MailSender, PasswordHasher, check_email(), _row_to_user(), SignInMethodConflict, UserError (+1 more)

### Community 26 - "Second Factor Reset Tests"
Cohesion: 0.18
Nodes (14): _admin(), _bearer(), http(), _register(), _state(), test_a_reset_between_storing_a_key_and_its_codes_leaves_neither(), reset_meanwhile(), test_a_reset_is_idempotent_and_still_audited() (+6 more)

### Community 27 - "Audit Hash Chain"
Cohesion: 0.09
Nodes (27): address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields(), _number(), row_hash() (+19 more)

### Community 28 - "TOTP Reset Tests"
Cohesion: 0.10
Nodes (31): audit_rows(), _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), _signed_in() (+23 more)

### Community 29 - "Configuration"
Cohesion: 0.12
Nodes (42): ConfigError, FakeSecrets, FakeSettings, _load(), _sso_tree(), test_audit_only_deployment_needs_no_link_templates(), test_complete_sso_configuration_loads(), test_configuration_is_immutable() (+34 more)

### Community 30 - "Auth Router Helpers"
Cohesion: 0.07
Nodes (60): client_ip(), json_response(), read_object(), refusal(), build_auth_router(), begin_enrolment(), change_password(), confirm_enrolment() (+52 more)

### Community 31 - "SSO Settings Store"
Cohesion: 0.10
Nodes (20): _from_config(), _plain(), revoke_sso_sessions(), SsoSettings, SsoSettingsError, SsoSettingsStore, _typed(), config() (+12 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "Audit Retention"
Cohesion: 0.10
Nodes (31): register_audit_actions(), purge(), RetentionError, _age(), _all(), keys(), MemorySecrets, _purged_trail() (+23 more)

### Community 34 - "ActionRegistry"
Cohesion: 0.10
Nodes (38): ActionRegistry, format_message(), neutralise(), register_syslog_actions(), registry(), _oversized(), _parse(), _record() (+30 more)

### Community 35 - "test_identity_key_publication.py"
Cohesion: 0.14
Nodes (12): _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), _access_token(), _b64(), _decode() (+4 more)

### Community 36 - "Password Hashing"
Cohesion: 0.15
Nodes (10): Verification, _legacy(), test_argon2_hash_verifies_the_right_password_only(), test_argon2_hash_with_weaker_parameters_needs_rehash(), test_dummy_verify_never_succeeds(), test_legacy_pbkdf2_verifies_and_always_needs_rehash(), test_malformed_hashes_fail_closed(), test_new_hashes_are_argon2id() (+2 more)

### Community 37 - "Syslog Forwarder"
Cohesion: 0.20
Nodes (32): _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader(), _raw_insert() (+24 more)

### Community 38 - "Password Resets and Links"
Cohesion: 0.09
Nodes (8): AuthenticationRefused, MailError, _Account, PasswordResets, _refusal(), PasskeyLinkNotConfigured, PasskeyLinkRefused, _Rollback

### Community 39 - "TOTP MFA Tests"
Cohesion: 0.10
Nodes (35): current_code(), race(), _challenge(), _enrolled(), _fresh_code(), _confirmed_at(), _signed_in(), test_a_failed_notice_does_not_undo_the_enrolment() (+27 more)

### Community 40 - "Cluster: test_syslog_transport.py"
Cohesion: 0.08
Nodes (31): frame(), open_transport(), tls_context(), main(), Authority, Issued, _key_pem(), _name() (+23 more)

### Community 42 - "Cluster: SyslogForwarder"
Cohesion: 0.07
Nodes (5): initialise_cursor(), load_cursor(), store_cursor(), SyslogForwarder, test_the_stored_cursor_never_moves_backwards()

### Community 43 - "Cluster: build_admin_router()"
Cohesion: 0.10
Nodes (38): _Abort, InvitationError, InvitationMismatch, _api_key(), _assignment(), build_admin_router(), assign_role(), create_key() (+30 more)

### Community 44 - "Cluster: test_config_webauthn.py"
Cohesion: 0.11
Nodes (33): _certificate(), _parse(), _refused(), _Secrets, test_a_malformed_passkey_registration_link_is_refused(), test_a_malformed_rp_id_is_refused(), test_a_malformed_rp_name_is_refused(), test_a_registrable_suffix_of_the_origin_host_is_accepted() (+25 more)

### Community 45 - "Cluster: alembic"
Cohesion: 0.06
Nodes (4): _run(), upgrade(), upgrade(), upgrade()

### Community 46 - "Cluster: warden/cli.py"
Cohesion: 0.11
Nodes (23): AnchorError, ExternalAnchor, PurgeResult, AnchorReport, VerificationReport, _anchor_actor(), _audit(), _audit_anchor() (+15 more)

### Community 47 - "Cluster: test_webauthn_authentication.py"
Cohesion: 0.18
Nodes (28): _enrolled(), _refused(), test_a_counter_that_does_not_increase_is_a_suspected_clone(), test_a_counter_that_increases_is_accepted_and_stored(), test_a_discoverable_passkey_round_trip(), test_a_discoverable_sign_in_always_requires_user_verification(), test_a_discoverable_sign_in_needs_the_owners_user_handle(), test_a_discoverable_sign_in_without_user_verification_is_refused() (+20 more)

### Community 48 - "Cluster: pathlib"
Cohesion: 0.24
Nodes (5): _blocks(), test_dependabot_watches_github_actions_weekly(), _references(), test_every_action_is_pinned_to_a_commit_sha(), test_workflows_reference_actions()

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Cluster: Mfa"
Cohesion: 0.09
Nodes (7): Challenge, _hash_token(), Mfa, hash_recovery_code(), parse_recovery_code(), provisioning_uri(), step_for()

### Community 51 - "test_identity_prune.py"
Cohesion: 0.18
Nodes (10): _count(), _expire_all(), _fixtures(), test_a_failed_run_does_not_stop_the_schedule(), test_a_used_refresh_token_is_kept_until_it_expires(), test_ended_throttle_windows_are_pruned(), test_expired_rows_are_pruned_and_live_ones_kept(), test_pruning_runs_on_a_schedule() (+2 more)

### Community 52 - "Cluster: httpx"
Cohesion: 0.11
Nodes (27): callback(), completion(), handoff(), provider_code(), sso_config(), start(), Started, accept_through_sso() (+19 more)

### Community 53 - "Cluster: test_distributions.py"
Cohesion: 0.21
Nodes (17): _only(), _sdist(), test_a_directory_with_two_wheels_or_no_sdist_fails(), test_a_minimal_good_wheel_and_sdist_pass(), test_a_version_other_than_the_expected_one_fails(), test_a_wheel_built_from_source_holds_only_the_warden_package(), test_a_wheel_missing_a_required_file_fails(), test_a_wheel_with_anything_outside_warden_fails() (+9 more)

### Community 54 - "Cluster: test_config_fields.py"
Cohesion: 0.12
Nodes (27): _parse(), _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart(), test_from_config_carries_every_field(), test_from_config_refuses_a_ca_secret_it_cannot_read(), test_from_config_uses_the_local_host_name_when_none_is_configured() (+19 more)

### Community 55 - "Checkpoint"
Cohesion: 0.07
Nodes (14): _b64url(), _b64url_decode(), Checkpoint, _int(), MalformedCheckpoint, _str(), CheckpointSigner, _KeyLike (+6 more)

### Community 56 - "Cluster: soft_authenticator.py"
Cohesion: 0.13
Nodes (13): ca(), make_webauthn(), factory(), rogue_ca(), strict_webauthn(), webauthn(), webauthn_config(), _certificate() (+5 more)

### Community 57 - "Cluster: Mailer"
Cohesion: 0.15
Nodes (21): MailConfig, _check(), _load(), Mailer, MailKind, MailTemplate, package(), test_a_delivery_failure_is_reported_without_the_sender_s_detail() (+13 more)

### Community 58 - "Cluster: SecretBox"
Cohesion: 0.12
Nodes (14): _decode(), new_totp_key(), SecretBox, SecretKeyError, _key(), test_a_malformed_previous_key_fails_too(), test_a_missing_or_malformed_key_fails_at_start_up(), test_a_sealed_secret_is_bound_to_its_context() (+6 more)

### Community 59 - "build_reference_app"
Cohesion: 0.10
Nodes (9): build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), reference_config(), render() (+1 more)

### Community 60 - "Cluster: test_sso_sealing.py"
Cohesion: 0.07
Nodes (21): _derive_key(), open_invitation(), seal_invitation(), AttestationNotTrusted, _is_ca(), _issued_by(), TrustedRoots, binding() (+13 more)

### Community 61 - "Cluster: console/cli.py"
Cohesion: 0.08
Nodes (19): actor(), build_console(), Console, _create_admin(), work(), _dsn(), _init(), main() (+11 more)

### Community 62 - "Cluster: test_identity_apikeys.py"
Cohesion: 0.16
Nodes (16): _app(), _bearer(), client(), _reasons(), test_a_key_cannot_sign_out_or_change_a_password(), test_a_key_expires_within_the_configured_maximum(), test_a_key_is_accepted_by_require_user_and_require_permission(), test_a_key_is_prefixed_and_stored_only_as_its_hash() (+8 more)

### Community 63 - "Cluster: PermissionRegistry"
Cohesion: 0.12
Nodes (13): PermissionRegistry, registry(), test_a_role_may_only_use_registered_permissions(), test_administrator_roles_are_listed(), test_permission_names_are_dotted_lower_case(), test_permissions_for_several_roles_are_the_union(), test_redefinition_must_match(), test_role_names_are_validated() (+5 more)

### Community 64 - "Cluster: test_proxy.py"
Cohesion: 0.12
Nodes (15): _address(), resolve_client_ip(), _trusted(), TrustedProxyMiddleware, _App, _noop(), _scope(), test_middleware_ignores_other_forwarding_headers() (+7 more)

### Community 65 - "Cluster: identity_support.py"
Cohesion: 0.16
Nodes (14): enrol_totp(), make_config(), MemorySecrets, test_keys_may_be_unexpiring_when_no_maximum_is_set(), test_the_configured_prefix_is_used(), _identity(), test_the_challenge_failure_limit_comes_from_configuration(), test_the_challenge_lifetime_comes_from_configuration() (+6 more)

### Community 66 - "Cluster: current_revision()"
Cohesion: 0.12
Nodes (22): current_revision(), heads(), migrate(), test_upgrade_refuses_unchained_rows(), test_console_script_runs_migrate_from_a_config_file(), _columns(), _objects_outside_warden(), _tables() (+14 more)

### Community 67 - "test_identity_reset.py"
Cohesion: 0.21
Nodes (13): _reasons(), test_a_failed_send_leaves_no_link(), test_a_link_is_refused_and_spent_if_the_account_changed_since(), test_a_new_request_revokes_earlier_links(), test_a_reset_link_is_mailed_to_an_active_password_user(), test_a_reset_link_works_once(), test_a_weak_password_leaves_the_link_usable(), test_an_expired_link_is_refused() (+5 more)

### Community 68 - "test_webauthn_live.py"
Cohesion: 0.06
Nodes (24): admin(), browser(), config(), credentials(), last_step(), live_sessions(), no_credential_material(), ok() (+16 more)

### Community 69 - "Cluster: Sessions"
Cohesion: 0.14
Nodes (6): AccessClaims, _b64(), _hash(), _json(), Sessions, _unb64()

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (14): _app(), _bearer(), CaseScope, scope(), scoped_client(), test_a_scoped_permission_without_a_hook_fails_closed(), test_dependencies_need_an_installed_identity(), test_require_permission() (+6 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.19
Nodes (28): assert_refused(), admin(), config(), _credential_count(), http(), _identity(), _link(), _options() (+20 more)

### Community 72 - "notes_router"
Cohesion: 0.11
Nodes (10): _audit(), Note, Notes, notes_router(), create_note(), delete_note(), found(), update_note() (+2 more)

### Community 73 - "Cluster: sso.py"
Cohesion: 0.18
Nodes (14): _body_field(), build_sso_router(), callback(), clear_cookie(), failed(), land(), set_cookie(), source() (+6 more)

### Community 74 - "Cluster: PolicyStore"
Cohesion: 0.11
Nodes (3): PolicyError, PolicyStore, SessionPolicy

### Community 76 - "bump_version.py"
Cohesion: 0.27
Nodes (4): _current_branch(), main(), stamp(), StampRefused

### Community 77 - "Roles"
Cohesion: 0.06
Nodes (11): ApiKey, ApiKeyError, ApiKeys, _hash(), NewApiKey, _row_to_key(), LastAdministratorError, lock_administrators() (+3 more)

### Community 78 - "Cluster: test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (19): admin(), app(), _bearer(), client(), test_an_undeliverable_invitation_is_a_502(), test_api_keys_are_created_listed_and_revoked(), test_bad_api_keys_are_refused(), test_bad_invitations_are_refused() (+11 more)

### Community 79 - "Cluster: test_webauthn_migration.py"
Cohesion: 0.22
Nodes (17): _challenge(), _credential(), _refused(), _revisions(), _tables(), test_a_counter_at_the_32_bit_ceiling_is_stored(), test_a_credential_round_trips_and_its_id_is_unique(), test_a_user_handle_is_64_bytes_and_unique() (+9 more)

### Community 80 - "Cluster: test_cli_audit_anchor.py"
Cohesion: 0.20
Nodes (14): _export(), FakeSecrets, FakeSettings, secrets(), _seed(), _settings(), test_anchor_on_an_empty_trail_writes_nothing(), test_anchor_with_min_rows_waits_for_enough_rows() (+6 more)

### Community 81 - "Cluster: test_key_publication.py"
Cohesion: 0.16
Nodes (16): client(), FakeSecrets, _kids(), secrets(), store(), test_a_retired_key_is_published_only_for_historical_verification(), test_a_revoked_key_is_never_published(), test_a_rotated_key_is_published_at_once() (+8 more)

### Community 82 - "Cluster: test_console_app.py"
Cohesion: 0.18
Nodes (19): create_administrator(), assert_strict_csp(), bearer(), make_user(), link_token(), static_files(), test_a_password_sign_in_round_trip(), test_a_product_route_refused_without_its_permission_and_allowed_with_it() (+11 more)

### Community 83 - "Cluster: json"
Cohesion: 0.16
Nodes (16): csv_lines(), _csv_record(), escape_cell(), ndjson_lines(), AuditRow, _is_checkpoint(), _collect(), _row() (+8 more)

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
Cohesion: 0.16
Nodes (15): app(), authorise(), config(), idp(), sso(), test_a_bad_client_secret_is_refused(), test_an_invalid_change_names_the_field(), test_disabling_through_the_route_ends_sso_sessions() (+7 more)

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
Cohesion: 0.13
Nodes (3): passkey_keys(), SignInThrottle, throttle_key()

### Community 93 - "Cluster: test_audit_router.py"
Cohesion: 0.16
Nodes (15): client(), exporter(), NoKeys, reader(), registry(), test_an_unknown_export_format_is_refused_and_not_audited(), test_csv_export_is_audited_with_actor_and_real_client_address(), test_every_route_needs_the_products_authorisation() (+7 more)

### Community 94 - "Cluster: test_audit_verify.py"
Cohesion: 0.13
Nodes (17): row_from_record(), _purges(), verify_chain(), _walk(), ids(), NoKeys, registry(), _sql() (+9 more)

### Community 95 - "Cluster: main()"
Cohesion: 0.23
Nodes (12): main(), FakeSecrets, FakeSettings, _seed(), _settings(), test_a_configured_retention_below_the_minimum_fails_at_start_up(), test_purge_below_the_minimum_is_refused(), test_purge_uses_the_configured_retention_and_signs_a_checkpoint() (+4 more)

### Community 96 - "Cluster: field_validator"
Cohesion: 0.09
Nodes (4): AuditConfig, _check_secret_name(), _check_url(), SsoConfig

### Community 97 - "Cluster: test_db_schema.py"
Cohesion: 0.11
Nodes (7): _lock_keys(), _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range(), test_every_allocated_key_is_recorded_in_the_allocation_table(), test_no_module_defines_a_schema_name_of_its_own(), test_the_scan_finds_every_known_lock_key()

### Community 99 - "Cluster: test_sso_issuer.py"
Cohesion: 0.11
Nodes (17): alice(), app(), config(), configured_issuer(), idp(), _pins(), provider_issuer(), _refusals() (+9 more)

### Community 100 - "Cluster: test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (14): imported_modules(), Module, _names_identity(), test_importing_audit_loads_no_identity_module(), test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations(), preset_names() (+6 more)

### Community 101 - "Cluster: .register()"
Cohesion: 0.15
Nodes (3): _new_key(), _sign(), StoredCredential

### Community 102 - "Cluster: test_syslog_sd_id.py"
Cohesion: 0.15
Nodes (13): SyslogConfig, _config(), _record(), _sd_ids(), test_a_product_override_is_honoured(), test_config_and_settings_default_to_warden_at_67382(), test_start_up_no_longer_requires_an_sd_id_when_syslog_is_enabled(), test_start_up_still_requires_host_and_port_when_syslog_is_enabled() (+5 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "Cluster: WebAuthnConfig"
Cohesion: 0.08
Nodes (9): _base_origin(), _check_origin(), _check_template(), DbConfig, HttpConfig, _is_domain(), _Section, _serialise_origin() (+1 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (22): passkey_authenticator(), _accept(), admin(), config(), http(), _invite(), _options(), _status() (+14 more)

### Community 106 - "test_console_passkeys.py"
Cohesion: 0.17
Nodes (22): authenticator(), sign_in(), amr(), browser(), link_token(), outbox_message(), passkey_sign_in(), register_key() (+14 more)

### Community 107 - "Cluster: test_syslog_routes.py"
Cohesion: 0.26
Nodes (9): syslog_router(), _audit_rows(), authorise(), _client(), _settings(), test_routes_refuse_without_authorisation(), test_status_reports_the_forwarder(), test_test_send_delivers_one_message_and_audits_it() (+1 more)

### Community 108 - "Cluster: test_identity_lifecycle_routes.py"
Cohesion: 0.20
Nodes (12): app(), client(), test_a_bad_invitation_gets_the_uniform_refusal(), test_a_bad_reset_token_gets_the_uniform_refusal(), test_a_failed_send_still_answers_the_same(), test_a_non_json_body_gets_the_uniform_refusal(), test_a_password_for_an_sso_only_invitation_is_a_409(), test_a_reset_request_looks_the_same_whoever_asks() (+4 more)

### Community 109 - "Cluster: test_cli_audit_errors.py"
Cohesion: 0.19
Nodes (8): _anchors_file(), FakeSecrets, FakeSettings, _settings(), test_anchor_refuses_an_actor_too_long_to_forward_whole(), test_connection_failure_prints_a_fixed_message_and_exits_1(), test_grants_prints_sql_without_needing_a_database(), test_grants_refuses_a_shared_role()

### Community 110 - "Cluster: test_licence_audit.py"
Cohesion: 0.15
Nodes (12): _load(), _pkg(), test_a_named_exception_that_turns_strong_copyleft_fails(), test_a_strong_copyleft_package_fails_even_when_named_as_an_exception(), test_an_unnamed_weak_copyleft_package_fails(), test_audit_walks_the_runtime_tree_and_reports_copyleft(), test_both_named_exceptions_pass(), test_fido2s_declared_licences_need_the_named_exception() (+4 more)

### Community 111 - "Cluster: check_dist.py"
Cohesion: 0.20
Nodes (7): dist_problems(), import_problems(), main(), _metadata_version(), sdist_problems(), source_version(), wheel_problems()

### Community 112 - "Cluster: test_cli.py"
Cohesion: 0.22
Nodes (9): FakeSecrets, FakeSettings, _settings(), test_invalid_configuration_fails_before_doing_anything(), test_keys_rotate_adds_a_key_and_prints_only_its_id(), test_keys_rotate_twice_keeps_both_keys(), test_migrate_reads_the_dsn_through_a_secret_reference(), test_migrate_upgrades_to_head() (+1 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (15): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+7 more)

### Community 114 - "Cluster: MailMessage"
Cohesion: 0.11
Nodes (5): SecurityHeaders, with_headers(), MailMessage, FailingSender, RecordingSender

### Community 115 - "collector.py"
Cohesion: 0.09
Nodes (6): BlackholeCollector, split_frames(), UdpCollector, _UdpProtocol, test_a_collector_that_stops_reading_times_out_the_send(), test_udp_sends_one_message_per_datagram_without_framing()

### Community 116 - "Cluster: test_sso_break_glass_live.py"
Cohesion: 0.17
Nodes (7): _local_hostname(), app(), config(), secrets(), test_an_invitation_completes_with_a_password_while_sso_fails(), test_password_sign_in_works_while_sso_fails(), test_the_provider_is_stopped()

### Community 117 - "test_audit_grants.py"
Cohesion: 0.09
Nodes (17): age(), rechain(), _as(), MemorySecrets, _pool(), _refused(), _registry(), roles() (+9 more)

### Community 118 - "Cluster: grants.py"
Cohesion: 0.35
Nodes (7): append_only_grants(), _application(), _forwarder(), grants_sql(), _ident(), _purger(), _reset()

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "Cluster: parse_config()"
Cohesion: 0.19
Nodes (7): _format_errors(), load_config(), parse_config(), _resolve_secrets(), SecretSource, SettingsSource, _split_list()

### Community 121 - "Cluster: WardenConfig"
Cohesion: 0.26
Nodes (9): WardenConfig, _store(), test_a_change_reaches_another_replica_promptly(), test_defaults_come_from_configuration(), test_inconsistent_updates_are_refused(), test_reset_returns_to_configuration(), test_running_starts_and_stops_the_listener(), test_update_is_stored_and_audited() (+1 more)

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

### Community 128 - "test_bump_version.py"
Cohesion: 0.22
Nodes (9): init_file(), _load(), test_accepts_release_forms(), test_refuses_file_without_exactly_one_version_line(), test_refuses_malformed_versions(), test_refuses_off_a_release_branch(), test_refuses_version_for_another_release(), test_stamp_writes_lf_line_endings() (+1 more)

### Community 130 - "totp.py"
Cohesion: 0.20
Nodes (5): code_at(), generate_recovery_codes(), generate_secret(), matching_step(), parse_code()

### Community 131 - "Cluster: test_sso_invitation_sealing_migration.py"
Cohesion: 0.21
Nodes (12): _columns(), _constraints(), test_downgrade_removes_the_chain_revision_and_upgrade_restores_it(), test_head_includes_the_chain_revision(), _columns(), _insert(), _revisions(), _states() (+4 more)

### Community 132 - "test_identity_roles.py"
Cohesion: 0.25
Nodes (10): _admins(), test_an_administrator_role_cannot_expire(), test_an_expired_assignment_grants_nothing(), test_an_inactive_administrator_does_not_count(), test_assign_and_revoke_are_audited(), test_concurrent_demotions_cannot_remove_every_administrator(), test_concurrent_suspension_and_demotion_cannot_remove_every_administrator(), test_the_last_administrator_cannot_be_demoted() (+2 more)

### Community 133 - "Cluster: test_cli_errors.py"
Cohesion: 0.24
Nodes (5): FakeSecrets, FakeSettings, _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1(), test_migrate_connection_failure_prints_a_fixed_message_and_exits_1()

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (7): _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), test_dollar_detection(), test_no_anchored_pattern_relies_on_match_or_dollar(), test_the_scan_sees_the_patterns_it_guards()

### Community 135 - "Cluster: licence_audit.py"
Cohesion: 0.27
Nodes (7): audit(), classify(), installed(), main(), _one(), Package, Report

### Community 136 - "_rotate"
Cohesion: 0.22
Nodes (3): _LazySecrets, _OneConnection, _rotate()

### Community 137 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (3): test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 138 - "Cluster: test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (7): _columns(), _insert(), _revisions(), _tables(), test_a_transaction_may_carry_an_invitation_hash(), test_downgrade_removes_only_the_invitation_hash(), test_the_invitation_hash_is_a_sha256_digest()

### Community 139 - "Cluster: test_examples_public_surface.py"
Cohesion: 0.29
Nodes (8): _private(), _private_path(), sample_sources(), test_nothing_under_examples_reaches_into_warden_internals(), test_the_check_sees_each_kind_of_private_reach(), test_the_sample_has_python_to_check(), violations(), _warden()

### Community 140 - "Principal"
Cohesion: 0.12
Nodes (9): bearer_token(), Forbidden, installed_identity(), Principal, require_permission(), dependency(), require_user(), ResourceScopeHook (+1 more)

### Community 141 - "Cluster: ast"
Cohesion: 0.36
Nodes (5): _from_warden(), _private(), test_no_module_reaches_into_another_modules_private_names(), _violations(), _warden_bindings()

### Community 142 - "audit_router"
Cohesion: 0.11
Nodes (8): timestamp_text(), row_to_json(), _address_or_none(), audit_router(), export_audit_events(), list_audit_events(), verify_audit_chain(), _query()

### Community 143 - "SingleUseTokens"
Cohesion: 0.17
Nodes (15): Purpose, SingleUseTokens, _consume(), _issue(), test_a_token_is_consumed_once(), test_a_token_is_stored_only_as_its_hash(), test_a_token_serves_only_its_own_purpose(), test_an_expired_token_is_refused() (+7 more)

### Community 144 - "._accept"
Cohesion: 0.10
Nodes (8): AcceptedInvitation, check(), complete(), complete(), PasskeyRegistration, SubjectPin, InvitationAcceptance, SecretWriter

### Community 145 - "passkey_support.py"
Cohesion: 0.19
Nodes (6): expire_challenge_of(), passkey_app(), set_method(), set_status(), finish_then_switch(), finish_then_suspend()

### Community 146 - "AnchorSigner"
Cohesion: 0.24
Nodes (3): AnchorSigner, _KeyLike, _SignatureLike

### Community 147 - "SyslogSettings"
Cohesion: 0.12
Nodes (8): SyslogSettings, StreamTransport, _base(), test_backoff_cap_must_not_be_below_the_initial_delay(), test_bad_sd_ids_are_refused(), test_defaults(), test_invalid_values_are_refused(), test_sd_id_defaults_to_the_registered_enterprise_number()

### Community 148 - "Cluster: test_no_direct_environment.py"
Cohesion: 0.29
Nodes (5): _enclosing_functions(), visit(), _findings(), test_no_module_reads_the_environment_or_files_directly(), test_the_anchors_file_exemption_covers_exactly_one_read()

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 152 - "Cluster: test_webauthn_unconfigured.py"
Cohesion: 0.31
Nodes (5): bare(), _config(), http(), test_it_boots_without_webauthn(), test_password_and_totp_sign_in_are_unchanged()

### Community 153 - "identity/conftest.py"
Cohesion: 0.14
Nodes (14): app(), audit_registry(), client(), config(), db(), identity(), keys(), mail() (+6 more)

### Community 154 - "Cluster: test_tls_fail_closed.py"
Cohesion: 0.46
Nodes (5): _findings(), _is_cert_required(), _is_true(), test_no_module_disables_tls_verification(), test_the_scan_reaches_the_transport_and_it_requires_verification()

### Community 155 - "examples/conftest.py"
Cohesion: 0.09
Nodes (12): dsn(), migrated_dsn(), pg_admin_url(), pool(), client(), console(), make_console(), build() (+4 more)

### Community 156 - "Cluster: test_database.py"
Cohesion: 0.46
Nodes (5): _count(), test_database_uses_the_pool_it_was_given(), test_transaction_commits_on_success(), test_transaction_joins_the_callers_transaction(), test_transaction_rolls_back_on_error()

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "BaseModel"
Cohesion: 0.25
Nodes (4): AuditEventPage, AuditEventView, BrokenLinkView, ChainVerification

### Community 159 - "load_settings"
Cohesion: 0.17
Nodes (8): KonfigSecrets, load_settings(), write_config(), test_attestation_roots_added_to_the_configuration_load(), test_every_secret_in_the_example_is_a_dev_only_value(), test_init_seeds_the_secrets_warden_needs(), test_the_example_configuration_has_the_passkey_registration_link(), test_the_example_configuration_loads_through_konfig()

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "Cluster: test_client_guide.py"
Cohesion: 0.47
Nodes (3): _contract_routes(), test_every_contract_route_is_linked_from_the_guide(), test_every_route_the_guide_names_is_in_the_contract()

### Community 162 - "test_identity_throttle.py"
Cohesion: 0.19
Nodes (12): _fail(), test_a_password_alone_does_not_reset_the_count_when_mfa_follows(), test_a_successful_sign_in_resets_the_count(), test_another_address_is_not_affected(), test_attempts_beyond_the_limit_are_refused_even_with_the_right_password(), test_completing_the_second_factor_resets_the_count(), test_concurrent_attempts_cannot_exceed_the_limit(), test_expired_attempt_records_can_be_pruned() (+4 more)

### Community 165 - "test_readme.py"
Cohesion: 0.43
Nodes (4): _targets(), test_every_link_is_absolute(), test_link_check_refuses_relative_link_and_image(), test_readme_has_links()

### Community 169 - "test_webauthn_credentials.py"
Cohesion: 0.18
Nodes (9): test_an_invalid_nickname_is_refused(), test_another_users_credential_cannot_be_touched(), test_list_count_rename_and_remove(), test_no_credential_material_reaches_logs_or_errors(), test_prune_removes_only_expired_challenges(), test_remove_all_removes_only_that_users_credentials(), challenge_of(), expire_challenges() (+1 more)

### Community 176 - "subprocess"
Cohesion: 0.36
Nodes (4): test_every_exported_name_resolves_once(), test_identity_does_not_re_export_the_sso_presets(), test_the_public_names_match_the_snapshot(), test_the_root_package_names_the_subpackages_and_imports_none()

### Community 177 - "ceremony.js"
Cohesion: 0.24
Nodes (10): call(), create(), field(), flows, keep(), outcome, register(), state (+2 more)

### Community 178 - "fastapi"
Cohesion: 0.25
Nodes (3): JwkSet, _JwkSetResponse, OkpJwk

### Community 181 - "test_console_gaps.py"
Cohesion: 0.22
Nodes (4): test_every_gap_names_its_question(), test_every_gap_the_screens_use_is_defined(), test_the_passkey_flag_is_no_longer_a_gap(), test_the_totp_reset_is_no_longer_a_gap()

### Community 183 - ".prune"
Cohesion: 0.09
Nodes (5): check_interval(), Pruner, PruneReport, scheduled(), loop()

### Community 186 - "subprocess"
Cohesion: 0.26
Nodes (6): _device_modules_after(), test_importing_warden_loads_no_fido2_device_code(), test_the_probe_sees_device_code_when_it_is_loaded(), test_importing_the_key_store_loads_no_web_framework(), test_the_probe_sees_the_web_framework_when_it_is_loaded(), _web_modules_after()

## Knowledge Gaps
- **14 isolated node(s):** `cognisn-warden`, `AuditChainConflict`, `Append-only audit database roles (INSERT and SELECT only)`, `Canonical JSON row form (warden.audit.row.v1)`, `Details cap and warden.truncated marker` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1536 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **29 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `typing`, `TokenPair`, `Identity Service Operations`, `Signing Key Store`, `Invitation and Reset Tests`, `test_identity_roles.py`, `WebAuthn Second Factor Tests`, `contract.py`, `Principal`, `SSO Sign-In Flow Tests`, `Audit Recorder Tests`, `SingleUseTokens`, `http_client`, `passkey_support.py`, `SSO Invitation Tests`, `identity/__init__.py`, `Single Sign-On Service`, `WebAuthn Registration Tests`, `Audit Anchor Format`, `Cluster: test_webauthn_unconfigured.py`, `Users and Sign-In Methods`, `identity/conftest.py`, `Second Factor Reset Tests`, `TOTP Reset Tests`, `Auth Router Helpers`, `SSO Settings Store`, `test_identity_throttle.py`, `test_identity_key_publication.py`, `Password Resets and Links`, `TOTP MFA Tests`, `Cluster: build_admin_router()`, `Cluster: test_webauthn_authentication.py`, `Cluster: Mfa`, `test_identity_prune.py`, `Cluster: httpx`, `.prune`, `Cluster: Mailer`, `Cluster: SecretBox`, `build_reference_app`, `test_a_key_registered_while_switching_to_sso_only_never_leaves_both`, `Cluster: console/cli.py`, `Cluster: test_identity_apikeys.py`, `Cluster: PermissionRegistry`, `Cluster: identity_support.py`, `test_identity_reset.py`, `test_webauthn_live.py`, `Cluster: Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `Cluster: sso.py`, `Cluster: PolicyStore`, `Roles`, `Cluster: test_identity_admin_routes.py`, `Cluster: test_console_app.py`, `Cluster: test_identity_sign_in.py`, `Cluster: test_sso_admin_routes.py`, `Cluster: .sign_in()`, `.transaction`, `Cluster: test_sso_issuer.py`, `test_passkey_invitation.py`, `Cluster: test_identity_lifecycle_routes.py`, `Cluster: test_sso_break_glass_live.py`, `Cluster: WardenConfig`, `Cluster: test_identity_client_address.py`?**
  _High betweenness centrality (0.124) - this node is a cross-community bridge._
- **Are the 43 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 43 INFERRED edges - model-reasoned connections that need verification._
- **What connects `cognisn-warden`, `AuditChainConflict`, `Append-only audit database roles (INSERT and SELECT only)` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `typing` be split into smaller, more focused modules?**
  _Cohesion score 0.04569402228976697 - nodes in this community are weakly interconnected._
- **Why does `Database` connect `Audit Recorder Tests` to `test_passkey_sign_in.py`, `typing`, `test_identity_roles.py`, `Signing Key Store`, `Invitation and Reset Tests`, `Identity`, `Audit Anchors`, `_rotate`, `WebAuthn Second Factor Tests`, `SSO Sign-In Flow Tests`, `http_client`, `Syslog Transport`, `SingleUseTokens`, `test_audit_query.py`, `SSO Invitation Tests`, `identity/__init__.py`, `Single Sign-On Service`, `passkey_support.py`, `WebAuthn Registration Tests`, `Purpose`, `Users and Sign-In Methods`, `identity/conftest.py`, `Second Factor Reset Tests`, `Cluster: test_database.py`, `TOTP Reset Tests`, `Cluster: test_webauthn_unconfigured.py`, `SSO Settings Store`, `Audit Retention`, `test_identity_throttle.py`, `Syslog Forwarder`, `TOTP MFA Tests`, `test_webauthn_credentials.py`, `Cluster: SyslogForwarder`, `Cluster: warden/cli.py`, `Cluster: test_webauthn_authentication.py`, `test_identity_prune.py`, `Cluster: httpx`, `.prune`, `Cluster: soft_authenticator.py`, `Cluster: SecretBox`, `build_reference_app`, `Cluster: console/cli.py`, `Cluster: test_identity_apikeys.py`, `Cluster: PermissionRegistry`, `Cluster: identity_support.py`, `test_identity_reset.py`, `test_webauthn_live.py`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `Cluster: PolicyStore`, `ConnectionSource`, `Roles`, `Cluster: test_identity_admin_routes.py`, `Cluster: test_key_publication.py`, `Cluster: test_identity_sign_in.py`, `Cluster: test_sso_admin_routes.py`, `Cluster: .sign_in()`, `Cluster: test_audit_router.py`, `Cluster: test_audit_verify.py`, `.transaction`, `Cluster: test_sso_issuer.py`, `test_passkey_invitation.py`, `Cluster: test_syslog_routes.py`, `Cluster: test_identity_lifecycle_routes.py`, `Cluster: test_sso_break_glass_live.py`, `test_audit_grants.py`, `Cluster: WardenConfig`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`?**
  _High betweenness centrality (0.103) - this node is a cross-community bridge._
- **Are the 93 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 93 INFERRED edges - model-reasoned connections that need verification._
- **Should `SSO Provider Discovery` be split into smaller, more focused modules?**
  _Cohesion score 0.05246523388116309 - nodes in this community are weakly interconnected._