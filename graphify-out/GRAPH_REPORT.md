# Graph Report - warden  (2026-11-24)

## Corpus Check
- 354 files · ~392,964 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 7666 nodes · 25339 edges · 233 communities (210 shown, 23 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 2244 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `e81c3f24`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_passkey_sign_in.py
- test_password_feedback.py
- test_sso_provider.py
- AuditEvent
- Identity
- KeyStore
- RecordingSender
- PasswordResets
- AuditRecorder
- h
- test_webauthn_mfa.py
- contract.py
- build_password_admin_router
- http_sign_in
- test_audit_recorder.py
- test_webauthn_reset.py
- SoftwareAuthenticator
- test_console_password_policy.py
- test_sso_invitations.py
- PasswordPolicies
- SingleSignOn
- Invitations
- .finish_authentication
- anchor.py
- password_enforcement.py
- test_sso_sealing.py
- test_config_webauthn.py
- chain.py
- test_identity_totp_reset.py
- test_config.py
- json_response
- SsoSettingsStore
- CI Workflows
- test_console_browser.py
- ActionRegistry
- http.py
- test_identity_passwords.py
- test_syslog_forwarder.py
- rules.py
- current_code
- test_syslog_transport.py
- test_password_sign_in.py
- SyslogForwarder
- admin.py
- settings_admin.py
- alembic
- ApiKeys
- WebAuthn
- test_audit_retention.py
- Cluster: syslog
- Mfa
- identity_support.py
- FakeIdp
- test_distributions.py
- test_config_fields.py
- WardenConfig
- soft_authenticator.py
- MailKind
- test_console_passkeys.py
- export_openapi.py
- typing
- password_policy/__init__.py
- test_identity_apikeys.py
- PermissionRegistry
- test_proxy.py
- audit_rows
- migrate
- pytest
- LiveBrowser
- Sessions
- test_identity_dependencies.py
- test_passkey_registration_link.py
- test_password_watch_lists.py
- test_password_enforcement_keys.py
- DevClock
- test_password_admin_routes.py
- PolicySettings
- identity/__init__.py
- test_identity_admin_routes.py
- current_revision
- test_webauthn_live.py
- test_key_publication.py
- test_sso_capabilities.py
- verify.py
- test_openapi_contract.py
- test_identity_migration.py
- migrate.py
- test_identity_sign_in.py
- test_sso_admin_routes.py
- Client-behaviour guide
- Cluster: warden design overview
- modules
- webauthn/service.py
- webauthn/challenges.py
- test_passkey_sign_in_rules.py
- test_cli_audit_anchor.py
- attestation.py
- test_db_schema.py
- test_identity_tokens.py
- test_sign_in_methods_sso.py
- test_sso_preset_label_only.py
- check_dist.py
- Users
- Cluster: publish-pypi
- field_validator
- test_passkey_invitation.py
- test_sso_entra_email.py
- test_audit_source_ip_tripwire.py
- test_identity_lifecycle_routes.py
- WatchLists
- SecretBox
- test_audit_router.py
- test_cli.py
- Cluster: Audit hash chain specification
- test_unpinning_records_the_address
- collector.py
- race
- test_audit_grants.py
- httpx
- Cluster: with
- HttpConfig
- test_sso_issuer.py
- test_audit_chain_recorder.py
- Cluster: test_identity_client_address.py
- publish.yml
- SyslogSettings
- .rotate
- test_lifecycle_migration.py
- test_identity_reset.py
- LiveServer
- test_password_policy_migration.py
- Purpose
- checkpoint.py
- test_sso_invitation_migration.py
- Cluster: test_anchored_patterns.py
- test_mfa_factors_webauthn.py
- certs.py
- ._accept
- password_support.py
- test_examples_public_surface.py
- console_router
- test_no_private_imports.py
- test_password_policy_store.py
- SingleUseTokens
- test_password_cli.py
- test_identity_prune.py
- test_sso_break_glass_live.py
- test_console_capabilities.py
- test_no_direct_environment.py
- Cluster: updates
- SsoError
- _AfterFirstQuery
- Database
- test_identity_capabilities.py
- test_sso_guard_routes.py
- ceremony.js
- PasswordHistory
- Cluster: verify
- test_sign_in_methods_migration.py
- console/cli.py
- Cluster: rsyslog
- test_password_hibp.py
- test_identity_users.py
- test_licence_audit.py
- test_console_gaps.py
- test_identity_throttle.py
- test_syslog_routes.py
- _FieldProblems
- Cluster: examples/__init__.py
- test_browser_rules_vectors.py
- Cluster: cognisn-warden
- test_cli_passwords_errors.py
- main
- test_connection_failure_prints_a_fixed_message_and_exits_1
- passwordrules.js
- BuiltinList
- test_settings_routes.py
- tests/conftest.py
- test_console_source_ip.py
- test_sso_setup_guides.py
- TransportError
- test_identity_roles.py
- licence_audit.py
- throttle.py
- test_identity_key_publication.py
- copy
- APIRouter
- .connection
- test_sso_invitation_sealing_migration.py
- test_identity_totp_unit.py
- .__call__
- _LazySecrets
- complete_sign_in
- resolve
- .name
- Transport
- run_vectors.mjs
- build_console
- MemorySecrets
- FakeSettings
- warden sample console
- pathlib
- Single sign-on setup guides
- .install
- keys_router
- verify_chain
- .loose_text
- test_password_builtin.py
- .see
- subprocess
- The built-in common-password list
- .__init__
- test_failed_sign_in_timing_is_unchanged_by_the_passwords_state
- ._handle
- SecretReader
- test_readme.py
- sso_config
- console/__init__.py
- _Invalid
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
- .client
- _Prioritised
- _Abort

## God Nodes (most connected - your core abstractions)
1. `Identity` - 779 edges
2. `Database` - 719 edges
3. `audit_rows()` - 243 edges
4. `RecordingSender` - 210 edges
5. `KeyStore` - 176 edges
6. `FakeIdp` - 147 edges
7. `ActionRegistry` - 138 edges
8. `AuditRecorder` - 134 edges
9. `AuditEvent` - 126 edges
10. `User` - 125 edges

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

## Communities (233 total, 23 thin omitted)

### Community 0 - "test_passkey_sign_in.py"
Cohesion: 0.11
Nodes (60): expire_challenge_of(), give_passkey(), passkey_assertion(), passkey_config(), passkey_sign_in(), Any, Expire only the challenge a browser response answers, as if its lifetime had…, The identity tests' configuration, with the passkey registration link. (+52 more)

### Community 1 - "test_password_feedback.py"
Cohesion: 0.11
Nodes (29): failing_transport(), handler(), listing_transport(), MockTransport, Stubbed range API transports (imported as ``hibp_stub``): no live service in…, A range API that cannot be reached., A range API that lists ``passwords`` (and pads with zero-count entries)., _counts() (+21 more)

### Community 2 - "test_sso_provider.py"
Cohesion: 0.09
Nodes (51): Discovery, ProviderHttp, ProviderMetadata, AsyncClient, The provider's metadata, cached per issuer., Fetch and check the metadata, bypassing the cache., The one HTTP client single sign-on uses to reach the provider. Redirects are…, IdTokenValidator (+43 more)

### Community 3 - "AuditEvent"
Cohesion: 0.03
Nodes (68): Register warden's audit actions. Idempotent., register_audit_actions(), AuditEvent, BaseModel, One thing that happened: who did what to which resource, and how it ended., warden's audit subsystem. ``warden.audit`` imports nothing from…, ActionSpec, _check_summary() (+60 more)

### Community 4 - "Identity"
Cohesion: 0.03
Nodes (79): Record ``event`` through the installed recorder. See ``AuditRecorder.record``., record_audit(), Challenge, _Account, _ChangeDue, _credential_id(), Identity, PasswordChangeIssued (+71 more)

### Community 5 - "KeyStore"
Cohesion: 0.06
Nodes (52): KeysConfig, Ed25519 signing keys. Private halves live in konfig's secrets store., KeyStore, KeyStoreError, AsyncConnection, Composable, Exception, Sign and verify with warden's Ed25519 keys. (+44 more)

### Community 6 - "RecordingSender"
Cohesion: 0.08
Nodes (61): _Abort, InvitationError, Exception, An administrative invitation change was refused. Messages carry no values., A role the invited user receives on acceptance, optionally expiring., An identity the caller has already verified with the identity provider., Ends an acceptance transaction without committing it., StagedGrant (+53 more)

### Community 7 - "PasswordResets"
Cohesion: 0.16
Nodes (18): _Account, _Checked, PasswordResets, Any, AsyncConnection, NoReturn, SourceIp, UUID (+10 more)

### Community 8 - "AuditRecorder"
Cohesion: 0.12
Nodes (61): AnchorRecord, An anchor written to the trail, and the id of the row that carries it., AuditRecorder, Records events to the audit table and offers them to sinks., Verify the chain, then check each external anchor against it, in one snapshot.…, verify_anchors(), age(), Move ``recorded_at`` back ``days`` for ``ids`` (every row if ``None``), then… (+53 more)

### Community 9 - "h"
Cohesion: 0.08
Nodes (135): apiKeysScreen(), capabilities(), chosen(), FACTORS, invitationsScreen(), METHODS, pendingText(), POLICY_FIELDS (+127 more)

### Community 10 - "test_webauthn_mfa.py"
Cohesion: 0.12
Nodes (69): _amr(), _app(), _assertion(), _bearer(), _challenge(), http(), _key_sign_in(), _options() (+61 more)

### Community 11 - "contract.py"
Cohesion: 0.03
Nodes (146): Public sign-in routes. The product mounts them under…, AffectedUsersProposalBody, BuiltinListBody, ChallengeBody, ChangePasswordBody, CodeBody, detail(), _Doc (+138 more)

### Community 12 - "build_password_admin_router"
Cohesion: 0.09
Nodes (69): build_password_admin_router(), actor(), add_entries(), add_terms(), affected(), attach_list(), attached_to(), attachment() (+61 more)

### Community 13 - "http_sign_in"
Cohesion: 0.11
Nodes (29): http_sign_in(), identity_of(), AsyncClient, Response, The Identity installed in the app an ASGI test client talks to., ``POST <prefix>/sign-in`` carried through the second factor over HTTP. The…, Replace the default policy's settings (keeping its name)., set_default() (+21 more)

### Community 14 - "test_audit_recorder.py"
Cohesion: 0.15
Nodes (27): BrokenSink, CommitCheckingSink, _event(), listener(), _notifications(), Any, AsyncConnection, fixture (+19 more)

### Community 15 - "test_webauthn_reset.py"
Cohesion: 0.17
Nodes (26): _admin(), _bearer(), http(), Any, AsyncClient, fixture, MonkeyPatch, Response (+18 more)

### Community 16 - "SoftwareAuthenticator"
Cohesion: 0.11
Nodes (56): fido2_utils, One authenticator, holding the credentials it has created. ``counter_step`` is…, SoftwareAuthenticator, LogCaptureFixture, parametrize, UserFactory, The credential store (list, rename, remove, count) and challenge pruning., test_an_invalid_nickname_is_refused() (+48 more)

### Community 17 - "test_console_password_policy.py"
Cohesion: 0.07
Nodes (72): assert_strict_csp(), bearer(), http_sign_in(), make_user(), AsyncClient, Response, ``POST /auth/sign-in`` carried through the second factor: the final response., A password sign-in carried through its second factor (always required since… (+64 more)

### Community 18 - "test_sso_invitations.py"
Cohesion: 0.11
Nodes (58): Body, Started, accept(), acceptance_rows(), app(), _bodies(), config(), handoffs_of() (+50 more)

### Community 19 - "PasswordPolicies"
Cohesion: 0.09
Nodes (42): PasswordPolicyConflict, PasswordPolicyError, PasswordPolicyNotFound, A password policy, or a change to one, was refused., No password policy has that id., The change clashes with the stored state: a stale version, a name or priority…, Delete history beyond the largest count any policy keeps; returns how many., _check_priority() (+34 more)

### Community 20 - "SingleSignOn"
Cohesion: 0.08
Nodes (33): Single sign-on's subject pinning, run inside the acceptance transaction.…, SubjectPin, _challenge(), ConfigurationCheck, ConfigurationReport, _hash(), InvitationAcceptance, _method_refusal() (+25 more)

### Community 21 - "Invitations"
Cohesion: 0.14
Nodes (15): Invitation, Invitations, _Invitee, Any, AsyncConnection, datetime, UUID, An invitation just created or resent. The link went by mail and is not kept. (+7 more)

### Community 22 - ".finish_authentication"
Cohesion: 0.10
Nodes (25): Decide, PublicKeyCredentialDescriptor, _cose_key(), _extension_results(), _parse(), Any, AsyncConnection, AuthenticatorData (+17 more)

### Community 23 - "anchor.py"
Cohesion: 0.06
Nodes (61): cryptography_hazmat_primitives_asymmetric_ed25519, Anchor, AnchorError, AnchorSigner, _b64url(), _b64url_decode(), _from_ndjson(), _from_syslog() (+53 more)

### Community 24 - "password_enforcement.py"
Cohesion: 0.06
Nodes (40): SetPlace, AcceptedPassword, _match_details(), PasswordEnforcement, PasswordFailure, PendingChange, Any, AsyncConnection (+32 more)

### Community 25 - "test_sso_sealing.py"
Cohesion: 0.14
Nodes (27): cryptography_hazmat_primitives, cryptography_hazmat_primitives_ciphers_aead, cryptography_hazmat_primitives_kdf_hkdf, OIDC single sign-on for warden's identity subsystem., _derive_key(), open_invitation(), Sealing an invitation token into a single sign-on login transaction. An…, Seal ``token`` to the browser's ``binding`` and the transaction's… (+19 more)

### Community 26 - "test_config_webauthn.py"
Cohesion: 0.11
Nodes (36): _certificate(), _parse(), Any, parametrize, Start-up validation of the WebAuthn settings (rulings P2, P3 and P7 of 6…, _refused(), _Secrets, test_a_malformed_passkey_registration_link_is_refused() (+28 more)

### Community 27 - "chain.py"
Cohesion: 0.07
Nodes (50): decimal, JsonValue, address_text(), canonical_json(), cap_details(), ChainRow, _encode(), _fields() (+42 more)

### Community 28 - "test_identity_totp_reset.py"
Cohesion: 0.10
Nodes (45): _app(), _bearer(), client(), _counts(), _enrol(), _live_sessions(), AsyncClient, FastAPI (+37 more)

### Community 29 - "test_config.py"
Cohesion: 0.07
Nodes (66): ConfigError, Exception, The configuration is missing, unknown or inconsistent. The message lists every…, FakeSecrets, FakeSettings, _load(), _parse(), Any (+58 more)

### Community 30 - "json_response"
Cohesion: 0.07
Nodes (94): bearer_token(), json_response(), Any, Response, The request body as a JSON object, or None if it is anything else., read_object(), refusal(), build_auth_router() (+86 more)

### Community 31 - "SsoSettingsStore"
Cohesion: 0.13
Nodes (22): _from_config(), _plain(), Any, AsyncConnection, SourceIp, UUID, Whether single sign-on works: enabled, with an issuer and a client id., Who would be locked out without single sign-on, as the refusal; None if nobody. (+14 more)

### Community 32 - "CI Workflows"
Cohesion: 0.07
Nodes (45): runs-on, steps, concurrency, cancel-in-progress, group, runs-on, steps, jobs (+37 more)

### Community 33 - "test_console_browser.py"
Cohesion: 0.13
Nodes (20): code_for(), ConsoleBrowser, enrol_authenticator(), forced(), plain(), Any, fixture, The sample console's screens in a real browser (marked ``integration``).… (+12 more)

### Community 34 - "ActionRegistry"
Cohesion: 0.04
Nodes (98): IntEnum, The audit actions warden's own audit subsystem records., _now(), datetime, The audit event model., Event severity, numbered as RFC 5424 syslog severities., Severity, ActionRegistry (+90 more)

### Community 35 - "http.py"
Cohesion: 0.07
Nodes (54): fastapi_responses, client_ip(), Network, Request, SourceIp, HTTP helpers shared by identity's routers and dependencies. Every…, The client address, for audit events and the sign-in throttle key. Resolved by…, _body_field() (+46 more)

### Community 36 - "test_identity_passwords.py"
Cohesion: 0.13
Nodes (14): Match, The outcome of checking a password against a stored hash., Check ``password`` against ``encoded``; never raises for a bad input., Verification, _verify_legacy(), _legacy(), parametrize, Password hashing: Argon2id for new hashes, legacy PBKDF2 verified for rehash… (+6 more)

### Community 37 - "test_syslog_forwarder.py"
Cohesion: 0.20
Nodes (39): ForwarderFactory, _advisory_locks(), _event(), eventually(), FakeCollector, forwarders(), make(), _leader() (+31 more)

### Community 38 - "rules.py"
Cohesion: 0.05
Nodes (80): Each rule's result and any watch-list match. Never history; stores and audits…, _bool(), _classes(), _detail_tokens(), evaluate(), Evaluation, _int(), _local_part() (+72 more)

### Community 39 - "current_code"
Cohesion: 0.08
Nodes (60): code_at(), The TOTP time step containing ``timestamp`` (Unix seconds)., The code for ``step`` (RFC 4226 dynamic truncation)., step_for(), current_code(), _challenge(), _enrolled(), _fresh_code() (+52 more)

### Community 40 - "test_syslog_transport.py"
Cohesion: 0.11
Nodes (40): frame(), open_transport(), SSLContext, Connect to the collector named in ``settings``; ``TransportError`` on failure., Frame ``message`` for a stream transport (RFC 6587)., A client context that verifies the chain and host name, TLS 1.2 or later. The…, tls_context(), Authority (+32 more)

### Community 41 - "test_password_sign_in.py"
Cohesion: 0.14
Nodes (48): Clock, http(), A settable clock for ``Identity(clock=...)``: real time plus an offset., _amr(), clock(), _complete(), identity(), _legacy_password() (+40 more)

### Community 42 - "SyslogForwarder"
Cohesion: 0.07
Nodes (26): initialise_cursor(), load_cursor(), Any, AsyncConnection, The stored cursor, or ``None`` if the forwarder has never run., Store ``start`` if no cursor exists yet, and return the cursor in force., Advance the stored cursor to ``value``; never moves it backwards., store_cursor() (+18 more)

### Community 43 - "admin.py"
Cohesion: 0.07
Nodes (68): LastAdministratorError, Exception, A role change was refused. Messages carry identifiers only., The change would leave no active administrator., RoleError, _api_key(), _assignment(), _BadRequest (+60 more)

### Community 44 - "settings_admin.py"
Cohesion: 0.06
Nodes (60): Forbidden, installed_identity(), Principal, HTTPException, Protocol, Request, FastAPI dependencies: ``require_user``, ``require_permission`` and the…, A dependency requiring ``permission``; with ``scoped``, also the product's… (+52 more)

### Community 45 - "alembic"
Cohesion: 0.05
Nodes (12): alembic, sqlalchemy, sqlalchemy_dialects, Connection, Alembic environment for warden's own chain, pinned to the ``warden`` schema.…, _run(), Password policies and watch lists: the whole feature's schema. Revision ID:…, Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles,… (+4 more)

### Community 46 - "ApiKeys"
Cohesion: 0.11
Nodes (19): ApiKey, ApiKeyError, ApiKeys, _hash(), Any, datetime, Exception, NoReturn (+11 more)

### Community 47 - "WebAuthn"
Cohesion: 0.16
Nodes (41): The WebAuthn relying party: ceremonies and the credential store. A ``begin_*``…, Delete expired challenges; returns how many., WebAuthn, _enrolled(), Any, parametrize, UserFactory, UUID (+33 more)

### Community 48 - "test_audit_retention.py"
Cohesion: 0.13
Nodes (33): Any, Connection, Recompute every hash and link from the first surviving row's ``prev_hash``., rechain(), _age(), _all(), keys(), MemorySecrets (+25 more)

### Community 49 - "Cluster: syslog"
Cohesion: 0.05
Nodes (36): console, port, provider_ca_file, dsn, accept_invitation_link, passkey_registration_link, public_base_url, reset_password_link (+28 more)

### Community 50 - "Mfa"
Cohesion: 0.09
Nodes (26): Enrolment, _hash_token(), Mfa, Any, AsyncConnection, ChallengePurpose, SecondFactor, SourceIp (+18 more)

### Community 51 - "identity_support.py"
Cohesion: 0.10
Nodes (52): age_sessions(), direct_session(), enrol_totp(), fresh_totp_code(), identity_code(), Any, UUID, Helpers shared by identity tests (imported as ``identity_support``). (+44 more)

### Community 52 - "FakeIdp"
Cohesion: 0.11
Nodes (75): An opaque cursor for ``list(after=...)``: the users listed after ``user``., User, FakeIdp, callback(), completion(), handoff(), provider_code(), Any (+67 more)

### Community 53 - "test_distributions.py"
Cohesion: 0.13
Nodes (33): dist(), _load(), _only(), fixture, ModuleType, MonkeyPatch, parametrize, Path (+25 more)

### Community 54 - "test_config_fields.py"
Cohesion: 0.14
Nodes (29): _parse(), Any, parametrize, Start-up validation of the fields added for 0.1.0a4. Every field below is…, _refused(), test_a_totp_issuer_with_spaces_is_allowed(), test_api_key_fields(), test_every_forwarder_setting_has_a_config_counterpart() (+21 more)

### Community 55 - "WardenConfig"
Cohesion: 0.05
Nodes (83): BinaryIO, sqlalchemy_exc, ExternalAnchor, An anchor found in an export: its line, its own row id when known, and the…, get_recorder(), Install the process-wide recorder ``record_audit`` uses; returns the previous…, set_recorder(), AnchorReport (+75 more)

### Community 56 - "soft_authenticator.py"
Cohesion: 0.07
Nodes (39): Algorithm, AttestationFormat, fido2, fido2_cose, FLAG, PrivateKey, ca(), make_webauthn() (+31 more)

### Community 57 - "MailKind"
Cohesion: 0.08
Nodes (45): MailConfig, Mail settings. The product implements the sender., _check(), format_expiry(), _load(), Mailer, MailKind, MailMessage (+37 more)

### Community 58 - "test_console_passkeys.py"
Cohesion: 0.16
Nodes (31): authenticator(), key_session(), Any, A software authenticator that makes passkeys: discoverable, verifying the user., An access token for a user holding no second factor, as if signed in with a key., amr(), browser(), link_token() (+23 more)

### Community 59 - "export_openapi.py"
Cohesion: 0.08
Nodes (26): argparse, build_reference_app(), contract_version(), main(), _NoDatabase, openapi_text(), _product_authorisation(), Any (+18 more)

### Community 60 - "typing"
Cohesion: 0.03
Nodes (111): argon2, argon2_exceptions, asyncio, base64, binascii, collections_abc, contextlib, cryptography_exceptions (+103 more)

### Community 61 - "password_policy/__init__.py"
Cohesion: 0.06
Nodes (54): ChangeChallenge, _hash(), PasswordChangeChallenges, Any, AsyncConnection, UUID, Use the challenge up; False if another request already did, or it lapsed., Count a refused attempt against the challenge, in its own transaction. (+46 more)

### Community 62 - "test_identity_apikeys.py"
Cohesion: 0.16
Nodes (23): _app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory (+15 more)

### Community 63 - "PermissionRegistry"
Cohesion: 0.05
Nodes (50): PermissionRegistry, The union of the named roles' permissions; a role no longer defined grants…, The product's permissions and the roles built from them., Register a permission. Re-registering it identically is a no-op., Define a role. An administrator role counts towards last-administrator…, Role, make_config(), MemorySecrets (+42 more)

### Community 64 - "test_proxy.py"
Cohesion: 0.12
Nodes (26): _address(), Any, Network, _Scope, Trusted-proxy middleware: the real client address behind a reverse proxy. A…, Parse one forwarded entry: a bare address, ``v4:port`` or ``[v6]:port``., The client address, given the peer and every ``X-Forwarded-For`` value in order., ASGI middleware setting ``scope["client"]`` to the resolved client address. (+18 more)

### Community 65 - "audit_rows"
Cohesion: 0.10
Nodes (41): audit_rows(), test_a_reset_of_an_unknown_user_is_refused(), admin(), app(), assert_consistent(), has_password(), mailless(), Any (+33 more)

### Community 66 - "migrate"
Cohesion: 0.12
Nodes (27): heads(), migrate(), The chain's head revisions. A healthy chain has exactly one., Upgrade the database at ``dsn`` to ``revision`` in one transaction., _columns(), _constraints(), The audit chain migration: reversible, and refuses rows it cannot chain., test_downgrade_removes_the_chain_revision_and_upgrade_restores_it() (+19 more)

### Community 67 - "pytest"
Cohesion: 0.15
Nodes (26): os, pytest, accept_through_sso(), AsyncClient, parametrize, Live check: an invitation accepted through single sign-on, against the stub…, test_live_invitation_accepted_through_sso_then_sign_in_by_subject(), app() (+18 more)

### Community 68 - "LiveBrowser"
Cohesion: 0.13
Nodes (11): _b64(), _b64url(), LiveBrowser, Any, BaseException, T, Chromium with one page, its DevTools session and its virtual authenticators., Run a coroutine on the browser's loop and wait for it from the test's loop. (+3 more)

### Community 69 - "Sessions"
Cohesion: 0.06
Nodes (35): PolicyStore, Any, AsyncConnection, Event, SourceIp, The effective session policy, cached per replica and invalidated over NOTIFY., Whether ``listen()`` currently holds a LISTEN on the policy channel., Forget the cached policy; the next ``current()`` re-reads it. (+27 more)

### Community 70 - "test_identity_dependencies.py"
Cohesion: 0.12
Nodes (22): _app(), _bearer(), CaseScope, AsyncClient, FastAPI, fixture, parametrize, Request (+14 more)

### Community 71 - "test_passkey_registration_link.py"
Cohesion: 0.18
Nodes (36): UUID, set_status(), admin(), config(), _credential_count(), http(), _identity(), _link() (+28 more)

### Community 72 - "test_password_watch_lists.py"
Cohesion: 0.11
Nodes (37): WatchListKind, builtin(), _lines(), lists(), policies(), Any, fixture, parametrize (+29 more)

### Community 73 - "test_password_enforcement_keys.py"
Cohesion: 0.33
Nodes (10): _amr(), Any, AsyncClient, parametrize, UserFactory, Password policies with security keys and passkeys (rulings PW9 and P4 to P7). A…, _sign_in(), test_a_forced_enrolment_with_a_key_answers_the_change_with_the_key() (+2 more)

### Community 74 - "DevClock"
Cohesion: 0.12
Nodes (17): work(), DevClock, The real time plus a settable whole-day offset., client(), console(), make_console(), build(), Any (+9 more)

### Community 75 - "test_password_admin_routes.py"
Cohesion: 0.07
Nodes (68): bearer(), create_policy(), policy_body(), Any, AsyncClient, Helpers for the password policy and watch list administration route tests., app(), client() (+60 more)

### Community 76 - "PolicySettings"
Cohesion: 0.08
Nodes (34): RangeCache, Range answers for one recheck run, by prefix. Never kept beyond the run., PasswordRules, A policy's deterministic rules (PW3), passphrase setting (PW4) and tiers (PW5)., Raise ``PasswordPolicyError`` naming every inconsistent field., The versioned JSON shape a browser evaluates., PolicySettings, What an administrator sets on a policy: everything but its id, priority and… (+26 more)

### Community 77 - "identity/__init__.py"
Cohesion: 0.03
Nodes (130): enum, html, NewApiKey, API keys: long-lived bearer credentials for a user's scripts and integrations.…, A key just created. ``key`` is shown once and never stored., AuthenticationRefused, MfaError, Exception (+122 more)

### Community 78 - "test_identity_admin_routes.py"
Cohesion: 0.17
Nodes (25): admin(), app(), _bearer(), client(), AsyncClient, FastAPI, fixture, parametrize (+17 more)

### Community 79 - "current_revision"
Cohesion: 0.19
Nodes (26): current_revision(), The revision the database is at, or ``None`` if none is applied., _challenge(), _credential(), Any, Conn, parametrize, UUID (+18 more)

### Community 80 - "test_webauthn_live.py"
Cohesion: 0.25
Nodes (23): credentials(), enrol_key(), last_step(), live_sessions(), no_credential_material(), ok(), open_sign_in_challenges(), Any (+15 more)

### Community 81 - "test_key_publication.py"
Cohesion: 0.16
Nodes (22): client(), FakeSecrets, _kids(), Any, AsyncClient, fixture, parametrize, Key publication: the JWK Sets a product mounts at ``http.keys_prefix`` (design… (+14 more)

### Community 82 - "test_sso_capabilities.py"
Cohesion: 0.21
Nodes (18): app(), config(), idp(), offered(), Any, AsyncClient, FastAPI, fixture (+10 more)

### Community 83 - "verify.py"
Cohesion: 0.03
Nodes (108): AwareDatetime, BreakReason, csv, description, ExportFormat, io, ipaddress, json (+100 more)

### Community 84 - "test_openapi_contract.py"
Cohesion: 0.13
Nodes (20): fastapi_routing, document(), _load(), _operations(), Any, fixture, ModuleType, MonkeyPatch (+12 more)

### Community 85 - "test_identity_migration.py"
Cohesion: 0.19
Nodes (15): Connection, parametrize, UUID, Identity core's migration: its tables, their constraints, and a tested…, A sealed secret is nonce + ciphertext + tag; anything as short as a raw secret…, An unconfirmed enrolment can never record a used step (#130 at the schema…, _tables(), test_a_used_step_requires_a_confirmed_enrolment() (+7 more)

### Community 86 - "migrate.py"
Cohesion: 0.12
Nodes (23): alembic_config, alembic_runtime_migration, alembic_script, sqlalchemy_pool, _config(), downgrade(), migrate_connection(), Connection (+15 more)

### Community 87 - "test_identity_sign_in.py"
Cohesion: 0.18
Nodes (24): statistics, _assert_refusal(), Any, AsyncClient, parametrize, Response, UserFactory, Password sign-in over HTTP: outcomes, uniform refusals, timing and rehashing. (+16 more)

### Community 88 - "test_sso_admin_routes.py"
Cohesion: 0.14
Nodes (27): app(), authorise(), config(), idp(), Any, AsyncClient, FastAPI, fixture (+19 more)

### Community 89 - "Client-behaviour guide"
Cohesion: 0.21
Nodes (14): warden changelog, Passkey sign-in and passkey_only method (0.1.0b11), WebAuthn security keys and passkeys as second factor (0.1.0b10), OIDC single sign-on with PKCE, pre-provisioned accounts, HTTP contract docs/contract/openapi.json, Trusted-proxy middleware, Administrator's MFA and TOTP reset, Client-behaviour guide (+6 more)

### Community 90 - "Cluster: warden design overview"
Cohesion: 0.11
Nodes (23): fido2 runtime dependency (0.1.0b9), Integration procedure (merge, re-chain, stamp), Migrations across parallel workstreams, Mutation-checked guard and tripwire tests, warden project working agreement (CLAUDE.md), Single-use credentials consumed by one guarded atomic write, Acceptance tests from Termograph hardening findings, Argon2id passwords with legacy PBKDF2 rehash (D15) (+15 more)

### Community 91 - "modules"
Cohesion: 0.15
Nodes (27): Pattern, _docstring_nodes(), identifiers(), module_name(), modules(), AST, Path, Helpers for tripwires that read warden's own source. (+19 more)

### Community 92 - "webauthn/service.py"
Cohesion: 0.07
Nodes (39): The signed-in user's security keys and passkeys, oldest first., Challenges, Delete expired challenges, used or not; returns how many., Exception, StrEnum, UUID, Refusals from the WebAuthn ceremonies and the credential store. A refusal names…, Why a ceremony, or a change to a credential, was refused. (+31 more)

### Community 93 - "webauthn/challenges.py"
Cohesion: 0.25
Nodes (11): Ceremony, ConsumedChallenge, _hash(), IssuedChallenge, Any, AsyncConnection, StrEnum, UUID (+3 more)

### Community 94 - "test_passkey_sign_in_rules.py"
Cohesion: 0.14
Nodes (27): _allow(), config(), http(), _last_failure(), _passkey_user(), Any, AsyncClient, fixture (+19 more)

### Community 95 - "test_cli_audit_anchor.py"
Cohesion: 0.26
Nodes (18): _export(), FakeSecrets, CaptureFixture, fixture, Path, The warden CLI: audit anchor, and audit verify --anchors, against a real…, The whole trail as NDJSON, the way a SIEM export of warden's export would hold…, secrets() (+10 more)

### Community 96 - "attestation.py"
Cohesion: 0.13
Nodes (13): AttestationObject, Certificate, fido2_attestation_base, fido2_webauthn, itertools, AttestationNotTrusted, _is_ca(), _issued_by() (+5 more)

### Community 97 - "test_db_schema.py"
Cohesion: 0.10
Nodes (11): _lock_keys(), parametrize, Schema names other modules agree on: the audit channel, lock keys and setting…, String values ``warden.db.schema`` owns: table names and settings keys., Every module-level ``*_LOCK_KEY = <int>`` assignment under ``src/warden``., _schema_names(), test_advisory_lock_keys_anywhere_in_warden_are_distinct(), test_each_lock_key_is_a_signed_bigint_in_an_allocated_range() (+3 more)

### Community 98 - "test_identity_tokens.py"
Cohesion: 0.15
Nodes (33): _b64(), _parts(), AsyncClient, parametrize, UserFactory, Access tokens and refresh families., Token verification uses KeyStore.verify, never verify_historical., #131: a replayed refresh token is detected through its family. (+25 more)

### Community 99 - "test_sign_in_methods_sso.py"
Cohesion: 0.13
Nodes (34): Single sign-on cannot be turned off or cleared: someone signs in with it alone.…, SsoStillRequired, add_key(), app(), config(), enabled(), has_password(), idp() (+26 more)

### Community 100 - "test_sso_preset_label_only.py"
Cohesion: 0.18
Nodes (16): imported_modules(), Module, Absolute names of every module ``module`` imports, relative imports resolved., _names_identity(), Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design…, test_no_audit_module_imports_identity(), test_nothing_audit_depends_on_imports_identity(), _violations() (+8 more)

### Community 101 - "check_dist.py"
Cohesion: 0.08
Nodes (31): email_parser, dist_problems(), import_problems(), main(), _metadata_version(), Path, Check warden's built distributions, and the installed package, before…, Exactly one wheel and one sdist, each of them good. (+23 more)

### Community 102 - "Users"
Cohesion: 0.08
Nodes (32): lock_administrators(), Any, AsyncConnection, datetime, SourceIp, UUID, Role assignments in ``warden.role_assignments``., The user's unexpired role names. (+24 more)

### Community 103 - "Cluster: publish-pypi"
Cohesion: 0.12
Nodes (20): outputs, runs-on, name, url, jobs, build, publish-pypi, publish-testpypi (+12 more)

### Community 104 - "field_validator"
Cohesion: 0.08
Nodes (15): AsyncBaseTransport, _check_secret_name(), _check_template(), _check_url(), IdentityConfig, PasswordsConfig, field_validator, ValueError (+7 more)

### Community 105 - "test_passkey_invitation.py"
Cohesion: 0.18
Nodes (30): passkey_authenticator(), A user-verifying authenticator that makes discoverable credentials., _accept(), admin(), config(), http(), _invite(), _options() (+22 more)

### Community 106 - "test_sso_entra_email.py"
Cohesion: 0.16
Nodes (28): db(), Any, app(), config(), idp(), _pin(), Any, AsyncClient (+20 more)

### Community 107 - "test_audit_source_ip_tripwire.py"
Cohesion: 0.19
Nodes (16): collections, _constants(), _is_warden(), _missing(), _owner(), expr, Tripwire: every warden audit event carries the client address, unless it has no…, The class and method, or the function, a call sits in (nested routes keep their… (+8 more)

### Community 108 - "test_identity_lifecycle_routes.py"
Cohesion: 0.20
Nodes (18): app(), client(), AsyncClient, FastAPI, fixture, parametrize, UserFactory, Public lifecycle routes: accept an invitation, request and complete a password… (+10 more)

### Community 109 - "WatchLists"
Cohesion: 0.08
Nodes (40): HibpUnavailable, Exception, ValueError, Errors raised by password policies and watch lists. Messages carry field names,…, A watch list, or a change to one, was refused., No watch list has that id., The change clashes with the stored state: a list still attached to a policy., An import was refused or failed; the list is left as it was. ``line`` is the… (+32 more)

### Community 110 - "SecretBox"
Cohesion: 0.05
Nodes (53): _decode(), _key_id(), new_totp_key(), Exception, Protocol, ``(key_id, nonce || ciphertext || tag)`` for ``plaintext`` bound to ``context``., The plaintext, or None for an unknown key, wrong context or tampering., A TOTP key is missing or malformed. Names the secret, never its value. (+45 more)

### Community 111 - "test_audit_router.py"
Cohesion: 0.16
Nodes (21): client(), exporter(), NoKeys, Any, AsyncClient, fixture, parametrize, Audit routers: list, export and verify, behind the product's own authorisation. (+13 more)

### Community 112 - "test_cli.py"
Cohesion: 0.19
Nodes (14): FakeSecrets, FakeSettings, Any, CaptureFixture, Path, The warden CLI: migrate and keys rotate., _settings(), test_console_script_runs_migrate_from_a_config_file() (+6 more)

### Community 113 - "Cluster: Audit hash chain specification"
Cohesion: 0.15
Nodes (17): Signed chain-head anchor (warden.audit.anchor.v1), Append-only audit database roles (INSERT and SELECT only), Audit hash chain specification, AuditChainConflict, Canonical JSON row form (warden.audit.row.v1), Chain lock (transaction-scoped advisory lock), Details cap and warden.truncated marker, Signed retention checkpoint (warden.audit.checkpoint.v1) (+9 more)

### Community 114 - "test_unpinning_records_the_address"
Cohesion: 0.20
Nodes (11): Any, AsyncClient, parametrize, Response, UserFactory, The route passes ``actor`` and ``source_ip`` itself; a body cannot supply them., _recorded(), sso() (+3 more)

### Community 115 - "collector.py"
Cohesion: 0.08
Nodes (12): Framing, BlackholeCollector, Event, SSLContext, StreamReader, StreamWriter, In-process syslog collectors for tests: stream (TCP or TLS), UDP and a…, Accepts connections and never reads, so a sender's buffers fill and stall. (+4 more)

### Community 116 - "race"
Cohesion: 0.16
Nodes (18): race(), Run ``calls`` as concurrent tasks released together by a barrier. Every task…, app(), client(), headers(), _invite(), AsyncClient, FastAPI (+10 more)

### Community 117 - "test_audit_grants.py"
Cohesion: 0.12
Nodes (28): append_only_grants(), _application(), _forwarder(), grants_sql(), _ident(), _purger(), Composable, Composed (+20 more)

### Community 118 - "httpx"
Cohesion: 0.13
Nodes (40): httpx, assert_refused(), http_client(), passkey_app(), passkey_options(), AsyncClient, FastAPI, Response (+32 more)

### Community 119 - "Cluster: with"
Cohesion: 0.17
Nodes (16): steps, steps, steps, id, name, run, uses, with (+8 more)

### Community 120 - "HttpConfig"
Cohesion: 0.09
Nodes (21): _base_origin(), _check_origin(), DbConfig, HttpConfig, _is_domain(), BaseModel, Database settings. At runtime warden uses the product's pool, never this DSN., Where the product exposes warden (design D9). Mount prefixes are where the… (+13 more)

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

### Community 125 - "SyslogSettings"
Cohesion: 0.08
Nodes (34): Any, BaseModel, field_validator, model_validator, Self, Build settings from the shared ``SyslogConfig``. ``secrets`` looks up a konfig…, Everything the forwarder, formatter and transports need., SyslogSettings (+26 more)

### Community 126 - ".rotate"
Cohesion: 0.13
Nodes (15): Ed25519PrivateKey, _b64url(), _b64url_decode(), key_id_for(), PublicKey, Any, Generate a key and make it the signing key. Earlier keys keep verifying., Published keys, newest first. A revoked key is never included. (+7 more)

### Community 127 - "test_lifecycle_migration.py"
Cohesion: 0.21
Nodes (15): _lifecycle_revisions(), Conn, parametrize, UUID, Identity lifecycle's migration: its tables, their constraints, and a tested…, The lifecycle migration and the revision below it, however the chain was re-…, _tables(), test_a_single_use_token_cannot_expire_before_it_is_created() (+7 more)

### Community 128 - "test_identity_reset.py"
Cohesion: 0.18
Nodes (20): _force_method(), parametrize, UserFactory, UUID, Password reset by emailed link: refusal paths, single use (#127), sessions…, #127 for reset tokens., Put a method in force at once, behind the services' back: since 0.2.0 a move to…, _reasons() (+12 more)

### Community 129 - "LiveServer"
Cohesion: 0.12
Nodes (15): admin(), browser(), config(), fixture, The administrator's own client, signed in over the same live server., server(), live_app(), live_config() (+7 more)

### Community 130 - "test_password_policy_migration.py"
Cohesion: 0.12
Nodes (33): _columns(), _policy(), Any, Conn, parametrize, UUID, Password policies' migration: the whole feature's schema, with a tested…, _refused() (+25 more)

### Community 131 - "Purpose"
Cohesion: 0.16
Nodes (20): IssuedToken, _live_token(), LiveToken, Purpose, Any, AsyncConnection, datetime, StrEnum (+12 more)

### Community 132 - "checkpoint.py"
Cohesion: 0.20
Nodes (13): _b64url(), _b64url_decode(), Checkpoint, _int(), MalformedCheckpoint, Any, ValueError, Signed retention checkpoints. A retention purge deletes a prefix of the chain,… (+5 more)

### Community 133 - "test_sso_invitation_migration.py"
Cohesion: 0.29
Nodes (11): _columns(), _insert(), Connection, parametrize, SSO invitations' migration: the login transaction's invitation hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _tables() (+3 more)

### Community 134 - "Cluster: test_anchored_patterns.py"
Cohesion: 0.29
Nodes (11): Call, _compiled_names(), _findings(), _has_dollar_anchor(), _is_re_call(), AST, Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.…, The scan must actually find compiled patterns, or it guards nothing. (+3 more)

### Community 135 - "test_mfa_factors_webauthn.py"
Cohesion: 0.26
Nodes (23): _allow(), _challenge(), _keys(), _principal(), AsyncClient, UserFactory, UUID, Allowed second factors with security keys and passkeys (ruling CS14). The… (+15 more)

### Community 136 - "certs.py"
Cohesion: 0.13
Nodes (15): cryptography, cryptography_hazmat_primitives_asymmetric, cryptography_hazmat_primitives_serialization, cryptography_x509_oid, ssl, main(), Write a throwaway CA and a TLS keystore for the stub identity provider. python…, Issued (+7 more)

### Community 137 - "._accept"
Cohesion: 0.13
Nodes (17): Complete, Method, MethodCheck, check(), complete(), check(), PasskeyRegistration, NoReturn (+9 more)

### Community 138 - "password_support.py"
Cohesion: 0.19
Nodes (14): bearer(), codes(), lifecycle_app(), pin_policy(), Any, AsyncClient, FastAPI, Response (+6 more)

### Community 139 - "test_examples_public_surface.py"
Cohesion: 0.26
Nodes (12): ast, _private(), _private_path(), Path, Tripwire: the sample console uses only warden's public surface. The sample…, Every reach into a private warden module or name in ``source``., sample_sources(), test_nothing_under_examples_reaches_into_warden_internals() (+4 more)

### Community 140 - "console_router"
Cohesion: 0.17
Nodes (13): _anchor_report(), console_router(), anchor_head(), check_anchors(), import_sample(), move_clock(), recheck_passwords(), source() (+5 more)

### Community 141 - "test_no_private_imports.py"
Cohesion: 0.36
Nodes (8): ImportFrom, _from_warden(), _private(), Tripwire: no warden module reaches into another module's private names. A…, Local names bound by an import from warden (modules or anything else)., test_no_module_reaches_into_another_modules_private_names(), _violations(), _warden_bindings()

### Community 142 - "test_password_policy_store.py"
Cohesion: 0.16
Nodes (27): Any, fixture, parametrize, UUID, The password policy store (rulings PW1, PW2 and PW11): policies, priorities,…, _settings(), _store(), test_a_change_notifies_in_its_own_transaction() (+19 more)

### Community 143 - "SingleUseTokens"
Cohesion: 0.15
Nodes (25): Delete expired tokens, whatever their state; returns how many., Tokens in ``warden.single_use_tokens``. Every method works in the caller's…, SingleUseTokens, The token in a sent message's link (the test links end ``?t=<token>``)., _consume(), _issue(), fixture, parametrize (+17 more)

### Community 144 - "test_password_cli.py"
Cohesion: 0.24
Nodes (22): _banned(), _entries(), FakeSettings, _policy(), Any, CaptureFixture, Path, UUID (+14 more)

### Community 145 - "test_identity_prune.py"
Cohesion: 0.24
Nodes (14): _count(), _expire_all(), _fixtures(), Any, UserFactory, Pruning (#134): expired refresh and single-use tokens, MFA challenges, throttle…, Move every row of ``table`` into the past, keeping its own constraints., Reuse detection needs used tokens until they expire; pruning must not remove… (+6 more)

### Community 146 - "test_sso_break_glass_live.py"
Cohesion: 0.21
Nodes (13): app(), config(), Any, AsyncClient, FastAPI, fixture, parametrize, UserFactory (+5 more)

### Community 147 - "test_console_capabilities.py"
Cohesion: 0.29
Nodes (8): _admin(), _client(), Any, AsyncClient, The sample console asks warden what the deployment can do, and its screens…, test_with_a_sender_everything_that_mails_is_available(), test_without_a_sender_the_capabilities_say_so_and_the_503_stays(), test_without_the_link_setting_only_the_registration_link_is_unavailable()

### Community 148 - "test_no_direct_environment.py"
Cohesion: 0.31
Nodes (9): _enclosing_functions(), visit(), _findings(), AST, Tripwire: warden reads configuration only through konfig. No module under…, Each node's innermost enclosing function name, keyed by ``id(node)``., Every forbidden use, and whether it is the named exemption., test_each_exemption_covers_exactly_one_read() (+1 more)

### Community 149 - "Cluster: updates"
Cohesion: 0.22
Nodes (8): prefix, interval, updates, commit-message, directory, package-ecosystem, schedule, version

### Community 150 - "SsoError"
Cohesion: 0.09
Nodes (22): Exception, A single sign-on step was refused; ``reason`` says why, for the audit trail., SsoError, _basic(), _https(), JwksCache, _KeySet, parse_metadata() (+14 more)

### Community 151 - "_AfterFirstQuery"
Cohesion: 0.29
Nodes (5): _AfterFirstQuery, _HookedPool, Any, Delegates to a connection, running ``hook`` once after the checkpoint listing., traced_execute()

### Community 152 - "Database"
Cohesion: 0.11
Nodes (44): FixtureRequest, Database, warden's handle on the product's connection pool., work(), _count(), Any, The pool adapter and transaction helper over a product-supplied pool., test_database_uses_the_pool_it_was_given() (+36 more)

### Community 153 - "test_identity_capabilities.py"
Cohesion: 0.09
Nodes (53): IdentityCapabilities, What this deployment can do, so a client can disable and explain a feature up…, What this deployment can do, for a client to disable and explain features.…, app(), audit_registry(), client(), config(), identity() (+45 more)

### Community 154 - "test_sso_guard_routes.py"
Cohesion: 0.17
Nodes (19): app(), authorise(), config(), idp(), Any, AsyncClient, FastAPI, fixture (+11 more)

### Community 155 - "ceremony.js"
Cohesion: 0.27
Nodes (11): call(), create(), field(), flows, get(), keep(), outcome, register() (+3 more)

### Community 156 - "PasswordHistory"
Cohesion: 0.11
Nodes (25): PasswordHistory, Any, AsyncConnection, datetime, UUID, Previous Argon2id hashes per user., Keep ``password_hash`` (Argon2id only) as the user's newest previous password., Whether ``password`` matches any of the user's last ``count`` passwords. (+17 more)

### Community 157 - "Cluster: verify"
Cohesion: 0.29
Nodes (7): verify, python-version, fail-fast, matrix, needs, runs-on, strategy

### Community 158 - "test_sign_in_methods_migration.py"
Cohesion: 0.21
Nodes (19): _method(), _pending(), Any, Conn, parametrize, UUID, The sign-in methods migration (rulings CS13 and CS16), with a tested downgrade.…, _refused() (+11 more)

### Community 159 - "console/cli.py"
Cohesion: 0.08
Nodes (46): create_administrator(), Creating the first administrator. warden's own CLI cannot do this, because the…, Create an active user with ``password`` holding the administrator role. Running…, _create_admin(), work(), _dsn(), _init(), main() (+38 more)

### Community 160 - "Cluster: rsyslog"
Cohesion: 0.33
Nodes (5): build, ports, volumes, services, rsyslog

### Community 161 - "test_password_hibp.py"
Cohesion: 0.20
Nodes (18): _client(), LogCaptureFixture, parametrize, Request, Response, The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed…, Recorder, test_a_digest_must_be_twenty_bytes() (+10 more)

### Community 162 - "test_identity_users.py"
Cohesion: 0.11
Nodes (28): _paged(), Exception, parametrize, UserFactory, UUID, Users: creation, lookup, statuses, sign-in methods and passwords., _set_created(), test_a_limit_alone_returns_the_oldest() (+20 more)

### Community 163 - "test_licence_audit.py"
Cohesion: 0.07
Nodes (33): importlib_util, init_file(), _load(), fixture, ModuleType, parametrize, Path, The version script stamps only on a matching release branch. (+25 more)

### Community 164 - "test_console_gaps.py"
Cohesion: 0.15
Nodes (9): Every gap the console shows names the question that records it., Question 6 was ruled an administrator's reset in warden 0.1.0., Question 29 was answered with a field: the console labels keys from it., Question 39 was a defect in the admin route, fixed in warden 0.1.0., Question 7 was answered with warden's own routes in 0.2.0 (ruling CS22)., test_forbid_user_details_is_no_longer_a_gap(), test_the_passkey_flag_is_no_longer_a_gap(), test_the_session_policy_is_no_longer_a_gap() (+1 more)

### Community 165 - "test_identity_throttle.py"
Cohesion: 0.19
Nodes (18): _fail(), UserFactory, Sign-in throttling per (identifier, source address)., Otherwise a password holder gets unlimited challenges, and so unlimited code…, Barriered concurrent attempts: no more than the limit reach password…, An attacker elsewhere cannot lock the user out., Throttling must not reveal whether an account exists., test_a_password_alone_does_not_reset_the_count_when_mfa_follows() (+10 more)

### Community 166 - "test_syslog_routes.py"
Cohesion: 0.20
Nodes (22): Any, APIRouter, ``GET /syslog/status`` and ``POST /syslog/test``; mount under a prefix of your…, syslog_router(), _audit_rows(), authorise(), _client(), collector() (+14 more)

### Community 167 - "_FieldProblems"
Cohesion: 0.36
Nodes (4): _FieldProblems, model_validator, Self, Cross-field problems, each with a path relative to the failing model.

### Community 169 - "test_browser_rules_vectors.py"
Cohesion: 0.11
Nodes (16): CompletedProcess, names(), path(), Browser scripts warden publishes, for a product to serve from its own static…, The file names of the scripts warden ships., The location of a shipped script, by its exact file name. Anything else (a…, node(), Path (+8 more)

### Community 171 - "test_cli_passwords_errors.py"
Cohesion: 0.19
Nodes (15): FakeSecrets, FakeSettings, hibp_file(), Any, CaptureFixture, fixture, parametrize, Path (+7 more)

### Community 172 - "main"
Cohesion: 0.23
Nodes (16): main(), Run the CLI. ``settings`` and ``secrets`` replace konfig's, for tests.…, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI: audit verify and audit purge against a real database., _seed() (+8 more)

### Community 173 - "test_connection_failure_prints_a_fixed_message_and_exits_1"
Cohesion: 0.18
Nodes (13): _anchors_file(), FakeSecrets, FakeSettings, Any, CaptureFixture, parametrize, Path, One synthetic anchor row, as an NDJSON export holds it. (+5 more)

### Community 174 - "passwordrules.js"
Cohesion: 0.23
Nodes (15): classMatchers(), codePoints(), countClasses(), countWords(), detailTokens(), evaluate(), localPart(), longestRun() (+7 more)

### Community 175 - "BuiltinList"
Cohesion: 0.16
Nodes (13): console_settings(), functools, BuiltinList, _bundled(), bundled_list(), _check(), Path, The built-in common-password list (ruling PW12). A read-only list of common… (+5 more)

### Community 176 - "test_settings_routes.py"
Cohesion: 0.10
Nodes (53): admin(), app(), bearer(), client(), config(), _last_id(), owner(), pending_user() (+45 more)

### Community 177 - "tests/conftest.py"
Cohesion: 0.27
Nodes (9): dsn(), migrated_dsn(), pg_admin_url(), pool(), Any, fixture, Shared fixtures. Database tests use a real Postgres through testcontainers., A fresh, empty database for one test. (+1 more)

### Community 178 - "test_console_source_ip.py"
Cohesion: 0.33
Nodes (13): client(), headers(), Any, AsyncClient, fixture, Response, The sample console's own routes pass the client address, as a product should…, _recorded() (+5 more)

### Community 179 - "test_sso_setup_guides.py"
Cohesion: 0.11
Nodes (23): CopyBack, GuideStep, PresetGuide, Provider presets: setup guidance for an administrator, and nothing else.…, The steps for ``preset`` with the instance's values filled in. ``callback_uri``…, A value to copy from the provider's console into a warden setting., One step as written: ``text`` holds ``{placeholder}`` tokens., A step with its placeholders filled in. (+15 more)

### Community 180 - "TransportError"
Cohesion: 0.08
Nodes (15): DatagramTransport, classify_error(), BaseException, Exception, StreamReader, StreamWriter, TCP or TLS. After any failure the connection is spent and must be replaced., One message per datagram. UDP has no acknowledgement, so delivery is best… (+7 more)

### Community 181 - "test_identity_roles.py"
Cohesion: 0.25
Nodes (13): _admins(), UserFactory, Role assignments: audited, expiring, and never leaving no administrator., Two administrators demoting each other at once: exactly one demotion succeeds., test_an_administrator_role_cannot_expire(), test_an_expired_assignment_grants_nothing(), test_an_inactive_administrator_does_not_count(), test_assign_and_revoke_are_audited() (+5 more)

### Community 182 - "licence_audit.py"
Cohesion: 0.09
Nodes (21): importlib, packaging_requirements, packaging_utils, packaging_version, audit(), classify(), data_problems(), installed() (+13 more)

### Community 183 - "throttle.py"
Cohesion: 0.05
Nodes (38): PasswordPruning, Pruner, PruneReport, Identifier, Protocol, Delete every expired row once; each kind in its own short transaction., Run ``prune`` every ``every_seconds`` for the duration of a block., What the pruner needs from password policies. (+30 more)

### Community 184 - "test_identity_key_publication.py"
Cohesion: 0.29
Nodes (13): PyJWK, _access_token(), _b64(), _decode(), keys_client(), _published_key(), Any, AsyncClient (+5 more)

### Community 185 - "copy"
Cohesion: 0.22
Nodes (9): copy, FakeSecrets, FakeSettings, Any, CaptureFixture, The warden CLI fails cleanly when it cannot reach the database., _settings(), test_keys_rotate_connection_failure_prints_a_fixed_message_and_exits_1() (+1 more)

### Community 186 - "APIRouter"
Cohesion: 0.22
Nodes (5): APIRouter, Invitation acceptance and password reset; mount under…, Administration routes; mount under ``config.http.admin_prefix``. ``permission``…, The public sign-in routes; mount under ``config.http.auth_prefix``., The single sign-on routes; mount under ``config.http.auth_prefix`` too.

### Community 187 - ".connection"
Cohesion: 0.32
Nodes (5): AbstractAsyncContextManager, Any, AsyncConnection, Borrow a connection from the product's pool., Run a block in a transaction. With ``conn``, the block joins the caller's…

### Community 188 - "test_sso_invitation_sealing_migration.py"
Cohesion: 0.26
Nodes (12): _columns(), _insert(), Connection, parametrize, SSO invitation sealing's migration: the sealed token replaces its hash, and a…, This migration and the revision below it, however the chain was re-ordered., _revisions(), _states() (+4 more)

### Community 189 - "test_identity_totp_unit.py"
Cohesion: 0.18
Nodes (5): parametrize, TOTP primitives (RFC 6238) and recovery code formats. No database., test_malformed_codes_are_refused_cleanly(), test_malformed_recovery_codes_are_refused(), test_rfc6238_sha1_vectors()

### Community 190 - ".__call__"
Cohesion: 0.33
Nodes (4): Scope, with_headers(), Receive, Send

### Community 191 - "_LazySecrets"
Cohesion: 0.29
Nodes (4): _LazySecrets, Any, AsyncConnection, konfig ``Secrets``, constructed only if a command actually needs a secret.

### Community 192 - "complete_sign_in"
Cohesion: 0.25
Nodes (17): complete_sign_in(), A password sign-in carried through its second factor: the session or forced…, config(), has_password(), http(), live_sessions(), AsyncClient, fixture (+9 more)

### Community 193 - "resolve"
Cohesion: 0.22
Nodes (7): Collection, P, PolicySource, The policy ``roles`` would resolve to if granted, with no pin; else the default., PW1: the pin, else the highest-priority mapped and declared role, else the…, resolve(), test_resolution_order_is_pin_then_highest_priority_role_then_default()

### Community 194 - ".name"
Cohesion: 0.33
Nodes (3): run(), run(), Follow the link with this text, as a person clicks it (the page is not…

### Community 195 - "Transport"
Cohesion: 0.40
Nodes (3): Protocol, A connection to the collector. ``send`` raises ``TransportError`` on failure., Transport

### Community 196 - "run_vectors.mjs"
Cohesion: 0.22
Nodes (8): api, context, failures, fields, here, root, seen, vectors

### Community 197 - "build_console"
Cohesion: 0.04
Nodes (55): actor(), build_console(), Console, _mount_pages(), FastAPI, Request, The sample console's application: how a product wires warden into FastAPI. Read…, Build the console over the product's open pool and konfig's secrets store.… (+47 more)

### Community 200 - "warden sample console"
Cohesion: 0.29
Nodes (8): Product-declared permissions and roles (D5), Rotating refresh-token families with reuse detection, What the product builds itself in 0.1.0, Serialised refresh with reuse grace window, check_dist.py distribution checks, Console gaps (questions 7 to 11), warden sample console, Sample console HTML shell

### Community 201 - "pathlib"
Cohesion: 0.09
Nodes (26): pathlib, identity_support(), Helpers shared by the sample console's tests (imported as ``console_support``)., The identity tests' helpers (``tests/identity/identity_support.py``)., AsyncClient, The sample console's sign-in settings screens, over warden's own routes (ruling…, script(), test_a_session_without_a_recent_second_factor_is_told_to_sign_in_again() (+18 more)

### Community 202 - "Single sign-on setup guides"
Cohesion: 0.25
Nodes (7): Getting the steps, Google, Microsoft Entra ID, Okta, Other OpenID Connect provider, Single sign-on setup guides, What every guide shares

### Community 204 - "keys_router"
Cohesion: 0.25
Nodes (9): _jwk_set(), keys_router(), historical_keys(), live_keys(), _published(), Any, APIRouter, Response (+1 more)

### Community 205 - "verify_chain"
Cohesion: 0.19
Nodes (23): Verify the chain, from its first surviving row to ``through_id`` (or the head)., verify_chain(), ids(), NoKeys, Any, fixture, parametrize, Chain verification: any altered, deleted or reordered row is found, by id. (+15 more)

### Community 207 - "test_password_builtin.py"
Cohesion: 0.32
Nodes (10): _digests(), parametrize, Path, The built-in common-password list (ruling PW12): sorted SHA-1 digests, loaded…, test_a_listed_digest_is_found_and_others_are_not(), test_a_malformed_file_is_refused(), test_an_empty_list_matches_nothing(), test_the_bundled_list_ships() (+2 more)

### Community 209 - "subprocess"
Cohesion: 0.12
Nodes (19): _current_branch(), main(), Exception, Path, Stamp warden's version. Used only by the integration session, on a release…, The requested stamp is not allowed., Write ``version`` into ``init_path``, or raise ``StampRefused``., stamp() (+11 more)

### Community 210 - "The built-in common-password list"
Cohesion: 0.40
Nodes (4): Licence, Source and provenance, The built-in common-password list, What the file holds

### Community 213 - "._handle"
Cohesion: 0.31
Nodes (3): Any, Request, Response

### Community 214 - "SecretReader"
Cohesion: 0.33
Nodes (3): Protocol, SecretReader, SecretWriter

### Community 216 - "test_readme.py"
Cohesion: 0.43
Nodes (5): README.md is the PyPI project description, so it must render there without…, _targets(), test_every_link_is_absolute(), test_link_check_refuses_relative_link_and_image(), test_readme_has_links()

### Community 217 - "sso_config"
Cohesion: 0.10
Nodes (27): ValueError, A settings change was refused. The message names fields, never values., SsoSettingsError, sso_config(), app(), config(), idp(), Any (+19 more)

### Community 226 - "_Invalid"
Cohesion: 0.67
Nodes (3): _Invalid, Exception, A policy body refused, with each field at fault and a fixed message.

### Community 242 - "_Abort"
Cohesion: 0.67
Nodes (3): _Abort, Exception, Ends a transaction without committing it.

## Knowledge Gaps
- **125 isolated node(s):** `STATUSES`, `METHODS`, `FACTORS`, `POLICY_FIELDS`, `session` (+120 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2150 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **23 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Identity` connect `Identity` to `test_passkey_sign_in.py`, `test_password_feedback.py`, `KeyStore`, `RecordingSender`, `test_webauthn_mfa.py`, `contract.py`, `http_sign_in`, `test_webauthn_reset.py`, `SoftwareAuthenticator`, `test_sso_invitations.py`, `SingleSignOn`, `password_enforcement.py`, `test_identity_totp_reset.py`, `json_response`, `http.py`, `rules.py`, `current_code`, `test_password_sign_in.py`, `admin.py`, `settings_admin.py`, `WebAuthn`, `Mfa`, `identity_support.py`, `FakeIdp`, `WardenConfig`, `MailKind`, `export_openapi.py`, `typing`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `audit_rows`, `pytest`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_enforcement_keys.py`, `test_password_admin_routes.py`, `PolicySettings`, `identity/__init__.py`, `test_identity_admin_routes.py`, `test_webauthn_live.py`, `test_sso_capabilities.py`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `webauthn/service.py`, `test_passkey_sign_in_rules.py`, `test_identity_tokens.py`, `test_sign_in_methods_sso.py`, `Users`, `test_passkey_invitation.py`, `test_sso_entra_email.py`, `test_identity_lifecycle_routes.py`, `SecretBox`, `test_unpinning_records_the_address`, `race`, `httpx`, `test_sso_issuer.py`, `Cluster: test_identity_client_address.py`, `test_identity_reset.py`, `LiveServer`, `Purpose`, `test_mfa_factors_webauthn.py`, `password_support.py`, `console_router`, `SingleUseTokens`, `test_password_cli.py`, `test_identity_prune.py`, `test_sso_break_glass_live.py`, `Database`, `test_identity_capabilities.py`, `test_sso_guard_routes.py`, `PasswordHistory`, `console/cli.py`, `test_identity_users.py`, `test_identity_throttle.py`, `test_settings_routes.py`, `test_identity_roles.py`, `throttle.py`, `test_identity_key_publication.py`, `APIRouter`, `complete_sign_in`, `build_console`, `.install`, `test_failed_sign_in_timing_is_unchanged_by_the_passwords_state`, `sso_config`?**
  _High betweenness centrality (0.139) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `test_passkey_sign_in.py`, `test_password_feedback.py`, `AuditEvent`, `KeyStore`, `RecordingSender`, `PasswordResets`, `AuditRecorder`, `test_webauthn_mfa.py`, `http_sign_in`, `test_audit_recorder.py`, `test_webauthn_reset.py`, `SoftwareAuthenticator`, `test_sso_invitations.py`, `password_enforcement.py`, `test_identity_totp_reset.py`, `SsoSettingsStore`, `test_syslog_forwarder.py`, `current_code`, `test_password_sign_in.py`, `SyslogForwarder`, `ApiKeys`, `WebAuthn`, `test_audit_retention.py`, `Mfa`, `identity_support.py`, `FakeIdp`, `WardenConfig`, `soft_authenticator.py`, `export_openapi.py`, `typing`, `password_policy/__init__.py`, `test_identity_apikeys.py`, `PermissionRegistry`, `audit_rows`, `pytest`, `Sessions`, `test_identity_dependencies.py`, `test_passkey_registration_link.py`, `test_password_watch_lists.py`, `test_password_admin_routes.py`, `PolicySettings`, `identity/__init__.py`, `test_identity_admin_routes.py`, `test_webauthn_live.py`, `test_key_publication.py`, `verify.py`, `test_identity_sign_in.py`, `test_sso_admin_routes.py`, `webauthn/service.py`, `webauthn/challenges.py`, `test_passkey_sign_in_rules.py`, `attestation.py`, `test_identity_tokens.py`, `test_sign_in_methods_sso.py`, `Users`, `test_passkey_invitation.py`, `test_sso_entra_email.py`, `test_identity_lifecycle_routes.py`, `WatchLists`, `SecretBox`, `test_audit_router.py`, `test_unpinning_records_the_address`, `race`, `test_audit_grants.py`, `httpx`, `test_sso_issuer.py`, `test_audit_chain_recorder.py`, `Cluster: test_identity_client_address.py`, `test_identity_reset.py`, `test_mfa_factors_webauthn.py`, `test_password_policy_store.py`, `SingleUseTokens`, `test_password_cli.py`, `test_identity_prune.py`, `test_sso_break_glass_live.py`, `test_identity_capabilities.py`, `PasswordHistory`, `test_identity_users.py`, `test_identity_throttle.py`, `test_syslog_routes.py`, `test_settings_routes.py`, `test_identity_roles.py`, `throttle.py`, `.connection`, `complete_sign_in`, `build_console`, `verify_chain`, `.__init__`, `test_failed_sign_in_timing_is_unchanged_by_the_passwords_state`, `sso_config`?**
  _High betweenness centrality (0.120) - this node is a cross-community bridge._
- **Why does `build_sso_router()` connect `http.py` to `Identity`, `contract.py`, `identity/__init__.py`, `SsoError`, `APIRouter`, `json_response`?**
  _High betweenness centrality (0.030) - this node is a cross-community bridge._
- **Are the 62 inferred relationships involving `Identity` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Identity` has 62 INFERRED edges - model-reasoned connections that need verification._
- **Are the 94 inferred relationships involving `Database` (e.g. with `build_console()` and `build_reference_app()`) actually correct?**
  _`Database` has 94 INFERRED edges - model-reasoned connections that need verification._
- **Are the 174 inferred relationships involving `RecordingSender` (e.g. with `identity()` and `mail()`) actually correct?**
  _`RecordingSender` has 174 INFERRED edges - model-reasoned connections that need verification._
- **What connects `STATUSES`, `METHODS`, `FACTORS` to the rest of the system?**
  _125 weakly-connected nodes found - possible documentation gaps or missing edges._