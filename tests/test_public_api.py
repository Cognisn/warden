"""The public import surface, fixed as a snapshot.

warden's public API is whatever its packages export without a leading
underscore. Each package's ``__all__`` is pinned here, so adding, removing or
renaming a public name fails this test until the snapshot is changed in the
same commit, where review sees it. Update the snapshot only for a deliberate
change, and name it in CHANGELOG.md.
"""

from __future__ import annotations

import importlib
import subprocess
import sys

import pytest

SNAPSHOT: dict[str, list[str]] = {
    "warden": ["__version__"],
    "warden.audit": [
        "ActionRegistry",
        "ActionSpec",
        "Anchor",
        "AnchorCheck",
        "AnchorError",
        "AnchorRecord",
        "AnchorReport",
        "AnchorStatus",
        "AuditChainConflict",
        "AuditEvent",
        "AuditPage",
        "AuditQuery",
        "AuditRecorder",
        "AuditSink",
        "BreakReason",
        "BrokenLink",
        "ExternalAnchor",
        "MIN_RETENTION_DAYS",
        "MalformedAnchor",
        "Outcome",
        "PurgeResult",
        "RetentionError",
        "SUMMARY_FIELDS",
        "Severity",
        "VerificationReport",
        "anchor",
        "append_only_grants",
        "get_recorder",
        "grants_sql",
        "iter_events",
        "list_events",
        "purge",
        "read_anchors",
        "record_audit",
        "set_recorder",
        "verify_anchors",
        "verify_chain",
    ],
    "warden.audit.syslog": [
        "AuditRecord",
        "ForwarderSnapshot",
        "ForwarderStatus",
        "SYSLOG_TEST_ACTION",
        "SyslogForwarder",
        "SyslogSettings",
        "TestSendResult",
        "Transport",
        "TransportError",
        "TransportFactory",
        "classify_error",
        "format_message",
        "format_test_message",
        "frame",
        "neutralise",
        "open_transport",
        "register_syslog_actions",
        "send_test_message",
        "syslog_router",
        "tls_context",
    ],
    "warden.config": [
        "AuditConfig",
        "COGNISN_PEN",
        "ConfigError",
        "DEFAULT_SD_ID",
        "DbConfig",
        "HttpConfig",
        "IdentityConfig",
        "KeysConfig",
        "MIN_RETENTION_DAYS",
        "MailConfig",
        "PasswordsConfig",
        "SecretSource",
        "SettingsSource",
        "SsoConfig",
        "SyslogConfig",
        "WardenConfig",
        "WebAuthnConfig",
        "load_config",
        "parse_config",
    ],
    "warden.db": [
        "ADMINISTRATOR_LOCK_KEY",
        "API_KEYS",
        "AUDIT_CHANNEL",
        "AUDIT_EVENTS",
        "CHAIN_LOCK_KEY",
        "ConnectionSource",
        "Database",
        "IDENTITY_TABLES",
        "INVITATION_GRANTS",
        "LIFECYCLE_TABLES",
        "MIGRATION_LOCK_KEY",
        "PASSWORD_CHANGE_CHALLENGES",
        "PASSWORD_HISTORY",
        "PASSWORD_POLICIES",
        "PASSWORD_POLICY_LOCK_KEY",
        "PASSWORD_POLICY_NOTIFY",
        "PASSWORD_POLICY_PINS",
        "PASSWORD_POLICY_ROLES",
        "PASSWORD_POLICY_TABLES",
        "PASSWORD_POLICY_WATCH_LISTS",
        "PASSWORD_STATES",
        "POLICY_CHANNEL",
        "POLICY_SETTING",
        "SCHEMA",
        "SETTINGS",
        "SIGNING_KEYS",
        "SINGLE_USE_TOKENS",
        "SSO_HANDOFF_CODES",
        "SSO_IDENTITIES",
        "SSO_LOGIN_TRANSACTIONS",
        "SSO_SETTING",
        "SSO_SETTINGS_LOCK_KEY",
        "SSO_TABLES",
        "SYSLOG_CURSOR_SETTING",
        "SYSLOG_FORWARDER_LOCK_KEY",
        "VERSION_TABLE",
        "WATCH_LISTS",
        "WATCH_LIST_ENTRIES",
        "WATCH_LIST_LOCK_KEY",
        "WATCH_LIST_STAGING",
        "WATCH_LIST_TERMS",
        "WEBAUTHN_CHALLENGES",
        "WEBAUTHN_CREDENTIALS",
        "WEBAUTHN_TABLES",
        "WEBAUTHN_USER_HANDLES",
        "current_revision",
        "downgrade",
        "heads",
        "migrate",
        "migrate_connection",
        "table",
    ],
    "warden.identity": [
        "AcceptedInvitation",
        "ApiKey",
        "ApiKeyError",
        "ApiKeys",
        "AuthenticationRefused",
        "ChallengeIssued",
        "ChangeReason",
        "ConfigurationCheck",
        "ConfigurationReport",
        "DEFAULT_TEMPLATES",
        "EffectivePolicy",
        "Enrolment",
        "Fingerprints",
        "HibpRangeClient",
        "HibpUnavailable",
        "Identity",
        "IdentityCapabilities",
        "Invitation",
        "InvitationAcceptance",
        "InvitationError",
        "InvitationMismatch",
        "Invitations",
        "LastAdministratorError",
        "LastSecondFactorError",
        "LoginStart",
        "MailDeliveryError",
        "MailError",
        "MailKind",
        "MailMessage",
        "MailSender",
        "MailTemplate",
        "MfaError",
        "NewApiKey",
        "PasskeyInvitationAccepted",
        "PasskeyLinkNotConfigured",
        "PasskeyLinkRefused",
        "PasskeyRegistration",
        "PasswordAdvice",
        "PasswordChangeChallenges",
        "PasswordChangeIssued",
        "PasswordEnforcement",
        "PasswordFailure",
        "PasswordFeedback",
        "PasswordHasher",
        "PasswordHistory",
        "PasswordPolicies",
        "PasswordPolicy",
        "PasswordPolicyConflict",
        "PasswordPolicyError",
        "PasswordPolicyNotFound",
        "PasswordRecheck",
        "PasswordRejected",
        "PasswordResets",
        "PasswordRules",
        "PasswordState",
        "PasswordStates",
        "PasswordTokenPair",
        "PendingInvitation",
        "PermissionRegistry",
        "PolicyError",
        "PolicySettings",
        "PolicyStore",
        "Principal",
        "PruneReport",
        "Pruner",
        "RecheckReport",
        "ResourceScopeHook",
        "Role",
        "RoleAssignment",
        "RoleError",
        "Roles",
        "SSO_FAILURE_MESSAGE",
        "SecretKeyError",
        "SessionPolicy",
        "SignInMethod",
        "SignInMethodConflict",
        "SignInResult",
        "SingleSignOn",
        "SsoError",
        "SsoSettings",
        "SsoSettingsError",
        "SsoSettingsStore",
        "StagedGrant",
        "SubjectPin",
        "TOTP_KEY_SECRET",
        "TokenPair",
        "User",
        "UserError",
        "UserStatus",
        "Users",
        "Verification",
        "VerifiedIdentity",
        "WatchList",
        "WatchListCheck",
        "WatchListConflict",
        "WatchListError",
        "WatchListImportError",
        "WatchListKind",
        "WatchListMatch",
        "WatchListNotFound",
        "WatchListSource",
        "WatchLists",
        "WebAuthn",
        "WebAuthnAssertion",
        "WebAuthnCredential",
        "WebAuthnCredentials",
        "WebAuthnEnrolled",
        "WebAuthnError",
        "WebAuthnOptions",
        "WebAuthnPurpose",
        "WebAuthnRefusal",
        "WebAuthnRegistration",
        "WebAuthnUnavailable",
        "new_totp_key",
        "require_permission",
        "require_user",
    ],
    "warden.jwks": ["keys_router"],
    "warden.keys": [
        "KeyStore",
        "KeyStoreError",
        "PublicKey",
        "SecretStore",
        "Signature",
        "key_id_for",
    ],
    "warden.proxy": ["TrustedProxyMiddleware", "resolve_client_ip"],
}


@pytest.mark.parametrize("name", sorted(SNAPSHOT))
def test_the_public_names_match_the_snapshot(name: str) -> None:
    exported = importlib.import_module(name).__all__
    assert sorted(exported) == sorted(SNAPSHOT[name]), (
        "the public surface changed; update the snapshot and CHANGELOG.md together"
    )


@pytest.mark.parametrize("name", sorted(SNAPSHOT))
def test_every_exported_name_resolves_once(name: str) -> None:
    module = importlib.import_module(name)
    assert len(module.__all__) == len(set(module.__all__))
    for exported in module.__all__:
        assert hasattr(module, exported), f"{name}.{exported}"
        assert exported == "__version__" or not exported.startswith("_"), f"{name}.{exported}"


def test_the_root_package_names_the_subpackages_and_imports_none() -> None:
    import warden

    doc = warden.__doc__ or ""
    for name in SNAPSHOT:
        if name != "warden":
            assert f"``{name}``" in doc, name
    # D11: importing the root loads no subpackage, so ``import warden.audit``
    # cannot pull identity in through it.
    code = "import sys, warden; print(sorted(m for m in sys.modules if m.startswith('warden.')))"
    loaded = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout
    assert loaded.strip() == "[]"


def test_identity_does_not_re_export_the_sso_presets() -> None:
    # Presets are setup labels; the label-only tripwire keeps them out of
    # every identity module but the three that store and present them.
    from warden import identity

    assert not {"PRESETS", "PresetGuide"} & set(identity.__all__)
    assert not hasattr(identity, "PRESETS")


def test_identity_exports_the_objects_its_modules_define() -> None:
    from warden import identity
    from warden.identity import (
        apikeys,
        invitations,
        mail,
        password_enforcement,
        password_policy,
        prune,
        reset,
        webauthn,
    )
    from warden.identity import service as identity_service
    from warden.identity.sso import errors, service, settings

    for module in (
        apikeys,
        identity_service,
        invitations,
        mail,
        password_enforcement,
        password_policy,
        prune,
        reset,
        errors,
        service,
        settings,
        webauthn,
    ):
        for exported in getattr(module, "__all__", []):
            if exported in identity.__all__:
                assert getattr(identity, exported) is getattr(module, exported), exported
