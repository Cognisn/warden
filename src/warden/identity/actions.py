"""The audit actions identity records, registered when ``Identity`` is constructed."""

from __future__ import annotations

from warden.audit import ActionRegistry, Severity
from warden.audit.registry import register_warden_action

__all__ = ["IDENTITY_ACTIONS", "PASSWORD_ACTIONS", "register_actions"]

# Password policies and watch lists (rulings PW0 to PW14 of 10 November 2026),
# registered in full by wave 16 so later workstreams never edit this module.
# Details carry identifiers, rule codes and counts only: never a password, a
# hash, a hash prefix or a fingerprint.
PASSWORD_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    (
        "warden.identity.password_policy.created",
        Severity.NOTICE,
        "{actor} created password policy {resource_id}",
    ),
    (
        "warden.identity.password_policy.updated",
        Severity.NOTICE,
        "{actor} changed password policy {resource_id}",
    ),
    (
        "warden.identity.password_policy.deleted",
        Severity.NOTICE,
        "{actor} deleted password policy {resource_id}",
    ),
    (
        "warden.identity.password_policy.assigned",
        Severity.NOTICE,
        "{actor} changed the password policy of role {resource_id}",
    ),
    (
        "warden.identity.password_policy.pinned",
        Severity.NOTICE,
        "{actor} pinned a password policy on user {resource_id}",
    ),
    (
        "warden.identity.password_policy.unpinned",
        Severity.NOTICE,
        "{actor} removed the pinned password policy of user {resource_id}",
    ),
    (
        "warden.identity.watch_list.created",
        Severity.NOTICE,
        "{actor} created watch list {resource_id}",
    ),
    (
        "warden.identity.watch_list.updated",
        Severity.NOTICE,
        "{actor} changed watch list {resource_id}",
    ),
    (
        "warden.identity.watch_list.deleted",
        Severity.NOTICE,
        "{actor} deleted watch list {resource_id}",
    ),
    (
        "warden.identity.watch_list.imported",
        Severity.NOTICE,
        "{actor} imported watch list {resource_id}: {outcome}",
    ),
    (
        "warden.identity.watch_list.entries_changed",
        Severity.NOTICE,
        "{actor} changed the entries of watch list {resource_id}",
    ),
    (
        "warden.identity.password.change_required",
        Severity.WARNING,
        "user {resource_id} must change their password",
    ),
    (
        "warden.identity.password.change_completed",
        Severity.NOTICE,
        "user {resource_id} completed a required password change: {outcome}",
    ),
    (
        "warden.identity.password.change_cleared",
        Severity.NOTICE,
        "{actor} cleared the required password change of user {resource_id}",
    ),
    (
        "warden.identity.password.rejected",
        Severity.INFO,
        "a new password for user {resource_id} was refused",
    ),
    (
        "warden.identity.password.expired",
        Severity.NOTICE,
        "the password of user {resource_id} expired",
    ),
    (
        "warden.identity.password.recheck_completed",
        Severity.NOTICE,
        "{actor} rechecked passwords in use: {outcome}",
    ),
    (
        "warden.identity.password.watch_list_unavailable",
        Severity.WARNING,
        "the breached-password range service was unavailable: {outcome}",
    ),
)

IDENTITY_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    ("warden.identity.sign_in", Severity.NOTICE, "sign-in by {actor}: {outcome}"),
    ("warden.identity.sign_out", Severity.INFO, "{actor} signed out"),
    ("warden.identity.mfa.challenge", Severity.INFO, "second factor requested from {actor}"),
    ("warden.identity.mfa.verify", Severity.WARNING, "second factor from {actor}: {outcome}"),
    ("warden.identity.mfa.enrolment_started", Severity.INFO, "{actor} started TOTP enrolment"),
    ("warden.identity.mfa.enrolled", Severity.NOTICE, "{resource_id} enrolled TOTP"),
    ("warden.identity.mfa.reset", Severity.NOTICE, "{actor} reset TOTP of user {resource_id}"),
    (
        "warden.identity.mfa.webauthn.registered",
        Severity.NOTICE,
        "{actor} registered a security key: {outcome}",
    ),
    ("warden.identity.mfa.webauthn.renamed", Severity.INFO, "{actor} renamed a security key"),
    (
        "warden.identity.mfa.webauthn.removed",
        Severity.NOTICE,
        "{actor} removed a security key: {outcome}",
    ),
    (
        "warden.identity.mfa.webauthn.clone_suspected",
        Severity.WARNING,
        "a security key of user {resource_id} may have been copied",
    ),
    (
        "warden.identity.passkey.link_sent",
        Severity.NOTICE,
        "{actor} sent user {resource_id} a passkey registration link: {outcome}",
    ),
    (
        "warden.identity.passkey.registered",
        Severity.NOTICE,
        "passkey registered from a link for user {resource_id}: {outcome}",
    ),
    ("warden.identity.session.refresh", Severity.INFO, "session refresh: {outcome}"),
    (
        "warden.identity.session.reuse_detected",
        Severity.WARNING,
        "refresh token reuse: session {resource_id} revoked",
    ),
    ("warden.identity.password.changed", Severity.NOTICE, "{actor} changed password: {outcome}"),
    ("warden.identity.user.created", Severity.NOTICE, "{actor} created user {resource_id}"),
    (
        "warden.identity.user.status_changed",
        Severity.NOTICE,
        "{actor} changed status of user {resource_id}: {outcome}",
    ),
    (
        "warden.identity.user.sign_in_method_changed",
        Severity.NOTICE,
        "{actor} changed sign-in method of user {resource_id}",
    ),
    (
        "warden.identity.user.password_set",
        Severity.NOTICE,
        "{actor} set password of user {resource_id}",
    ),
    (
        "warden.identity.role.assigned",
        Severity.NOTICE,
        "{actor} assigned a role to user {resource_id}",
    ),
    (
        "warden.identity.role.revoked",
        Severity.NOTICE,
        "{actor} revoked a role from user {resource_id}: {outcome}",
    ),
    ("warden.identity.policy.changed", Severity.NOTICE, "{actor} changed the session policy"),
    *PASSWORD_ACTIONS,
)


def register_actions(registry: ActionRegistry) -> None:
    for action, severity, summary in IDENTITY_ACTIONS:
        register_warden_action(registry, action, severity=severity, summary=summary)
