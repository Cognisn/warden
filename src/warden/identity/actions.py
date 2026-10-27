"""The audit actions identity records, registered when ``Identity`` is constructed."""

from __future__ import annotations

from warden.audit import ActionRegistry, Severity
from warden.audit.registry import register_warden_action

__all__ = ["IDENTITY_ACTIONS", "register_actions"]

IDENTITY_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    ("warden.identity.sign_in", Severity.NOTICE, "sign-in by {actor}: {outcome}"),
    ("warden.identity.sign_out", Severity.INFO, "{actor} signed out"),
    ("warden.identity.mfa.challenge", Severity.INFO, "second factor requested from {actor}"),
    ("warden.identity.mfa.verify", Severity.WARNING, "second factor from {actor}: {outcome}"),
    ("warden.identity.mfa.enrolment_started", Severity.INFO, "{actor} started TOTP enrolment"),
    ("warden.identity.mfa.enrolled", Severity.NOTICE, "{resource_id} enrolled TOTP"),
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
)


def register_actions(registry: ActionRegistry) -> None:
    for action, severity, summary in IDENTITY_ACTIONS:
        register_warden_action(registry, action, severity=severity, summary=summary)
