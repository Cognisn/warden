"""The audit actions single sign-on records, all under ``warden.identity.sso.``.

A successful sign-in is recorded as identity's ``warden.identity.sign_in``
with ``amr`` ``["sso"]``, so every sign-in is one action; a refused one is
``warden.identity.sso.sign_in`` with the reason, which the browser never sees.
"""

from __future__ import annotations

from warden.audit import ActionRegistry, Severity
from warden.audit.registry import register_warden_action

__all__ = ["SSO_ACTIONS", "register_sso_actions"]

SSO_ACTIONS: tuple[tuple[str, Severity, str], ...] = (
    ("warden.identity.sso.sign_in", Severity.WARNING, "single sign-on refused: {outcome}"),
    (
        "warden.identity.sso.subject_pinned",
        Severity.NOTICE,
        "user {resource_id} pinned to a single sign-on subject",
    ),
    (
        "warden.identity.sso.subject_unpinned",
        Severity.NOTICE,
        "{actor} removed the single sign-on pin of user {resource_id}",
    ),
    (
        "warden.identity.sso.settings_changed",
        Severity.NOTICE,
        "{actor} changed the single sign-on settings",
    ),
    (
        "warden.identity.sso.disabled",
        Severity.NOTICE,
        "{actor} disabled single sign-on; its sessions were ended",
    ),
    (
        "warden.identity.sso.client_secret_set",
        Severity.NOTICE,
        "{actor} set the single sign-on client secret",
    ),
    (
        "warden.identity.sso.configuration_tested",
        Severity.INFO,
        "{actor} tested the single sign-on configuration: {outcome}",
    ),
)


def register_sso_actions(registry: ActionRegistry) -> None:
    for action, severity, summary in SSO_ACTIONS:
        register_warden_action(registry, action, severity=severity, summary=summary)
