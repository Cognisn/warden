"""Every audit action password policies and watch lists need is registered now
(kick-off item 5), so wave 17 never edits ``actions.py``."""

from __future__ import annotations

from warden.audit import ActionRegistry, Severity
from warden.identity.actions import IDENTITY_ACTIONS, PASSWORD_ACTIONS, register_actions

EXPECTED = {
    "warden.identity.password_policy.created",
    "warden.identity.password_policy.updated",
    "warden.identity.password_policy.deleted",
    "warden.identity.password_policy.assigned",
    "warden.identity.password_policy.pinned",
    "warden.identity.password_policy.unpinned",
    "warden.identity.watch_list.created",
    "warden.identity.watch_list.updated",
    "warden.identity.watch_list.deleted",
    "warden.identity.watch_list.imported",
    "warden.identity.watch_list.entries_changed",
    "warden.identity.password.changed",
    "warden.identity.password.change_required",
    "warden.identity.password.change_completed",
    "warden.identity.password.rejected",
    "warden.identity.password.expired",
    "warden.identity.password.recheck_completed",
    "warden.identity.password.watch_list_unavailable",
}


def test_every_password_action_is_registered() -> None:
    registry = ActionRegistry()
    register_actions(registry)
    names = {spec.action for spec in registry.actions()}
    assert names >= EXPECTED
    assert {action for action, _, _ in PASSWORD_ACTIONS} | {
        "warden.identity.password.changed"
    } == EXPECTED


def test_password_actions_are_part_of_identitys_actions() -> None:
    names = [action for action, _, _ in IDENTITY_ACTIONS]
    assert len(names) == len(set(names))
    assert {action for action, _, _ in PASSWORD_ACTIONS} <= set(names)


def test_a_forced_change_and_an_unavailable_range_service_are_warnings() -> None:
    severities = {action: severity for action, severity, _ in PASSWORD_ACTIONS}
    assert severities["warden.identity.password.change_required"] == Severity.WARNING
    assert severities["warden.identity.password.watch_list_unavailable"] == Severity.WARNING
