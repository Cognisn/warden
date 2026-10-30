"""The sample product's own permissions, roles and audit actions.

warden hardcodes none of these (design D5): a product declares its
permissions, defines roles as named sets of them, and registers the audit
actions it records. Product actions may not use the ``warden.`` namespace.
"""

from __future__ import annotations

from warden.audit import ActionRegistry, Severity
from warden.identity import PermissionRegistry

# The product's resource.
NOTES_READ = "notes.read"
NOTES_WRITE = "notes.write"
NOTES_ADMIN = "notes.admin"

# What the sample guards warden's administration and audit routes with.
USERS_MANAGE = "users.manage"
KEYS_MANAGE = "keys.manage"
SSO_MANAGE = "sso.manage"
POLICY_MANAGE = "policy.manage"
AUDIT_READ = "audit.read"
AUDIT_EXPORT = "audit.export"
SYSLOG_MANAGE = "syslog.manage"

PERMISSIONS = {
    NOTES_READ: "Read notes",
    NOTES_WRITE: "Write notes (your own, unless you also administer notes)",
    NOTES_ADMIN: "Edit and delete anyone's notes",
    USERS_MANAGE: "Manage users, roles and invitations",
    KEYS_MANAGE: "Manage API keys",
    SSO_MANAGE: "Manage single sign-on",
    POLICY_MANAGE: "Manage the session policy",
    AUDIT_READ: "Read and verify the audit trail",
    AUDIT_EXPORT: "Export the audit trail",
    SYSLOG_MANAGE: "See syslog forwarding and send a test message",
}

ROLES: dict[str, frozenset[str]] = {
    "viewer": frozenset({NOTES_READ}),
    "editor": frozenset({NOTES_READ, NOTES_WRITE}),
    "notes-admin": frozenset({NOTES_READ, NOTES_WRITE, NOTES_ADMIN}),
    "auditor": frozenset({AUDIT_READ, AUDIT_EXPORT}),
}
ADMINISTRATOR = "administrator"

NOTE_CREATED = "console.note.created"
NOTE_UPDATED = "console.note.updated"
NOTE_DELETED = "console.note.deleted"


def permissions() -> PermissionRegistry:
    """The product's permission registry and role sets."""
    registry = PermissionRegistry()
    for name, description in PERMISSIONS.items():
        registry.register_permission(name, description)
    for role, granted in ROLES.items():
        registry.define_role(role, granted)
    # An administrator role counts towards last-administrator protection.
    registry.define_role(ADMINISTRATOR, set(PERMISSIONS), administrator=True)
    return registry


def register_actions(registry: ActionRegistry) -> None:
    """The product's audit actions, with severity and summary templates."""
    registry.register(NOTE_CREATED, severity=Severity.INFO, summary="{actor} created a note")
    registry.register(NOTE_UPDATED, severity=Severity.INFO, summary="{actor} changed a note")
    registry.register(NOTE_DELETED, severity=Severity.NOTICE, summary="{actor} deleted a note")
