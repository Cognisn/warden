"""warden's identity subsystem: users, sign-in, sessions, roles and permissions.

A product constructs one ``Identity``, installs it on its FastAPI app, and
mounts ``identity.auth_router()``; routes then depend on ``require_user`` or
``require_permission``. Identity records every event through
``warden.audit.record_audit``; it never writes the audit table itself.
"""

from warden.identity.crypto import TOTP_KEY_SECRET, SecretKeyError, new_totp_key
from warden.identity.dependencies import (
    Principal,
    ResourceScopeHook,
    require_permission,
    require_user,
)
from warden.identity.errors import AuthenticationRefused, MfaError
from warden.identity.mfa import Enrolment
from warden.identity.passwords import PasswordHasher
from warden.identity.policy import PolicyError, PolicyStore, SessionPolicy
from warden.identity.roles import (
    LastAdministratorError,
    PermissionRegistry,
    Role,
    RoleAssignment,
    RoleError,
    Roles,
)
from warden.identity.service import ChallengeIssued, Identity, SignInResult
from warden.identity.tokens import TokenPair
from warden.identity.users import SignInMethod, User, UserError, Users, UserStatus

__all__ = [
    "TOTP_KEY_SECRET",
    "AuthenticationRefused",
    "ChallengeIssued",
    "Enrolment",
    "Identity",
    "LastAdministratorError",
    "MfaError",
    "PasswordHasher",
    "PermissionRegistry",
    "PolicyError",
    "PolicyStore",
    "Principal",
    "ResourceScopeHook",
    "Role",
    "RoleAssignment",
    "RoleError",
    "Roles",
    "SecretKeyError",
    "SessionPolicy",
    "SignInMethod",
    "SignInResult",
    "TokenPair",
    "User",
    "UserError",
    "UserStatus",
    "Users",
    "new_totp_key",
    "require_permission",
    "require_user",
]
