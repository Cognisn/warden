"""warden's identity subsystem: users, sign-in, sessions, roles and permissions,
the user lifecycle (invitations, password reset, mail, API keys, pruning),
OIDC single sign-on, and passkeys and security keys (WebAuthn).

A product constructs one ``Identity``, installs it on its FastAPI app, and
mounts ``identity.auth_router()`` (and the lifecycle, administration and
single sign-on routers it wants); routes then depend on ``require_user`` or
``require_permission``. The product supplies a ``MailSender`` for
invitations and password resets. Identity records every event through
``warden.audit.record_audit``; it never writes the audit table itself.
"""

from warden.identity.apikeys import ApiKey, ApiKeyError, ApiKeys, NewApiKey
from warden.identity.crypto import TOTP_KEY_SECRET, SecretKeyError, new_totp_key
from warden.identity.dependencies import (
    Principal,
    ResourceScopeHook,
    require_permission,
    require_user,
)
from warden.identity.errors import AuthenticationRefused, MfaError
from warden.identity.invitations import (
    AcceptedInvitation,
    Invitation,
    InvitationError,
    InvitationMismatch,
    Invitations,
    PendingInvitation,
    StagedGrant,
    SubjectPin,
    VerifiedIdentity,
)
from warden.identity.mail import (
    DEFAULT_TEMPLATES,
    MailDeliveryError,
    MailError,
    MailKind,
    MailMessage,
    MailSender,
    MailTemplate,
)
from warden.identity.mfa import Enrolment
from warden.identity.passwords import PasswordHasher, Verification
from warden.identity.policy import PolicyError, PolicyStore, SessionPolicy
from warden.identity.prune import Pruner, PruneReport
from warden.identity.reset import PasswordResets
from warden.identity.roles import (
    LastAdministratorError,
    PermissionRegistry,
    Role,
    RoleAssignment,
    RoleError,
    Roles,
)
from warden.identity.service import ChallengeIssued, Identity, SignInResult
from warden.identity.sso.errors import SsoError
from warden.identity.sso.service import (
    SSO_FAILURE_MESSAGE,
    ConfigurationCheck,
    ConfigurationReport,
    InvitationAcceptance,
    LoginStart,
    SingleSignOn,
)
from warden.identity.sso.settings import SsoSettings, SsoSettingsError, SsoSettingsStore
from warden.identity.tokens import TokenPair
from warden.identity.users import SignInMethod, User, UserError, Users, UserStatus
from warden.identity.webauthn import (
    WebAuthn,
    WebAuthnAssertion,
    WebAuthnCredential,
    WebAuthnCredentials,
    WebAuthnError,
    WebAuthnOptions,
    WebAuthnPurpose,
    WebAuthnRefusal,
    WebAuthnRegistration,
)

__all__ = [
    "DEFAULT_TEMPLATES",
    "SSO_FAILURE_MESSAGE",
    "TOTP_KEY_SECRET",
    "AcceptedInvitation",
    "ApiKey",
    "ApiKeyError",
    "ApiKeys",
    "AuthenticationRefused",
    "ChallengeIssued",
    "ConfigurationCheck",
    "ConfigurationReport",
    "Enrolment",
    "Identity",
    "Invitation",
    "InvitationAcceptance",
    "InvitationError",
    "InvitationMismatch",
    "Invitations",
    "LastAdministratorError",
    "LoginStart",
    "MailDeliveryError",
    "MailError",
    "MailKind",
    "MailMessage",
    "MailSender",
    "MailTemplate",
    "MfaError",
    "NewApiKey",
    "PasswordHasher",
    "PasswordResets",
    "PendingInvitation",
    "PermissionRegistry",
    "PolicyError",
    "PolicyStore",
    "Principal",
    "PruneReport",
    "Pruner",
    "ResourceScopeHook",
    "Role",
    "RoleAssignment",
    "RoleError",
    "Roles",
    "SecretKeyError",
    "SessionPolicy",
    "SignInMethod",
    "SignInResult",
    "SingleSignOn",
    "SsoError",
    "SsoSettings",
    "SsoSettingsError",
    "SsoSettingsStore",
    "StagedGrant",
    "SubjectPin",
    "TokenPair",
    "User",
    "UserError",
    "UserStatus",
    "Users",
    "Verification",
    "VerifiedIdentity",
    "WebAuthn",
    "WebAuthnAssertion",
    "WebAuthnCredential",
    "WebAuthnCredentials",
    "WebAuthnError",
    "WebAuthnOptions",
    "WebAuthnPurpose",
    "WebAuthnRefusal",
    "WebAuthnRegistration",
    "new_totp_key",
    "require_permission",
    "require_user",
]
