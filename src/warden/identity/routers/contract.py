"""Documentation metadata for identity's routes: OpenAPI bodies and responses.

Identity's routes read their own request bodies and build their own
responses (``warden.identity.http``), so FastAPI cannot infer either. The
models here describe them for the published contract
(``docs/contract/openapi.json``) and are never used to parse or build a
request or response: changing one changes the document, not the behaviour.
Internal to warden's routers: not exported from ``warden.identity``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

__all__ = [
    "FORBIDDEN",
    "PRODUCT_AUTHORISATION",
    "REFUSED",
    "AffectedUsersProposalBody",
    "BuiltinListBody",
    "ChallengeBody",
    "ChangePasswordBody",
    "CodeBody",
    "EnrolmentBody",
    "EnrolmentConfirmBody",
    "HandoffBody",
    "InvitationAcceptBody",
    "InvitationCreateBody",
    "LinkPasswordCheckBody",
    "LinkTokenBody",
    "NewApiKeyBody",
    "PasskeyRegistrationBody",
    "PasskeySignInBody",
    "PasskeyTokenBody",
    "PasswordChangeBody",
    "PasswordChangeChallengeBody",
    "PasswordChangeCheckBody",
    "PasswordCheckBody",
    "PasswordPolicyCreateBody",
    "PasswordPolicyOrderBody",
    "PasswordPolicyPinBody",
    "PasswordPolicyPriorityBody",
    "PasswordPolicyRoleBody",
    "PasswordPolicyUpdateBody",
    "RefreshBody",
    "ResetCompleteBody",
    "ResetRequestBody",
    "RoleAssignBody",
    "SignInBody",
    "SignInMethodBody",
    "SsoClientSecretBody",
    "SsoInvitationBody",
    "StagedGrantBody",
    "StatusBody",
    "WardenAffectedUsers",
    "WardenAffectedUsersProposal",
    "WardenApiKey",
    "WardenApiKeyList",
    "WardenCapabilities",
    "WardenChallengeIssued",
    "WardenChangeRequired",
    "WardenDetail",
    "WardenEnrolmentConfirmed",
    "WardenExposureByList",
    "WardenExposureByPolicy",
    "WardenFieldError",
    "WardenForbidden",
    "WardenInvitationAccepted",
    "WardenInvitationIssued",
    "WardenInvitationList",
    "WardenNewApiKeyIssued",
    "WardenPasskeyInvitationAccepted",
    "WardenPasskeyLinkSent",
    "WardenPasskeyRegistered",
    "WardenPassphraseRule",
    "WardenPasswordChangeRequired",
    "WardenPasswordChangeRequiredAfterEnrolment",
    "WardenPasswordChangeRequiredAfterWebAuthnRegistration",
    "WardenPasswordCheck",
    "WardenPasswordExposure",
    "WardenPasswordExposures",
    "WardenPasswordFailure",
    "WardenPasswordPolicy",
    "WardenPasswordPolicyEnvelope",
    "WardenPasswordPolicyInvalid",
    "WardenPasswordPolicyList",
    "WardenPasswordPolicyRecord",
    "WardenPasswordRefusal",
    "WardenPasswordRejected",
    "WardenPasswordRuleResult",
    "WardenPasswordTier",
    "WardenPasswordWatchListMatch",
    "WardenPendingInvitation",
    "WardenPolicyName",
    "WardenRecoveryCodes",
    "WardenRefusal",
    "WardenResetRequested",
    "WardenResetSent",
    "WardenRole",
    "WardenRoleAssignment",
    "WardenRoleList",
    "WardenSecondFactorAnswer",
    "WardenSignInAnswer",
    "WardenSignInCapabilities",
    "WardenSignInMethodSet",
    "WardenSignedIn",
    "WardenSignedInAfterEnrolment",
    "WardenSsoCheck",
    "WardenSsoReport",
    "WardenStagedGrant",
    "WardenTotpEnrolment",
    "WardenUser",
    "WardenUserDetail",
    "WardenUserEnvelope",
    "WardenUserList",
    "WardenUserPasswordStatus",
    "WardenWatchList",
    "WardenWatchListCount",
    "WardenWatchListEnvelope",
    "WardenWatchListList",
    "WardenWebAuthnCredential",
    "WardenWebAuthnCredentialEnvelope",
    "WardenWebAuthnCredentialList",
    "WardenWebAuthnOptions",
    "WardenWebAuthnRegistered",
    "WardenWebAuthnRegistrationConfirmed",
    "WatchListCreateBody",
    "WatchListEntriesBody",
    "WatchListTermsBody",
    "WatchListUpdateBody",
    "WebAuthnRegistrationConfirmBody",
    "WebAuthnRenameBody",
    "WebAuthnVerifyBody",
    "WebAuthnVerifyOptionsBody",
    "detail",
    "json_body",
    "no_store",
    "password_rejected",
]


SignInMethodName = Literal["password_and_sso", "sso_only", "passkey_only"]


class _Doc(BaseModel):
    model_config = ConfigDict(extra="forbid")


# Bodies identity answers with.


class WardenRefusal(_Doc):
    """The uniform refusal: the same bytes for every authentication failure."""

    detail: Literal["authentication failed"]


class WardenForbidden(_Doc):
    """A signed-in caller without the permission the route needs."""

    detail: Literal["forbidden"]


class WardenDetail(_Doc):
    """A fixed message; never an echo of the request."""

    detail: str


class WardenSignedIn(_Doc):
    """A new session. Every route that issues one answers with this body."""

    status: Literal["signed_in"]
    access_token: str = Field(description="EdDSA-signed access token; send as `Bearer`.")
    token_type: Literal["Bearer"]
    expires_in: int = Field(description="Seconds until the access token expires.")
    refresh_token: str = Field(description="Single-use; replaced on every refresh.")
    refresh_expires_in: int = Field(description="Seconds until the refresh token expires.")
    password_expires_in_days: int | None = Field(
        default=None,
        description=(
            "Only after a password sign-in whose password expires within its policy's warning "
            "window: whole days until it expires (at least 1). Absent otherwise."
        ),
    )


class WardenSignedInAfterEnrolment(WardenSignedIn):
    """A new session after a forced enrolment, with the recovery codes, shown once."""

    recovery_codes: list[str]


ChangeReasonName = Literal["expired", "watch_list", "administrator", "policy"]


class WardenPasswordChangeRequired(_Doc):
    """The password and any second factor were right, but the password must change first.

    No session yet: send the challenge and a new password to
    `POST /password-change`, which answers with the session.
    """

    status: Literal["password_change_required"]
    challenge: str = Field(description="Opaque and single-use; pass it to `/password-change`.")
    expires_in: int = Field(description="Seconds until the challenge expires.")
    reason: ChangeReasonName = Field(
        description=(
            "`expired` (the password reached its policy's maximum age), `watch_list` (it is on "
            "a watch list), `administrator` (an administrator asked for a change) or `policy` "
            "(it fails the current rules of a policy that enforces them at sign-in)."
        )
    )
    watch_list_reason: str | None = Field(
        default=None,
        description="With `watch_list` only: the list's reason, to show the user.",
    )


class WardenPasswordChangeRequiredAfterEnrolment(WardenPasswordChangeRequired):
    """A forced enrolment confirmed, with the recovery codes, but the password must change."""

    recovery_codes: list[str]


class WardenChallengeIssued(_Doc):
    """The password was right; a second factor, or enrolment in one, comes next."""

    status: Literal["mfa_required", "mfa_enrolment_required"]
    challenge: str = Field(description="Opaque; pass it to the next step.")
    expires_in: int = Field(description="Seconds until the challenge expires.")
    methods: list[Literal["totp", "webauthn"]] | None = Field(
        default=None,
        description=(
            "With `mfa_required` only (absent from `mfa_enrolment_required`): the kinds of "
            "second factor the user holds, `totp` before `webauthn`. A recovery code is "
            "always accepted as well."
        ),
    )


class WardenSignInAnswer(
    RootModel[WardenSignedIn | WardenChallengeIssued | WardenPasswordChangeRequired]
):
    """What ``POST /sign-in`` answers: a session, a challenge for the next step, or a
    forced password change."""


class WardenSecondFactorAnswer(RootModel[WardenSignedIn | WardenPasswordChangeRequired]):
    """A completed second factor: a session, or a forced password change first."""


class WardenTotpEnrolment(_Doc):
    secret: str = Field(description="The TOTP secret, base32.")
    uri: str = Field(description="An `otpauth://totp/` URI for an authenticator app.")


class WardenRecoveryCodes(_Doc):
    recovery_codes: list[str] = Field(description="Each usable once; shown only now.")


class WardenEnrolmentConfirmed(
    RootModel[
        WardenRecoveryCodes
        | WardenSignedInAfterEnrolment
        | WardenPasswordChangeRequiredAfterEnrolment
    ]
):
    """The recovery codes; under a challenge, with the new session (or a forced password
    change) as well.

    The codes are fresh when TOTP is the user's first second factor; when
    the user already holds a security key or passkey the list is empty, and
    the codes they hold cover TOTP too.
    """


class WardenWebAuthnOptions(_Doc):
    """What the browser passes to `navigator.credentials.create()` or `get()`."""

    public_key: dict[str, Any] = Field(
        description=(
            "The `publicKey` member as WebAuthn's JSON form (binary values base64url): pass "
            "it to `PublicKeyCredential.parseCreationOptionsFromJSON` or "
            "`parseRequestOptionsFromJSON`."
        )
    )
    expires_at: datetime = Field(description="When the ceremony's challenge stops being usable.")


class WardenWebAuthnCredential(_Doc):
    """A security key or passkey, as its owner sees it. Never the public key."""

    id: str = Field(description="warden's UUID for the credential (not the authenticator's id).")
    nickname: str | None
    created_at: datetime
    last_used_at: datetime | None
    aaguid: str = Field(description="The authenticator model's AAGUID; all zeros when unknown.")
    backup_eligible: bool = Field(description="Whether the credential may be synced (a passkey).")
    backup_state: bool = Field(description="Whether it was backed up when last used.")
    discoverable: bool = Field(description="Whether it can be used without naming the user.")
    passkey: bool = Field(
        description=(
            "Whether it signs in on its own as a passkey: true exactly when it is "
            "discoverable and was registered with user verification."
        )
    )


class WardenWebAuthnCredentialList(_Doc):
    credentials: list[WardenWebAuthnCredential] = Field(description="Oldest first.")


class WardenWebAuthnCredentialEnvelope(_Doc):
    credential: WardenWebAuthnCredential


class WardenWebAuthnRegistered(_Doc):
    """A key registered by a signed-in user."""

    credential: WardenWebAuthnCredential
    recovery_codes: list[str] = Field(
        description=(
            "Fresh codes, shown only now, when the key is the user's first second factor; "
            "otherwise empty."
        )
    )


class WardenSignedInAfterWebAuthnRegistration(WardenSignedInAfterEnrolment):
    """A new session after a forced enrolment completed with a key."""

    credential: WardenWebAuthnCredential


class WardenPasswordChangeRequiredAfterWebAuthnRegistration(
    WardenPasswordChangeRequiredAfterEnrolment
):
    """A forced enrolment completed with a key, but the password must change first."""

    credential: WardenWebAuthnCredential


class WardenWebAuthnRegistrationConfirmed(
    RootModel[
        WardenWebAuthnRegistered
        | WardenSignedInAfterWebAuthnRegistration
        | WardenPasswordChangeRequiredAfterWebAuthnRegistration
    ]
):
    """The key and the recovery codes; under a challenge, with the new session (or a forced
    password change) as well."""


class WardenInvitationAccepted(_Doc):
    status: Literal["accepted"]
    email: str


class WardenPasskeyInvitationAccepted(WardenInvitationAccepted):
    """A `passkey_only` invitation accepted by registering a passkey; not signed in."""

    credential: WardenWebAuthnCredential
    recovery_codes: list[str] = Field(
        description="Fresh codes, shown only now, since the passkey is the user's first factor."
    )


class WardenPasskeyRegistered(_Doc):
    """A passkey registered from an administrator's link; not signed in."""

    status: Literal["registered"]
    credential: WardenWebAuthnCredential
    recovery_codes: list[str] = Field(
        description=(
            "Fresh codes, shown only now, when the user held none; otherwise empty, and the "
            "codes they hold cover the passkey too."
        )
    )


class WardenPasskeyLinkSent(_Doc):
    status: Literal["sent"]
    expires_at: datetime = Field(description="When the link stops working.")


class WardenSignInCapabilities(_Doc):
    """What a sign-in screen may offer. The same for every caller; booleans only."""

    password_reset: bool = Field(
        description=(
            "A reset link can be mailed: `POST /password-reset` sends one to an account "
            "that may have it. When false that route still answers 202 and sends nothing."
        )
    )
    single_sign_on: bool = Field(
        description=(
            "Single sign-on is enabled: `/sso/start` goes to the identity provider. Follows "
            "an administrator's run-time setting within `identity.policy_cache_seconds`."
        )
    )
    passkey_sign_in: bool = Field(
        description="Passkeys work here: `POST /passkey/options` answers with options."
    )


class WardenCapabilities(_Doc):
    """What this deployment can do, for administration. Booleans only, never a setting."""

    mail_sender: bool = Field(description="The product installed a mail sender.")
    invitations: bool = Field(
        description="Invitations can be mailed: a sender and `http.accept_invitation_link`."
    )
    password_reset: bool = Field(
        description="Reset links can be mailed: a sender and `http.reset_password_link`."
    )
    passkey_registration_link: bool = Field(
        description=(
            "A passkey registration link can be mailed: WebAuthn, "
            "`http.passkey_registration_link` and a sender."
        )
    )
    single_sign_on: bool = Field(
        description="Single sign-on is enabled, with an issuer and a client id."
    )
    webauthn: bool = Field(
        description="Passkeys and security keys work: a relying party id is known."
    )


class WardenResetRequested(_Doc):
    status: Literal["requested"]


class WardenResetSent(_Doc):
    status: Literal["sent"]


class WardenUser(_Doc):
    id: str = Field(description="UUID.")
    email: str
    display_name: str | None
    status: Literal["invited", "active", "suspended", "deactivated"]
    sign_in_method: SignInMethodName
    has_password: bool
    created_at: datetime
    updated_at: datetime


class WardenUserList(_Doc):
    users: list[WardenUser] = Field(description="The matching users, oldest first.")
    next: str | None = Field(
        default=None,
        description=(
            "Only when `limit` or `after` was given: the cursor for the following page, "
            "or null on the last page."
        ),
    )


class WardenUserEnvelope(_Doc):
    user: WardenUser


class WardenSignInMethodSet(_Doc):
    user: WardenUser
    has_passkey: bool | None = Field(
        default=None,
        description=(
            "Only when the method set is `passkey_only`: whether the user holds a passkey (a "
            "discoverable credential registered with user verification). When false, send "
            "them a registration link (`POST /users/{user_id}/passkey-registration`)."
        ),
    )


class WardenRoleAssignment(_Doc):
    role: str
    granted_at: datetime
    granted_by: str | None
    expires_at: datetime | None


class WardenUserDetail(_Doc):
    user: WardenUser
    roles: list[WardenRoleAssignment]
    webauthn_credentials: int = Field(
        description="How many security keys and passkeys the user holds."
    )
    password: WardenUserPasswordStatus = Field(
        description="The user's password policy and password state."
    )


class WardenRole(_Doc):
    name: str
    permissions: list[str]
    administrator: bool


class WardenRoleList(_Doc):
    roles: list[WardenRole]
    permissions: dict[str, str] = Field(
        description="Every registered permission: its name to its description."
    )


class WardenStagedGrant(_Doc):
    role: str
    expires_at: datetime | None


class WardenPendingInvitation(_Doc):
    user: WardenUser
    expires_at: datetime | None = Field(description="When the current link expires.")
    roles: list[WardenStagedGrant]


class WardenInvitationList(_Doc):
    invitations: list[WardenPendingInvitation]


class WardenInvitationIssued(_Doc):
    user_id: str
    email: str
    expires_at: datetime
    roles: list[WardenStagedGrant]


class WardenApiKey(_Doc):
    id: str
    user_id: str
    name: str
    hint: str = Field(description="A short, non-secret reminder of the key.")
    scopes: list[str]
    created_at: datetime
    created_by: str | None
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class WardenApiKeyList(_Doc):
    api_keys: list[WardenApiKey]


class WardenNewApiKeyIssued(_Doc):
    key: str = Field(description="The key itself: shown once, never again.")
    api_key: WardenApiKey


class WardenSsoCheck(_Doc):
    name: str
    ok: bool
    reason: str | None


class WardenSsoReport(_Doc):
    ok: bool
    checks: list[WardenSsoCheck]


# Password policies in force (feat/0.1.0-password-enforcement, rulings PW3 to
# PW12): refusals, the forced change and live feedback. Administration routes
# keep their metadata in a block of their own.

PasswordFailureCode = Literal[
    "min_length",
    "max_length",
    "min_classes",
    "max_repeat",
    "no_email",
    "no_display_name",
    "watch_list",
    "watch_list_unavailable",
    "history",
    "min_age",
]


class WardenPasswordFailure(_Doc):
    code: PasswordFailureCode = Field(
        description=(
            "A rule's stable code, `watch_list` (the message is the list's reason), "
            "`watch_list_unavailable` (the breached-password service could not be asked and "
            "the policy refuses then), `history` (one of the user's recent passwords; which "
            "is never said) or `min_age` (changed too recently)."
        )
    )
    message: str = Field(description="A plain sentence to show the user.")


class WardenPasswordRejected(_Doc):
    """A new password the user's password policy refused: every reason, never the password."""

    detail: Literal["password not accepted"]
    failures: list[WardenPasswordFailure] = Field(description="Every failed check, rules first.")


class WardenPasswordPolicy(_Doc):
    """The policy a new password must meet here, for a client to evaluate as the user types."""

    rules: dict[str, Any] = Field(
        description=(
            "The policy's rules in their versioned description (`version` 1): lengths in "
            "Unicode code points after NFC, character classes, the longest run, the user-detail "
            "rule, passphrases and tiers. `docs/contract/password-rule-vectors.json` holds test "
            "cases a client's evaluation must agree with."
        )
    )
    history_count: int = Field(
        description="How many recent passwords the new one may not repeat (checked on submit)."
    )


class WardenPasswordRuleResult(_Doc):
    code: Literal[
        "min_length", "max_length", "min_classes", "max_repeat", "no_email", "no_display_name"
    ]
    passed: bool
    waived: bool = Field(description="The class rule passed only because it is a passphrase.")
    message: str = Field(description="What the rule asks, as a plain sentence.")


class WardenPasswordWatchListMatch(_Doc):
    reason: str = Field(description="The list's reason, to show the user.")


class WardenPasswordCheck(_Doc):
    """A candidate's result against the policy; history is never checked here."""

    ok: bool = Field(
        description="Every rule passed and no watch list refuses it (history is checked on submit)."
    )
    results: list[WardenPasswordRuleResult] = Field(description="Each configured rule, in order.")
    passphrase: bool
    tier: str | None = Field(description="The first change-period tier it meets, if any.")
    watch_list: WardenPasswordWatchListMatch | None = Field(
        description="The first watch list it is on, if any."
    )
    watch_list_unavailable: bool = Field(
        description="The breached-password service could not be asked."
    )


class PasswordCheckBody(_Doc):
    password: str = Field(description="The candidate; never stored or logged.")


class LinkTokenBody(_Doc):
    token: str = Field(description="The token from the link.")


class LinkPasswordCheckBody(_Doc):
    token: str = Field(description="The token from the link.")
    password: str = Field(description="The candidate; never stored or logged.")


class PasswordChangeChallengeBody(_Doc):
    challenge: str = Field(description="The `password_change_required` challenge.")


class PasswordChangeCheckBody(_Doc):
    challenge: str = Field(description="The `password_change_required` challenge.")
    password: str = Field(description="The candidate; never stored or logged.")


class PasswordChangeBody(_Doc):
    challenge: str = Field(description="The `password_change_required` challenge.")
    new_password: str


class WardenPasswordRefusal(RootModel[WardenDetail | WardenPasswordRejected]):
    """A fixed message, or the password policy's refusal naming every failure."""


def password_rejected(description: str, *, also: str | None = None) -> dict[str, Any]:
    """A 400 answered with the password policy's refusal, or (``also``) a fixed message."""
    examples: dict[str, Any] = {
        "refused by the policy": {
            "value": {
                "detail": "password not accepted",
                "failures": [
                    {"code": "min_length", "message": "Use at least 12 characters"},
                    {"code": "watch_list", "message": "This password is too common"},
                ],
            }
        }
    }
    if also is not None:
        examples["refused"] = {"value": {"detail": also}}
    return {
        "model": WardenPasswordRejected if also is None else WardenPasswordRefusal,
        "description": description,
        "headers": no_store(),
        "content": {"application/json": {"examples": examples}},
    }


# Bodies identity reads.


class SignInBody(_Doc):
    email: str
    password: str


class ChallengeBody(_Doc):
    challenge: str
    code: str = Field(description="Six ASCII digits.")


class CodeBody(_Doc):
    challenge: str
    code: str = Field(description="One unused recovery code.")


class RefreshBody(_Doc):
    refresh_token: str


class ChangePasswordBody(_Doc):
    current_password: str
    new_password: str


class EnrolmentBody(_Doc):
    challenge: str | None = Field(
        default=None,
        description="The `mfa_enrolment_required` challenge; omit when sending a bearer token.",
    )


class EnrolmentConfirmBody(_Doc):
    code: str = Field(description="Six ASCII digits from the newly enrolled authenticator.")
    challenge: str | None = Field(
        default=None,
        description="The `mfa_enrolment_required` challenge; omit when sending a bearer token.",
    )


class WebAuthnVerifyOptionsBody(_Doc):
    challenge: str = Field(description="The `mfa_required` challenge.")


class WebAuthnVerifyBody(_Doc):
    challenge: str = Field(description="The `mfa_required` challenge.")
    credential: dict[str, Any] = Field(
        description="The browser's answer to `navigator.credentials.get()`, as its `toJSON()`."
    )


class WebAuthnRegistrationConfirmBody(_Doc):
    credential: dict[str, Any] = Field(
        description=("The browser's answer to `navigator.credentials.create()`, as its `toJSON()`.")
    )
    nickname: str | None = Field(
        default=None, description="1 to 64 characters without control characters."
    )
    challenge: str | None = Field(
        default=None,
        description="The `mfa_enrolment_required` challenge; omit when sending a bearer token.",
    )


class WebAuthnRenameBody(_Doc):
    nickname: str | None = Field(
        description="1 to 64 characters without control characters, or null to clear it."
    )


class InvitationAcceptBody(_Doc):
    token: str = Field(description="The token from the invitation link.")
    password: str


class PasskeySignInBody(_Doc):
    credential: dict[str, Any] = Field(
        description="The browser's answer to `navigator.credentials.get()`, as its `toJSON()`."
    )


class PasskeyTokenBody(_Doc):
    token: str = Field(description="The token from the registration or invitation link.")


class PasskeyRegistrationBody(_Doc):
    token: str = Field(description="The token from the registration or invitation link.")
    credential: dict[str, Any] = Field(
        description="The browser's answer to `navigator.credentials.create()`, as its `toJSON()`."
    )
    nickname: str | None = Field(
        default=None, description="1 to 64 characters without control characters."
    )


class ResetRequestBody(_Doc):
    email: str


class ResetCompleteBody(_Doc):
    token: str = Field(description="The token from the reset link.")
    new_password: str


class HandoffBody(_Doc):
    code: str = Field(description="The `code` the callback put on the completion link.")


class SsoInvitationBody(_Doc):
    invitation: str = Field(description="The token from the invitation link.")


class StatusBody(_Doc):
    status: Literal["invited", "active", "suspended", "deactivated"]


class SignInMethodBody(_Doc):
    sign_in_method: SignInMethodName


class RoleAssignBody(_Doc):
    expires_at: datetime | None = Field(
        default=None,
        description="ISO 8601 with a zone offset; an administrator role cannot expire.",
    )


class StagedGrantBody(_Doc):
    role: str
    expires_at: datetime | None = Field(default=None, description="ISO 8601 with a zone offset.")


class InvitationCreateBody(_Doc):
    email: str
    display_name: str | None = None
    sign_in_method: SignInMethodName = "password_and_sso"
    roles: list[StagedGrantBody] = Field(default_factory=list)


class NewApiKeyBody(_Doc):
    user_id: str = Field(description="UUID of the user the key acts as.")
    name: str
    scopes: list[str] = Field(description="Registered permissions the user holds now.")
    expires_at: datetime | None = Field(
        default=None,
        description=(
            "ISO 8601 with a zone offset; at most `identity.api_key_max_lifetime_days` ahead."
        ),
    )


class SsoClientSecretBody(_Doc):
    client_secret: str = Field(description="1 to 4096 printable characters; never returned.")


# Password policy administration (wave 17, feat/0.1.0-password-policy-admin).
# Kept as one block, apart from the password enforcement routes' models.

PolicySource = Literal["pin", "role", "default"]
WatchListSourceName = Literal["builtin", "list", "term", "hibp"]


class WardenPassphraseRule(_Doc):
    min_length: int = Field(description="Code points a passphrase has at least.")
    min_words: int = Field(
        description="Words separated by spaces, hyphens, full stops or underscores."
    )
    relaxes_classes: bool = Field(description="Whether a passphrase is excused the class rule.")


class WardenPasswordTier(_Doc):
    name: str
    passphrase: bool = Field(
        default=False, description="Met by a passphrase; the length and classes are unused."
    )
    min_length: int = 0
    min_classes: int = 0
    max_age_days: int | None = Field(
        default=None, description="Days until a change is due; null is never."
    )


class WardenPasswordPolicyRecord(_Doc):
    id: str = Field(description="UUID.")
    name: str
    description: str
    priority: int | None = Field(description="1 is the highest; null for the default.")
    is_default: bool
    version: int = Field(description="Send it back to change the policy.")
    roles: list[str] = Field(description="The roles mapped to this policy.")
    min_length: int = Field(description="Code points, after NFC; at least 8.")
    max_length: int = Field(description="Code points, at most 1024.")
    min_classes: int = Field(
        description="Character classes needed: lowercase, uppercase, digit, other letters, symbol."
    )
    max_repeat: int | None = Field(description="The longest run of one character; null is any.")
    forbid_user_details: bool = Field(
        description="Refuse a password containing the email local part or display name."
    )
    passphrase: WardenPassphraseRule | None
    tiers: list[WardenPasswordTier] = Field(
        description="Change-period tiers, strongest first; the first one met is recorded."
    )
    warning_days: int = Field(description="Days before expiry that sign-in warns.")
    history_count: int = Field(description="Previous passwords that may not be reused, 0 to 24.")
    min_age_hours: int = Field(description="Hours before a password may change again.")
    include_builtin: bool = Field(description="Check the built-in common-password list.")
    watch_list_ids: list[str] = Field(description="UUIDs of the watch lists checked.")
    hibp_enabled: bool = Field(description="Ask the Pwned Passwords range API (k-anonymity).")
    hibp_on_unavailable: Literal["allow", "refuse"]
    fingerprint_enabled: bool = Field(
        description="Keep a sealed fingerprint for `warden passwords recheck`; needs a key."
    )
    end_sessions_on_match: bool = Field(description="End live sessions when recheck finds a match.")
    enforce_on_sign_in: bool = Field(
        description="Force a change at sign-in when the password fails the current rules."
    )
    created_at: datetime
    updated_at: datetime


class WardenPasswordPolicyList(_Doc):
    policies: list[WardenPasswordPolicyRecord] = Field(
        description="Highest priority first, then the default."
    )


class WardenPasswordPolicyEnvelope(_Doc):
    policy: WardenPasswordPolicyRecord


class WardenFieldError(_Doc):
    field: str | None = Field(description="The body field at fault, such as `tiers[1]`.")
    message: str = Field(description="A fixed message; never an echo of the value.")


class WardenPasswordPolicyInvalid(_Doc):
    detail: Literal["the password policy is not valid"]
    errors: list[WardenFieldError]


class WardenAffectedUsers(_Doc):
    affected_users: int


class WardenAffectedUsersProposal(_Doc):
    current: int
    proposed: int


class WardenPolicyName(_Doc):
    id: str = Field(description="UUID.")
    name: str


class WardenUserPasswordStatus(_Doc):
    applies: bool = Field(description="Whether the user signs in with a password.")
    policy: WardenPolicyName | None
    source: PolicySource | None = Field(description="Why the policy applies.")
    role: str | None = Field(description="The mapped role that chose it, when `source` is `role`.")
    tier: str | None
    password_set_at: datetime | None
    expires_at: datetime | None
    change_required: bool
    change_reason: ChangeReasonName | None
    watch_list_source: WatchListSourceName | None
    watch_list_id: str | None


class WardenChangeRequired(_Doc):
    change_required: Literal[True]
    change_reason: ChangeReasonName = Field(description="The reason that stands.")


class WardenWatchList(_Doc):
    id: str = Field(description="UUID.")
    name: str
    reason: str = Field(description="What a user is shown when their password is on the list.")
    kind: Literal["manual", "imported"]
    entry_count: int
    term_count: int
    import_threshold: int | None
    last_imported_at: datetime | None
    policy_ids: list[str] = Field(description="The policies that check this list.")
    created_at: datetime
    updated_at: datetime


class WardenWatchListList(_Doc):
    watch_lists: list[WardenWatchList]


class WardenWatchListEnvelope(_Doc):
    watch_list: WardenWatchList


class WardenWatchListCount(_Doc):
    added: int | None = Field(default=None, description="When adding: how many were new.")
    removed: int | None = Field(default=None, description="When removing: how many went.")


class WardenPasswordExposure(_Doc):
    user_id: str
    source: WatchListSourceName
    watch_list_id: str | None
    policy_id: str | None = Field(
        description="Null for a user who does not sign in with a password."
    )


class WardenExposureByList(_Doc):
    source: WatchListSourceName
    watch_list_id: str | None
    users: int


class WardenExposureByPolicy(_Doc):
    policy_id: str | None
    users: int


class WardenPasswordExposures(_Doc):
    users: list[WardenPasswordExposure] = Field(description="In user id order.")
    by_list: list[WardenExposureByList]
    by_policy: list[WardenExposureByPolicy]
    total: int
    next: str | None = Field(
        default=None,
        description=(
            "Only when `limit` or `after` was given: the cursor for the following page, "
            "or null on the last page."
        ),
    )


class PasswordPolicyCreateBody(_Doc):
    name: str = Field(description="1 to 64 characters, unique.")
    priority: int = Field(description="1 to 10000, unique; 1 is the highest.")
    description: str = Field(default="", description="At most 500 characters.")
    min_length: int
    max_length: int = 1024
    min_classes: int = 0
    max_repeat: int | None = None
    forbid_user_details: bool = False
    passphrase: WardenPassphraseRule | None = None
    tiers: list[WardenPasswordTier] = Field(default_factory=list)
    warning_days: int = 14
    history_count: int = 0
    min_age_hours: int = 0
    include_builtin: bool = True
    watch_list_ids: list[str] = Field(default_factory=list)
    hibp_enabled: bool = False
    hibp_on_unavailable: Literal["allow", "refuse"] = "allow"
    fingerprint_enabled: bool = False
    end_sessions_on_match: bool = False
    enforce_on_sign_in: bool = False


class PasswordPolicyUpdateBody(_Doc):
    version: int = Field(description="The version read; a stale one is a 409.")
    name: str | None = None
    description: str | None = None
    min_length: int | None = None
    max_length: int | None = None
    min_classes: int | None = None
    max_repeat: int | None = None
    forbid_user_details: bool | None = None
    passphrase: WardenPassphraseRule | None = None
    tiers: list[WardenPasswordTier] | None = None
    warning_days: int | None = None
    history_count: int | None = None
    min_age_hours: int | None = None
    include_builtin: bool | None = None
    watch_list_ids: list[str] | None = None
    hibp_enabled: bool | None = None
    hibp_on_unavailable: Literal["allow", "refuse"] | None = None
    fingerprint_enabled: bool | None = None
    end_sessions_on_match: bool | None = None
    enforce_on_sign_in: bool | None = None


class PasswordPolicyPriorityBody(_Doc):
    priority: int = Field(description="1 to 10000; 1 is the highest.")


class PasswordPolicyOrderBody(_Doc):
    policy_ids: list[str] = Field(
        description="Every non-default policy's UUID once, highest first."
    )


class BuiltinListBody(_Doc):
    include: bool


class PasswordPolicyRoleBody(_Doc):
    policy_id: str = Field(description="UUID of a policy other than the default.")


class PasswordPolicyPinBody(_Doc):
    policy_id: str = Field(description="UUID.")


class AffectedUsersProposalBody(_Doc):
    policy_id: str | None = Field(default=None, description="UUID; leave out for a new policy.")
    priority: int | None = Field(default=None, description="Required for a new policy.")
    roles: list[str] | None = Field(
        default=None, description="Every role that would map to the policy; declared roles only."
    )


class WatchListCreateBody(_Doc):
    name: str = Field(description="1 to 64 characters, unique.")
    reason: str = Field(description="1 to 200 characters, shown to a user whose password matches.")
    kind: Literal["manual", "imported"]


class WatchListUpdateBody(_Doc):
    name: str | None = None
    reason: str | None = None


class WatchListEntriesBody(_Doc):
    passwords: list[str] = Field(
        description="1 to 100 exact passwords; hashed at once, never kept."
    )


class WatchListTermsBody(_Doc):
    terms: list[str] = Field(description="1 to 100 terms of 3 to 64 characters.")


WardenUserDetail.model_rebuild()


# Response fragments.

_NO_STORE_HEADER = {"description": "Always `no-store`.", "schema": {"type": "string"}}


def no_store() -> dict[str, Any]:
    """The headers of a response identity marks as never to be cached."""
    return {"cache-control": _NO_STORE_HEADER}


REFUSED: dict[int | str, dict[str, Any]] = {
    401: {
        "model": WardenRefusal,
        "description": (
            "The uniform refusal. Every authentication failure on every identity route "
            "answers with these exact bytes, headers and status, with indistinguishable "
            "timing; the reason is recorded only in the audit trail."
        ),
        "headers": {
            "www-authenticate": {"description": "`Bearer`.", "schema": {"type": "string"}},
            **no_store(),
        },
        "content": {"application/json": {"example": {"detail": "authentication failed"}}},
    }
}

FORBIDDEN: dict[int | str, dict[str, Any]] = {
    403: {
        "model": WardenForbidden,
        "description": "Signed in, but without the permission this route requires.",
        "headers": no_store(),
        "content": {"application/json": {"example": {"detail": "forbidden"}}},
    }
}


_PRODUCT_REFUSAL = "Refused by the product's `authorise` dependency; the body is the product's."

PRODUCT_AUTHORISATION: dict[int | str, dict[str, Any]] = {
    401: {"description": _PRODUCT_REFUSAL},
    403: {"description": _PRODUCT_REFUSAL},
}


def detail(description: str, *messages: str) -> dict[str, Any]:
    """An error answered with one of identity's fixed ``detail`` messages."""
    examples = {f"message {n}": {"value": {"detail": m}} for n, m in enumerate(messages, 1)}
    content: dict[str, Any] = {"application/json": {"examples": examples}} if examples else {}
    return {
        "model": WardenDetail,
        "description": description,
        "headers": no_store(),
        "content": content,
    }


def _inline(schema: dict[str, Any]) -> dict[str, Any]:
    """``schema`` with its ``$defs`` references replaced by the definitions themselves."""
    definitions = schema.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                return resolve(dict(definitions[ref.removeprefix("#/$defs/")]))
            return {key: resolve(value) for key, value in node.items()}
        if isinstance(node, list):
            return [resolve(item) for item in node]
        return node

    resolved: dict[str, Any] = resolve(schema)
    return resolved


def json_body(
    model: type[BaseModel],
    *,
    required: bool = True,
    also: tuple[str, ...] = (),
) -> dict[str, Any]:
    """``openapi_extra`` describing a body the route reads itself, as JSON (and ``also``)."""
    schema = _inline(model.model_json_schema())
    media_types = ("application/json", *also)
    return {
        "requestBody": {
            "required": required,
            "content": {media_type: {"schema": schema} for media_type in media_types},
        }
    }
