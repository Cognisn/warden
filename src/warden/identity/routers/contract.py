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
    "ChallengeBody",
    "ChangePasswordBody",
    "CodeBody",
    "EnrolmentBody",
    "EnrolmentConfirmBody",
    "HandoffBody",
    "InvitationAcceptBody",
    "InvitationCreateBody",
    "NewApiKeyBody",
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
    "WardenApiKey",
    "WardenApiKeyList",
    "WardenChallengeIssued",
    "WardenDetail",
    "WardenEnrolmentConfirmed",
    "WardenForbidden",
    "WardenInvitationAccepted",
    "WardenInvitationIssued",
    "WardenInvitationList",
    "WardenNewApiKeyIssued",
    "WardenPendingInvitation",
    "WardenRecoveryCodes",
    "WardenRefusal",
    "WardenResetRequested",
    "WardenResetSent",
    "WardenRole",
    "WardenRoleAssignment",
    "WardenRoleList",
    "WardenSignInAnswer",
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
    "detail",
    "json_body",
    "no_store",
]


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


class WardenSignedInAfterEnrolment(WardenSignedIn):
    """A new session after a forced enrolment, with the recovery codes, shown once."""

    recovery_codes: list[str]


class WardenChallengeIssued(_Doc):
    """The password was right; a second factor, or TOTP enrolment, comes next."""

    status: Literal["mfa_required", "mfa_enrolment_required"]
    challenge: str = Field(description="Opaque; pass it to the next step.")
    expires_in: int = Field(description="Seconds until the challenge expires.")


class WardenSignInAnswer(RootModel[WardenSignedIn | WardenChallengeIssued]):
    """What ``POST /sign-in`` answers: a session, or a challenge for the next step."""


class WardenTotpEnrolment(_Doc):
    secret: str = Field(description="The TOTP secret, base32.")
    uri: str = Field(description="An `otpauth://totp/` URI for an authenticator app.")


class WardenRecoveryCodes(_Doc):
    recovery_codes: list[str] = Field(description="Each usable once; shown only now.")


class WardenEnrolmentConfirmed(RootModel[WardenRecoveryCodes | WardenSignedInAfterEnrolment]):
    """The recovery codes; under a challenge, with the new session as well."""


class WardenInvitationAccepted(_Doc):
    status: Literal["accepted"]
    email: str


class WardenResetRequested(_Doc):
    status: Literal["requested"]


class WardenResetSent(_Doc):
    status: Literal["sent"]


class WardenUser(_Doc):
    id: str = Field(description="UUID.")
    email: str
    display_name: str | None
    status: Literal["invited", "active", "suspended", "deactivated"]
    sign_in_method: Literal["password_and_sso", "sso_only"]
    has_password: bool
    created_at: datetime
    updated_at: datetime


class WardenUserList(_Doc):
    users: list[WardenUser] = Field(description="Every matching user, oldest first.")


class WardenUserEnvelope(_Doc):
    user: WardenUser


class WardenRoleAssignment(_Doc):
    role: str
    granted_at: datetime
    granted_by: str | None
    expires_at: datetime | None


class WardenUserDetail(_Doc):
    user: WardenUser
    roles: list[WardenRoleAssignment]


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


class InvitationAcceptBody(_Doc):
    token: str = Field(description="The token from the invitation link.")
    password: str


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
    sign_in_method: Literal["password_and_sso", "sso_only"]


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
    sign_in_method: Literal["password_and_sso", "sso_only"] = "password_and_sso"
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
