"""Refusals from the WebAuthn ceremonies and the credential store.

A refusal names its reason and the identifiers involved (the user and
warden's id for the credential), never credential material: no public key,
signature, client data, attestation statement, challenge or user handle.
The callers that face a browser (waves 10 and 11) answer every refusal
alike and record the reason in the audit trail.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

__all__ = ["WebAuthnError", "WebAuthnRefusal"]


class WebAuthnRefusal(StrEnum):
    """Why a ceremony, or a change to a credential, was refused."""

    MALFORMED = "malformed"
    """The response could not be read as a WebAuthn response."""
    CHALLENGE_UNKNOWN = "challenge_unknown"
    CHALLENGE_USED = "challenge_used"
    CHALLENGE_EXPIRED = "challenge_expired"
    CHALLENGE_PURPOSE = "challenge_purpose"
    """The challenge was issued for the other ceremony (registration or sign-in)."""
    CHALLENGE_USER = "challenge_user"
    """The challenge was issued for another user, or for a discoverable sign-in."""
    TYPE = "type"
    ORIGIN = "origin"
    CROSS_ORIGIN = "cross_origin"
    RP_ID_HASH = "rp_id_hash"
    USER_PRESENCE = "user_presence"
    USER_VERIFICATION = "user_verification"
    FLAGS = "flags"
    """The authenticator data's flags are inconsistent (backed up but not eligible)."""
    NOT_DISCOVERABLE = "not_discoverable"
    ALGORITHM = "algorithm"
    ATTESTATION = "attestation"
    """Trusted roots are configured and the attestation does not chain to one."""
    CREDENTIAL_EXISTS = "credential_exists"
    UNKNOWN_CREDENTIAL = "unknown_credential"
    CREDENTIAL_NOT_ALLOWED = "credential_not_allowed"
    """The credential belongs to another user than the ceremony's."""
    USER_HANDLE = "user_handle"
    BACKUP_ELIGIBILITY = "backup_eligibility"
    SIGNATURE = "signature"
    SUSPECTED_CLONE = "suspected_clone"
    """The signature counter did not increase: the key may have been copied."""
    NO_CREDENTIALS = "no_credentials"
    LIMIT_REACHED = "limit_reached"
    UNKNOWN_USER = "unknown_user"
    INACTIVE_USER = "inactive_user"
    SSO_ONLY = "sso_only"
    """Ruling P5: a single sign-on only user's identity provider owns authentication."""
    NICKNAME = "nickname"


class WebAuthnError(Exception):
    """A WebAuthn ceremony or credential change was refused.

    ``user_id`` and ``credential_id`` (warden's id for the credential, not
    the authenticator's) are set where known.
    """

    def __init__(
        self,
        reason: WebAuthnRefusal,
        *,
        user_id: uuid.UUID | None = None,
        credential_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(f"webauthn refused: {reason.value}")
        self.reason = reason
        self.user_id = user_id
        self.credential_id = credential_id

    @property
    def suspected_clone(self) -> bool:
        """Whether the refusal reports a credential that may have been copied."""
        return self.reason is WebAuthnRefusal.SUSPECTED_CLONE
