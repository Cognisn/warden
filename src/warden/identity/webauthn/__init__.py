"""Passkeys and security keys (WebAuthn): the ceremonies and the credential store.

``WebAuthn`` is the relying party. It registers credentials for a user, as
a second factor or as a passkey, and signs users in with them, for a known
user or discoverably (rulings P0 to P12 of 6 November 2026). It adds no
HTTP route and records no audit event: identity's sign-in and enrolment
paths call it and record each outcome. ``WebAuthnError`` carries the reason
for a refusal and identifiers only.
"""

from warden.identity.webauthn.errors import WebAuthnError, WebAuthnRefusal
from warden.identity.webauthn.service import (
    WebAuthn,
    WebAuthnAssertion,
    WebAuthnOptions,
    WebAuthnPurpose,
    WebAuthnRegistration,
)
from warden.identity.webauthn.store import WebAuthnCredential, WebAuthnCredentials

__all__ = [
    "WebAuthn",
    "WebAuthnAssertion",
    "WebAuthnCredential",
    "WebAuthnCredentials",
    "WebAuthnError",
    "WebAuthnOptions",
    "WebAuthnPurpose",
    "WebAuthnRefusal",
    "WebAuthnRegistration",
]
