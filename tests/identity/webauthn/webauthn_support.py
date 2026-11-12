"""Helpers shared by the WebAuthn tests (imported as ``webauthn_support``)."""

from __future__ import annotations

import uuid
from typing import Any

from fido2.utils import websafe_decode
from soft_authenticator import SoftwareAuthenticator

from warden.db import Database
from warden.identity.webauthn import (
    WebAuthn,
    WebAuthnError,
    WebAuthnPurpose,
    WebAuthnRefusal,
    WebAuthnRegistration,
)


async def register(
    webauthn: WebAuthn,
    user_id: uuid.UUID,
    authenticator: SoftwareAuthenticator,
    purpose: WebAuthnPurpose = WebAuthnPurpose.SECOND_FACTOR,
    **tamper: Any,
) -> WebAuthnRegistration:
    options = await webauthn.begin_registration(user_id, purpose)
    response = authenticator.register(options.public_key, **tamper)
    return await webauthn.finish_registration(user_id, response)


async def expire_challenges(db: Database) -> None:
    """Make every outstanding challenge expired, as if its lifetime had passed."""
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.webauthn_challenges"
            " SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'"
        )


def challenge_of(options: dict[str, Any]) -> bytes:
    return websafe_decode(options["challenge"])


def refusal(error: BaseException) -> WebAuthnRefusal:
    assert isinstance(error, WebAuthnError), repr(error)
    return error.reason
