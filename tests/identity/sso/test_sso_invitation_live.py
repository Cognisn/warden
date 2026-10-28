"""Live check: an invitation accepted through single sign-on, against the stub provider.

Marked ``integration`` (skipped by default). Run it with the stub provider up,
with the same variables as ``test_sso_live.py``:

    WARDEN_IT_SANDBOX      directory holding idp-certs/
    WARDEN_IT_IDP_PORT     the stub provider's port (stub_idp in ports.txt)

An administrator invites a user; the user's browser posts the link's token to
``POST /auth/sso/start``, signs in on the provider's own login page, and the
callback accepts the invitation and lands with a handoff code. The new user
then signs in again through single sign-on, matched by subject. The
break-glass half, with the provider stopped, is in
``test_sso_break_glass_live.py``.
"""

from __future__ import annotations

import os

import httpx
import pytest
from identity_support import RecordingSender, audit_rows
from sso_support import completion, handoff

pytestmark = [pytest.mark.integration, pytest.mark.db]

if not (os.environ.get("WARDEN_IT_SANDBOX") and os.environ.get("WARDEN_IT_IDP_PORT")):
    pytest.skip("live identity provider not configured", allow_module_level=True)

# After the skip, which that module shares. Its fixtures are used here by name.
from test_sso_live import (  # noqa: E402, F401
    app,
    browser_to_idp,
    config,
    provider_login,
    round_trip,
    secrets,
    sso,
)

from warden.db import Database  # noqa: E402
from warden.identity import Identity, SignInMethod, UserStatus  # noqa: E402


async def accept_through_sso(
    client: httpx.AsyncClient, idp: httpx.AsyncClient, token: str, subject: str, email: str
) -> dict[str, str]:
    started = await client.post("/auth/sso/start", data={"invitation": token})
    assert started.status_code == 303, started.text
    location = started.headers["location"]
    assert token not in location
    code, state = await provider_login(
        idp, location, subject, {"email": email, "email_verified": True}
    )
    return completion(await client.get("/auth/sso/callback", params={"code": code, "state": state}))


async def test_live_invitation_accepted_through_sso_then_sign_in_by_subject(
    client: httpx.AsyncClient,
    browser_to_idp: httpx.AsyncClient,  # noqa: F811 - the shared fixture, by name
    identity: Identity,
    mail: RecordingSender,
    db: Database,
) -> None:
    invitation = await identity.invitations.create(
        "dana@example.com", actor="admin", sign_in_method=SignInMethod.SSO_ONLY
    )
    token = mail.token()

    # An identity for another address is refused, and the invitation stays usable.
    refused = await accept_through_sso(client, browser_to_idp, token, "s-erin", "erin@example.com")
    assert refused == {"error": "sso_failed"}
    reasons = [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sso.sign_in")]
    assert reasons[-1] == "invitation_mismatch"

    # Accepted through the provider (the address differs only in case), then signed in.
    landed = await accept_through_sso(client, browser_to_idp, token, "s-dana", "Dana@Example.com")
    response = await handoff(client, landed["code"])
    assert response.status_code == 200, response.text
    principal = await identity.authenticate(response.json()["access_token"])
    assert principal.user_id == invitation.user_id
    assert principal.amr == ("sso",)
    user = await identity.users.get(invitation.user_id)
    assert user is not None and user.status == UserStatus.ACTIVE
    accepted = await audit_rows(db, "warden.identity.invitation.accepted")
    assert accepted[-1]["outcome"] == "success"
    assert accepted[-1]["details"]["method"] == "sso"

    # A normal sign-in, with no invitation, matches the pinned subject.
    landed = await round_trip(client, browser_to_idp, "s-dana", "dana@example.com")
    response = await handoff(client, landed["code"])
    assert response.status_code == 200, response.text
    again = await identity.authenticate(response.json()["access_token"])
    assert again.user_id == invitation.user_id

    # The link is spent.
    assert await accept_through_sso(
        client, browser_to_idp, token, "s-dana", "dana@example.com"
    ) == {"error": "sso_failed"}
