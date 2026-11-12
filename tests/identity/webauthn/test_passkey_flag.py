"""The credential list says which keys sign in on their own as passkeys.

``passkey`` is true exactly when a credential is discoverable and was
registered with user verification, the rule a discoverable sign-in applies
(wave 11 decision 27). Each case checks the listed value against the Python
type, the HTTP list, and whether passkey sign-in really succeeds for that key.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from identity_support import PASSWORD, UserFactory
from passkey_support import (
    give_passkey,
    http_client,
    passkey_authenticator,
    passkey_config,
    passkey_options,
    passkey_sign_in,
)

from warden.config import WardenConfig
from warden.identity import Identity
from warden.identity.webauthn import WebAuthnPurpose

pytestmark = pytest.mark.db


@pytest.fixture
def config() -> WardenConfig:
    return passkey_config(sign_in_attempt_limit=1000)


@pytest.fixture
async def http(identity: Identity) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(identity) as client:
        yield client


CASES = [
    pytest.param(True, True, True, id="discoverable-and-verified"),
    pytest.param(True, False, False, id="discoverable-not-verified"),
    pytest.param(False, True, False, id="not-discoverable"),
]


@pytest.mark.parametrize(("resident", "verifying", "expected"), CASES)
async def test_the_listed_passkey_value_matches_what_sign_in_does(
    http: httpx.AsyncClient,
    identity: Identity,
    make_user: UserFactory,
    resident: bool,
    verifying: bool,
    expected: bool,
) -> None:
    user = await make_user()
    signed_in = await http.post("/auth/sign-in", json={"email": user.email, "password": PASSWORD})
    headers = {"authorization": f"Bearer {signed_in.json()['access_token']}"}
    key, credential = await give_passkey(
        identity,
        user,
        passkey_authenticator(resident=resident, user_verifying=verifying),
        purpose=WebAuthnPurpose.SECOND_FACTOR,
        report_rk=resident,
    )
    assert credential.passkey is expected

    listed = await http.get("/auth/webauthn/credentials", headers=headers)
    assert listed.status_code == 200, listed.text
    (item,) = listed.json()["credentials"]
    assert item["passkey"] is expected
    assert item["discoverable"] is resident

    options = (await passkey_options(http)).json()["public_key"]
    assertion = key.authenticate(
        options, credential_id=key.only_credential().credential_id, uv=True
    )
    answer = await passkey_sign_in(http, assertion)
    assert (answer.status_code == 200) is item["passkey"]
