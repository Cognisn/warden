"""The credential store (list, rename, remove, count) and challenge pruning."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from fido2.utils import websafe_encode
from identity_support import UserFactory
from soft_authenticator import SoftwareAuthenticator
from webauthn_support import expire_challenges, register

from warden.db import Database
from warden.identity.webauthn import WebAuthn, WebAuthnError, WebAuthnPurpose, WebAuthnRefusal

pytestmark = pytest.mark.db


async def test_list_count_rename_and_remove(webauthn: WebAuthn, make_user: UserFactory) -> None:
    user = await make_user()
    first = (await register(webauthn, user.id, SoftwareAuthenticator())).credential
    second = (await register(webauthn, user.id, SoftwareAuthenticator())).credential
    assert await webauthn.credentials.count(user.id) == 2
    assert [c.id for c in await webauthn.credentials.list(user.id)] == [first.id, second.id]

    renamed = await webauthn.credentials.rename(user.id, first.id, "Laptop")
    assert renamed is not None and renamed.nickname == "Laptop"
    cleared = await webauthn.credentials.rename(user.id, first.id, None)
    assert cleared is not None and cleared.nickname is None
    assert await webauthn.credentials.get(user.id, first.id) == cleared

    assert await webauthn.credentials.remove(user.id, first.id) is True
    assert await webauthn.credentials.remove(user.id, first.id) is False
    assert [c.id for c in await webauthn.credentials.list(user.id)] == [second.id]
    assert await webauthn.credentials.count(user.id) == 1


async def test_another_users_credential_cannot_be_touched(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    owner, other = await make_user(), await make_user()
    credential = (await register(webauthn, owner.id, SoftwareAuthenticator())).credential
    assert await webauthn.credentials.get(other.id, credential.id) is None
    assert await webauthn.credentials.rename(other.id, credential.id, "Mine now") is None
    assert await webauthn.credentials.remove(other.id, credential.id) is False
    assert await webauthn.credentials.get(owner.id, credential.id) == credential


async def test_remove_all_removes_only_that_users_credentials(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user, other = await make_user(), await make_user()
    for _ in range(3):
        await register(webauthn, user.id, SoftwareAuthenticator())
    await register(webauthn, other.id, SoftwareAuthenticator())
    assert await webauthn.credentials.remove_all(user.id) == 3
    assert await webauthn.credentials.count(user.id) == 0
    assert await webauthn.credentials.count(other.id) == 1


@pytest.mark.parametrize("nickname", ["", "n" * 65, "Lap\ntop", "Lap\x7ftop"])
async def test_an_invalid_nickname_is_refused(
    webauthn: WebAuthn, make_user: UserFactory, nickname: str
) -> None:
    user = await make_user()
    credential = (await register(webauthn, user.id, SoftwareAuthenticator())).credential
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.credentials.rename(user.id, credential.id, nickname)
    assert caught.value.reason is WebAuthnRefusal.NICKNAME
    assert nickname not in str(caught.value) or nickname == ""


async def test_prune_removes_only_expired_challenges(
    webauthn: WebAuthn, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    await webauthn.begin_registration(user.id, WebAuthnPurpose.SECOND_FACTOR)
    await webauthn.begin_authentication(None, require_user_verification=True)
    await expire_challenges(db)
    live = await webauthn.begin_authentication(None, require_user_verification=True)
    assert await webauthn.prune() == 2
    assert await webauthn.prune() == 0
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.webauthn_challenges")
        assert await cur.fetchone() == (1,)
    assert live.public_key["challenge"]


async def test_no_credential_material_reaches_logs_or_errors(
    webauthn: WebAuthn, make_user: UserFactory, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    user = await make_user()
    authenticator = SoftwareAuthenticator(resident=True)
    options = await webauthn.begin_registration(user.id, WebAuthnPurpose.PASSKEY)
    response = authenticator.register(options.public_key)
    await webauthn.finish_registration(user.id, response)
    stored = authenticator.only_credential()
    errors: list[str] = []
    for tamper in ({"origin": "https://evil.example.net"}, {"uv": False}, {}):
        sign_in = await webauthn.begin_authentication(None, require_user_verification=True)
        assertion: dict[str, Any] = authenticator.authenticate(sign_in.public_key, **tamper)
        try:
            await webauthn.finish_authentication(None, assertion)
        except WebAuthnError as error:
            errors.append(f"{error} {error!r}")
        secrets = [
            sign_in.public_key["challenge"],
            assertion["response"]["signature"],
            assertion["response"]["clientDataJSON"],
            assertion["response"]["authenticatorData"],
        ]
        for secret in secrets:
            assert all(secret not in text for text in errors)
    material = [
        options.public_key["challenge"],
        options.public_key["user"]["id"],
        response["response"]["attestationObject"][:40],
        response["response"]["clientDataJSON"],
        websafe_encode(stored.credential_id),
        stored.credential_id.hex(),
        stored.user_handle.hex(),
    ]
    logged = caplog.text + " ".join(errors)
    assert len(errors) == 2
    for item in material:
        assert item not in logged
