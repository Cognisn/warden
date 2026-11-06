"""Registering a passkey or security key: the options, the checks and every refusal."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fido2.utils import websafe_decode
from identity_support import UserFactory, race
from soft_authenticator import AAGUID, RP_ID, SoftwareAuthenticator, TestCa
from webauthn_support import challenge_of, expire_challenges, refusal, register

from warden.db import Database
from warden.identity import Identity, SignInMethod, UserStatus
from warden.identity.webauthn import (
    WebAuthn,
    WebAuthnError,
    WebAuthnPurpose,
    WebAuthnRefusal,
)

pytestmark = pytest.mark.db

R = WebAuthnRefusal
SECOND_FACTOR = WebAuthnPurpose.SECOND_FACTOR
PASSKEY = WebAuthnPurpose.PASSKEY


async def _refused(
    webauthn: WebAuthn,
    user_id: uuid.UUID,
    response: dict[str, Any],
    reason: WebAuthnRefusal,
    **kw: Any,
) -> WebAuthnError:
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.finish_registration(user_id, response, **kw)
    assert caught.value.reason is reason, caught.value.reason
    return caught.value


# Round trips: each algorithm, both purposes.


@pytest.mark.parametrize("algorithm", ["ES256", "EdDSA", "RS256"])
@pytest.mark.parametrize("purpose", [SECOND_FACTOR, PASSKEY])
async def test_a_registration_round_trip(
    webauthn: WebAuthn, make_user: UserFactory, algorithm: Any, purpose: WebAuthnPurpose
) -> None:
    user = await make_user()
    authenticator = SoftwareAuthenticator(algorithm=algorithm, transports=("usb", "nfc"))
    options = await webauthn.begin_registration(user.id, purpose)
    response = authenticator.register(options.public_key)
    registration = await webauthn.finish_registration(user.id, response, nickname="Desk key")

    credential = registration.credential
    assert registration.purpose is purpose
    assert credential.user_id == user.id
    assert credential.nickname == "Desk key"
    assert credential.aaguid == AAGUID
    assert credential.transports == ("usb", "nfc")
    assert credential.user_verified is True
    assert credential.attestation_verified is False
    assert credential.discoverable is (purpose is PASSKEY)
    assert credential.sign_count == 0
    assert credential.last_used_at is None
    assert await webauthn.credentials.list(user.id) == [credential]


async def test_registration_options_for_a_second_factor(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user("ada@example.com", display_name="Ada")
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    public_key = options.public_key
    assert public_key["rp"] == {"name": RP_ID, "id": RP_ID}
    assert public_key["user"]["name"] == "ada@example.com"
    assert public_key["user"]["displayName"] == "Ada"
    assert len(websafe_decode(public_key["user"]["id"])) == 64
    assert len(challenge_of(public_key)) == 32
    assert [p["alg"] for p in public_key["pubKeyCredParams"]] == [-8, -7, -257]
    assert public_key["timeout"] == 240_000
    assert public_key["authenticatorSelection"] == {
        "residentKey": "preferred",
        "requireResidentKey": False,
        "userVerification": "preferred",
    }
    assert public_key["attestation"] == "none"
    assert public_key["extensions"] == {"credProps": True}
    assert "excludeCredentials" not in public_key or public_key["excludeCredentials"] == []
    assert options.expires_at is not None


async def test_registration_options_for_a_passkey(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    public_key = (await webauthn.begin_registration(user.id, PASSKEY)).public_key
    assert public_key["authenticatorSelection"] == {
        "residentKey": "required",
        "requireResidentKey": True,
        "userVerification": "required",
    }


async def test_the_users_existing_credentials_are_excluded(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    first, second = SoftwareAuthenticator(), SoftwareAuthenticator(transports=("internal",))
    await register(webauthn, user.id, first)
    await register(webauthn, user.id, second)
    other = await make_user()
    await register(webauthn, other.id, SoftwareAuthenticator())

    public_key = (await webauthn.begin_registration(user.id, SECOND_FACTOR)).public_key
    excluded = {
        websafe_decode(d["id"]): d.get("transports") for d in public_key["excludeCredentials"]
    }
    assert excluded == {
        first.only_credential().credential_id: ["usb"],
        second.only_credential().credential_id: ["internal"],
    }


async def test_the_user_handle_is_stable_random_and_never_the_user_id(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user, other = await make_user(), await make_user()
    first = websafe_decode(
        (await webauthn.begin_registration(user.id, PASSKEY)).public_key["user"]["id"]
    )
    again = websafe_decode(
        (await webauthn.begin_registration(user.id, SECOND_FACTOR)).public_key["user"]["id"]
    )
    theirs = websafe_decode(
        (await webauthn.begin_registration(other.id, PASSKEY)).public_key["user"]["id"]
    )
    assert first == again
    assert first != theirs
    for handle, owner in ((first, user.id), (theirs, other.id)):
        assert len(handle) == 64
        assert owner.bytes not in handle
        assert str(owner).encode() not in handle
        assert owner.hex.encode() not in handle


async def test_a_credential_with_rk_reported_is_discoverable(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    registration = await register(webauthn, user.id, SoftwareAuthenticator(resident=True))
    assert registration.credential.discoverable is True


async def test_backup_flags_are_recorded(webauthn: WebAuthn, make_user: UserFactory) -> None:
    user = await make_user()
    synced = SoftwareAuthenticator(backup_eligible=True, backed_up=True, counter_step=0)
    credential = (await register(webauthn, user.id, synced, PASSKEY)).credential
    assert credential.backup_eligible is True
    assert credential.backup_state is True


async def test_user_verification_is_recorded_when_only_preferred(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    authenticator = SoftwareAuthenticator(user_verifying=False)
    credential = (await register(webauthn, user.id, authenticator)).credential
    assert credential.user_verified is False


# Checks on every response.


@pytest.mark.parametrize(
    ("tamper", "reason"),
    [
        ({"origin": "https://evil.example.net"}, R.ORIGIN),
        ({"origin": "https://sub.app.example.com"}, R.ORIGIN),
        ({"origin": "http://app.example.com"}, R.ORIGIN),
        ({"origin": "https://app.example.com:443"}, R.ORIGIN),
        ({"rp_id": "example.org"}, R.RP_ID_HASH),
        ({"type": "webauthn.get"}, R.TYPE),
        ({"cross_origin": True}, R.CROSS_ORIGIN),
        ({"up": False}, R.USER_PRESENCE),
        ({"be": False, "bs": True}, R.FLAGS),
    ],
    ids=[
        "foreign-origin",
        "sub-origin",
        "plain-http",
        "explicit-port",
        "rp-id-hash",
        "type",
        "cross-origin",
        "user-presence",
        "backed-up-not-eligible",
    ],
)
async def test_a_tampered_registration_is_refused(
    webauthn: WebAuthn,
    make_user: UserFactory,
    tamper: dict[str, Any],
    reason: WebAuthnRefusal,
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(options.public_key, **tamper)
    error = await _refused(webauthn, user.id, response, reason)
    assert error.user_id == user.id
    assert await webauthn.credentials.count(user.id) == 0


async def test_user_verification_is_required_for_a_passkey(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, PASSKEY)
    response = SoftwareAuthenticator().register(options.public_key, uv=False)
    await _refused(webauthn, user.id, response, R.USER_VERIFICATION)


async def test_a_passkey_reported_as_not_discoverable_is_refused(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, PASSKEY)
    response = SoftwareAuthenticator().register(options.public_key, report_rk=False)
    await _refused(webauthn, user.id, response, R.NOT_DISCOVERABLE)


async def test_a_replayed_registration_is_refused(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    authenticator = SoftwareAuthenticator()
    await webauthn.finish_registration(user.id, authenticator.register(options.public_key))
    again = authenticator.register(options.public_key)
    await _refused(webauthn, user.id, again, R.CHALLENGE_USED)
    assert await webauthn.credentials.count(user.id) == 1


async def test_a_refused_response_uses_its_challenge_up(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    authenticator = SoftwareAuthenticator()
    bad = authenticator.register(options.public_key, origin="https://evil.example.net")
    await _refused(webauthn, user.id, bad, R.ORIGIN)
    await _refused(webauthn, user.id, authenticator.register(options.public_key), R.CHALLENGE_USED)


async def test_an_expired_challenge_is_refused(
    webauthn: WebAuthn, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    await expire_challenges(db)
    response = SoftwareAuthenticator().register(options.public_key)
    await _refused(webauthn, user.id, response, R.CHALLENGE_EXPIRED)


async def test_an_unknown_challenge_is_refused(webauthn: WebAuthn, make_user: UserFactory) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(options.public_key, challenge=b"\x07" * 32)
    await _refused(webauthn, user.id, response, R.CHALLENGE_UNKNOWN)


async def test_a_sign_in_challenge_cannot_register(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    await register(webauthn, user.id, SoftwareAuthenticator())
    sign_in = await webauthn.begin_authentication(user.id, require_user_verification=False)
    registration = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(
        registration.public_key, challenge=challenge_of(sign_in.public_key)
    )
    await _refused(webauthn, user.id, response, R.CHALLENGE_PURPOSE)
    # The sign-in challenge was not used up by the refusal.
    assert await webauthn.credentials.count(user.id) == 1


async def test_another_users_challenge_cannot_register(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user, other = await make_user(), await make_user()
    options = await webauthn.begin_registration(other.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(options.public_key)
    await _refused(webauthn, user.id, response, R.CHALLENGE_USER)
    # The other user's ceremony is untouched.
    await webauthn.finish_registration(other.id, response)


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"id": "AA", "rawId": "AA", "type": "public-key", "response": {}},
        {"id": "AA", "rawId": "AQ", "type": "public-key", "response": {}},
        "not a mapping",
    ],
    ids=["empty", "no-response", "id-mismatch", "string"],
)
async def test_a_malformed_registration_is_refused(
    webauthn: WebAuthn, make_user: UserFactory, response: Any
) -> None:
    user = await make_user()
    await webauthn.begin_registration(user.id, SECOND_FACTOR)
    await _refused(webauthn, user.id, response, R.MALFORMED)


async def test_a_response_whose_ids_disagree_is_refused(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(options.public_key)
    response["id"] = response["rawId"] = "AAAA"
    await _refused(webauthn, user.id, response, R.MALFORMED)


async def test_the_same_credential_cannot_be_registered_twice(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user, other = await make_user(), await make_user()
    credential_id = b"\x05" * 32
    await register(webauthn, user.id, SoftwareAuthenticator(), credential_id=credential_id)
    options = await webauthn.begin_registration(other.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(options.public_key, credential_id=credential_id)
    await _refused(webauthn, other.id, response, R.CREDENTIAL_EXISTS)


@pytest.mark.parametrize("nickname", ["", "n" * 65, "Desk\nkey", "Desk\x00key"])
async def test_an_invalid_nickname_is_refused_before_the_challenge_is_used(
    webauthn: WebAuthn, make_user: UserFactory, nickname: str
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(options.public_key)
    await _refused(webauthn, user.id, response, R.NICKNAME, nickname=nickname)
    await webauthn.finish_registration(user.id, response, nickname="Desk key")


# The user: unknown, inactive or single sign-on only, and the credential limit.


async def test_an_unknown_user_cannot_begin(webauthn: WebAuthn) -> None:
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.begin_registration(uuid.uuid4(), SECOND_FACTOR)
    assert caught.value.reason is R.UNKNOWN_USER


@pytest.mark.parametrize(
    "status", [UserStatus.SUSPENDED, UserStatus.DEACTIVATED, UserStatus.INVITED]
)
async def test_an_inactive_user_cannot_begin(
    webauthn: WebAuthn, make_user: UserFactory, status: UserStatus
) -> None:
    user = await make_user(status=status)
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.begin_registration(user.id, SECOND_FACTOR)
    assert caught.value.reason is R.INACTIVE_USER


async def test_a_user_suspended_mid_ceremony_cannot_finish(
    webauthn: WebAuthn, make_user: UserFactory, identity: Identity
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="test")
    response = SoftwareAuthenticator().register(options.public_key)
    await _refused(webauthn, user.id, response, R.INACTIVE_USER)
    assert await webauthn.credentials.count(user.id) == 0


async def test_an_sso_only_user_cannot_register(webauthn: WebAuthn, make_user: UserFactory) -> None:
    # Ruling P5: their identity provider owns authentication.
    user = await make_user(password=None, sign_in_method=SignInMethod.SSO_ONLY)
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.begin_registration(user.id, PASSKEY)
    assert caught.value.reason is R.SSO_ONLY


async def test_a_user_made_sso_only_mid_ceremony_cannot_finish(
    webauthn: WebAuthn, make_user: UserFactory, db: Database
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.users SET sign_in_method = 'sso_only' WHERE id = %s", (user.id,)
        )
    response = SoftwareAuthenticator().register(options.public_key)
    await _refused(webauthn, user.id, response, R.SSO_ONLY)


async def test_the_credential_limit_refuses_a_new_ceremony(
    make_webauthn: Any, make_user: UserFactory
) -> None:
    webauthn = make_webauthn(max_credentials_per_user=2)
    user = await make_user()
    for _ in range(2):
        await register(webauthn, user.id, SoftwareAuthenticator())
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.begin_registration(user.id, SECOND_FACTOR)
    assert caught.value.reason is R.LIMIT_REACHED


async def test_the_credential_limit_holds_for_ceremonies_begun_before_it_was_reached(
    make_webauthn: Any, make_user: UserFactory
) -> None:
    webauthn = make_webauthn(max_credentials_per_user=2)
    user = await make_user()
    begun = [await webauthn.begin_registration(user.id, SECOND_FACTOR) for _ in range(4)]
    responses = [SoftwareAuthenticator().register(o.public_key) for o in begun]
    outcomes = await race(
        *(lambda r=r: webauthn.finish_registration(user.id, r) for r in responses)
    )
    refused = [o for o in outcomes if isinstance(o, BaseException)]
    assert len(outcomes) - len(refused) == 2
    assert {refusal(o) for o in refused} == {R.LIMIT_REACHED}
    assert await webauthn.credentials.count(user.id) == 2


# Single use under concurrency.


async def test_the_same_response_submitted_concurrently_registers_once(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    options = await webauthn.begin_registration(user.id, SECOND_FACTOR)
    response = SoftwareAuthenticator().register(options.public_key)
    outcomes = await race(
        *(lambda: webauthn.finish_registration(user.id, response) for _ in range(8))
    )
    accepted = [o for o in outcomes if not isinstance(o, BaseException)]
    assert len(accepted) == 1
    assert {refusal(o) for o in outcomes if isinstance(o, BaseException)} == {R.CHALLENGE_USED}
    assert await webauthn.credentials.count(user.id) == 1


# Trusted attestation roots (ruling P3).


async def test_with_roots_set_direct_attestation_is_requested(
    strict_webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    public_key = (await strict_webauthn.begin_registration(user.id, SECOND_FACTOR)).public_key
    assert public_key["attestation"] == "direct"


async def test_with_roots_set_a_chain_to_a_root_is_accepted(
    strict_webauthn: WebAuthn, make_user: UserFactory, ca: TestCa
) -> None:
    user = await make_user()
    authenticator = SoftwareAuthenticator(attestation="packed", ca=ca)
    credential = (await register(strict_webauthn, user.id, authenticator)).credential
    assert credential.attestation_verified is True
    assert credential.aaguid == AAGUID


async def test_with_several_roots_any_one_suffices(
    make_webauthn: Any, make_user: UserFactory, ca: TestCa, rogue_ca: TestCa
) -> None:
    webauthn = make_webauthn(attestation_roots=rogue_ca.root_pem + ca.root_pem)
    user = await make_user()
    authenticator = SoftwareAuthenticator(attestation="packed", ca=ca)
    assert (await register(webauthn, user.id, authenticator)).credential.attestation_verified


@pytest.mark.parametrize(
    "attestation", ["chain-elsewhere", "self", "none", "through-a-leaf", "bad-signature"]
)
async def test_with_roots_set_untrusted_attestation_is_refused(
    strict_webauthn: WebAuthn,
    make_user: UserFactory,
    ca: TestCa,
    rogue_ca: TestCa,
    attestation: str,
) -> None:
    user = await make_user()
    options = await strict_webauthn.begin_registration(user.id, SECOND_FACTOR)
    if attestation == "chain-elsewhere":
        response = SoftwareAuthenticator(attestation="packed", ca=rogue_ca).register(
            options.public_key
        )
    elif attestation == "through-a-leaf":
        chain, key = ca.forged_chain()
        response = SoftwareAuthenticator(attestation="packed", ca=ca).register(
            options.public_key, x5c=chain, attestation_key=key
        )
    elif attestation == "bad-signature":
        response = SoftwareAuthenticator(attestation="packed", ca=ca).register(
            options.public_key, attestation_key=rogue_ca.leaf_key
        )
    else:
        response = SoftwareAuthenticator(attestation=attestation).register(  # type: ignore[arg-type]
            options.public_key
        )
    await _refused(strict_webauthn, user.id, response, R.ATTESTATION)
    assert await strict_webauthn.credentials.count(user.id) == 0


@pytest.mark.parametrize("attestation", ["none", "self", "packed"])
async def test_without_roots_any_authenticator_registers_unverified(
    webauthn: WebAuthn, make_user: UserFactory, rogue_ca: TestCa, attestation: Any
) -> None:
    user = await make_user()
    authenticator = SoftwareAuthenticator(attestation=attestation, ca=rogue_ca)
    credential = (await register(webauthn, user.id, authenticator)).credential
    assert credential.attestation_verified is False
    assert credential.aaguid == AAGUID
