"""Signing in with a passkey or security key: known-user and discoverable ceremonies."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fido2.utils import websafe_decode
from identity_support import UserFactory, race
from soft_authenticator import RP_ID, SoftwareAuthenticator, other_key
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


async def _enrolled(
    webauthn: WebAuthn, make_user: UserFactory, purpose: WebAuthnPurpose = SECOND_FACTOR, **kw: Any
) -> tuple[uuid.UUID, SoftwareAuthenticator]:
    user = await make_user()
    authenticator = SoftwareAuthenticator(**kw)
    await register(webauthn, user.id, authenticator, purpose)
    return user.id, authenticator


async def _refused(
    webauthn: WebAuthn,
    user_id: uuid.UUID | None,
    response: dict[str, Any],
    reason: WebAuthnRefusal,
) -> WebAuthnError:
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.finish_authentication(user_id, response)
    assert caught.value.reason is reason, caught.value.reason
    return caught.value


# Round trips: each algorithm, known user and discoverable.


@pytest.mark.parametrize("algorithm", ["ES256", "EdDSA", "RS256"])
async def test_a_second_factor_round_trip(
    webauthn: WebAuthn, make_user: UserFactory, algorithm: Any
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, algorithm=algorithm)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    assertion = await webauthn.finish_authentication(
        user_id, authenticator.authenticate(options.public_key)
    )
    assert assertion.user_id == user_id
    assert assertion.user_verified is True
    assert assertion.credential.sign_count == 1
    assert assertion.credential.last_used_at is not None
    (stored,) = await webauthn.credentials.list(user_id)
    assert stored == assertion.credential


@pytest.mark.parametrize("algorithm", ["ES256", "EdDSA", "RS256"])
async def test_a_discoverable_passkey_round_trip(
    webauthn: WebAuthn, make_user: UserFactory, algorithm: Any
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, PASSKEY, algorithm=algorithm)
    options = await webauthn.begin_authentication(None, require_user_verification=True)
    assertion = await webauthn.finish_authentication(
        None, authenticator.authenticate(options.public_key)
    )
    assert assertion.user_id == user_id
    assert assertion.user_verified is True


async def test_known_user_options_list_only_that_users_credentials(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, transports=("usb", "nfc"))
    await _enrolled(webauthn, make_user)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    public_key = options.public_key
    assert public_key["rpId"] == RP_ID
    assert public_key["userVerification"] == "preferred"
    assert public_key["timeout"] == 240_000
    assert len(challenge_of(public_key)) == 32
    assert [(websafe_decode(d["id"]), d["transports"]) for d in public_key["allowCredentials"]] == [
        (authenticator.only_credential().credential_id, ["usb", "nfc"])
    ]


async def test_discoverable_options_reveal_no_credentials(webauthn: WebAuthn) -> None:
    public_key = (
        await webauthn.begin_authentication(None, require_user_verification=True)
    ).public_key
    assert not public_key.get("allowCredentials")
    assert public_key["userVerification"] == "required"


async def test_a_discoverable_sign_in_always_requires_user_verification(webauthn: WebAuthn) -> None:
    with pytest.raises(ValueError, match="user verification"):
        await webauthn.begin_authentication(None, require_user_verification=False)


async def test_a_user_without_credentials_cannot_begin(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user = await make_user()
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.begin_authentication(user.id, require_user_verification=False)
    assert caught.value.reason is R.NO_CREDENTIALS


async def test_an_authenticator_without_a_counter_keeps_working(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    _user_id, authenticator = await _enrolled(
        webauthn, make_user, PASSKEY, counter_step=0, backup_eligible=True, backed_up=True
    )
    for _ in range(3):
        options = await webauthn.begin_authentication(None, require_user_verification=True)
        assertion = await webauthn.finish_authentication(
            None, authenticator.authenticate(options.public_key)
        )
        assert assertion.credential.sign_count == 0


async def test_the_backup_state_follows_the_authenticator(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, backup_eligible=True)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    assertion = await webauthn.finish_authentication(
        user_id, authenticator.authenticate(options.public_key, bs=True)
    )
    assert assertion.credential.backup_state is True


# Checks on every response.


@pytest.mark.parametrize(
    ("tamper", "reason"),
    [
        ({"origin": "https://evil.example.net"}, R.ORIGIN),
        ({"origin": "https://app.example.com/"}, R.ORIGIN),
        ({"rp_id": "example.org"}, R.RP_ID_HASH),
        ({"type": "webauthn.create"}, R.TYPE),
        ({"cross_origin": True}, R.CROSS_ORIGIN),
        ({"up": False}, R.USER_PRESENCE),
        ({"signing_key": other_key()}, R.SIGNATURE),
        ({"be": False}, R.BACKUP_ELIGIBILITY),
        ({"be": False, "bs": True}, R.FLAGS),
    ],
    ids=[
        "foreign-origin",
        "trailing-slash",
        "rp-id-hash",
        "type",
        "cross-origin",
        "user-presence",
        "signature",
        "backup-eligibility-changed",
        "backed-up-not-eligible",
    ],
)
async def test_a_tampered_assertion_is_refused(
    webauthn: WebAuthn,
    make_user: UserFactory,
    tamper: dict[str, Any],
    reason: WebAuthnRefusal,
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, backup_eligible=True)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    response = authenticator.authenticate(options.public_key, **tamper)
    await _refused(webauthn, user_id, response, reason)
    (stored,) = await webauthn.credentials.list(user_id)
    assert stored.last_used_at is None
    assert stored.sign_count == 0


async def test_user_verification_absent_when_required_is_refused(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user)
    options = await webauthn.begin_authentication(user_id, require_user_verification=True)
    response = authenticator.authenticate(options.public_key, uv=False)
    await _refused(webauthn, user_id, response, R.USER_VERIFICATION)


async def test_user_verification_absent_when_preferred_is_accepted(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    assertion = await webauthn.finish_authentication(
        user_id, authenticator.authenticate(options.public_key, uv=False)
    )
    assert assertion.user_verified is False


async def test_a_discoverable_sign_in_without_user_verification_is_refused(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    _user_id, authenticator = await _enrolled(webauthn, make_user, PASSKEY)
    options = await webauthn.begin_authentication(None, require_user_verification=True)
    response = authenticator.authenticate(options.public_key, uv=False)
    await _refused(webauthn, None, response, R.USER_VERIFICATION)


async def test_a_replayed_assertion_is_refused(webauthn: WebAuthn, make_user: UserFactory) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    response = authenticator.authenticate(options.public_key)
    await webauthn.finish_authentication(user_id, response)
    await _refused(webauthn, user_id, response, R.CHALLENGE_USED)


async def test_an_expired_challenge_is_refused(
    webauthn: WebAuthn, make_user: UserFactory, db: Database
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    await expire_challenges(db)
    response = authenticator.authenticate(options.public_key)
    await _refused(webauthn, user_id, response, R.CHALLENGE_EXPIRED)


async def test_a_registration_challenge_cannot_sign_in(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user)
    registration = await webauthn.begin_registration(user_id, SECOND_FACTOR)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    response = authenticator.authenticate(
        options.public_key, challenge=challenge_of(registration.public_key)
    )
    await _refused(webauthn, user_id, response, R.CHALLENGE_PURPOSE)


async def test_a_known_user_challenge_cannot_finish_a_discoverable_sign_in(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, PASSKEY)
    options = await webauthn.begin_authentication(user_id, require_user_verification=True)
    response = authenticator.authenticate(options.public_key)
    await _refused(webauthn, None, response, R.CHALLENGE_USER)
    # A discoverable challenge cannot finish a known user's sign-in either.
    options = await webauthn.begin_authentication(None, require_user_verification=True)
    response = authenticator.authenticate(options.public_key)
    await _refused(webauthn, user_id, response, R.CHALLENGE_USER)


async def test_an_unknown_credential_is_refused(webauthn: WebAuthn, make_user: UserFactory) -> None:
    await _enrolled(webauthn, make_user, PASSKEY)
    stranger = SoftwareAuthenticator(resident=True)
    stranger.register({"rp": {"id": RP_ID}, "user": {"id": "AAAA"}, "challenge": "AAAA"})
    options = await webauthn.begin_authentication(None, require_user_verification=True)
    await _refused(webauthn, None, stranger.authenticate(options.public_key), R.UNKNOWN_CREDENTIAL)


async def test_another_users_credential_is_refused(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, _ = await _enrolled(webauthn, make_user)
    _other_id, theirs = await _enrolled(webauthn, make_user)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    response = theirs.authenticate(
        options.public_key, credential_id=theirs.only_credential().credential_id
    )
    await _refused(webauthn, user_id, response, R.CREDENTIAL_NOT_ALLOWED)


@pytest.mark.parametrize("handle", [None, b"\x00" * 64, "other"])
async def test_a_discoverable_sign_in_needs_the_owners_user_handle(
    webauthn: WebAuthn, make_user: UserFactory, handle: Any
) -> None:
    _user_id, authenticator = await _enrolled(webauthn, make_user, PASSKEY)
    if handle == "other":
        _other_id, theirs = await _enrolled(webauthn, make_user, PASSKEY)
        handle = theirs.only_credential().user_handle
    options = await webauthn.begin_authentication(None, require_user_verification=True)
    response = authenticator.authenticate(options.public_key, user_handle=handle)
    await _refused(webauthn, None, response, R.USER_HANDLE)


# The counter rule: a non-zero counter that does not increase is a suspected clone.


@pytest.mark.parametrize("counter", [5, 4, 0], ids=["equal", "lower", "reset-to-zero"])
async def test_a_counter_that_does_not_increase_is_a_suspected_clone(
    webauthn: WebAuthn, make_user: UserFactory, counter: int
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user)
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    await webauthn.finish_authentication(
        user_id, authenticator.authenticate(options.public_key, counter=5)
    )
    options = await webauthn.begin_authentication(user_id, require_user_verification=False)
    response = authenticator.authenticate(options.public_key, counter=counter)
    error = await _refused(webauthn, user_id, response, R.SUSPECTED_CLONE)
    assert error.suspected_clone is True
    (stored,) = await webauthn.credentials.list(user_id)
    assert error.credential_id == stored.id
    assert stored.sign_count == 5


async def test_a_counter_that_increases_is_accepted_and_stored(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user)
    for counter in (3, 4, 100):
        options = await webauthn.begin_authentication(user_id, require_user_verification=False)
        assertion = await webauthn.finish_authentication(
            user_id, authenticator.authenticate(options.public_key, counter=counter)
        )
        assert assertion.credential.sign_count == counter


# The user: inactive or single sign-on only.


@pytest.mark.parametrize("status", [UserStatus.SUSPENDED, UserStatus.DEACTIVATED])
async def test_an_inactive_user_gets_nothing(
    webauthn: WebAuthn, make_user: UserFactory, identity: Identity, status: UserStatus
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, PASSKEY)
    known = await webauthn.begin_authentication(user_id, require_user_verification=True)
    anyone = await webauthn.begin_authentication(None, require_user_verification=True)
    await identity.users.set_status(user_id, status, actor="test")

    await _refused(webauthn, user_id, authenticator.authenticate(known.public_key), R.INACTIVE_USER)
    await _refused(webauthn, None, authenticator.authenticate(anyone.public_key), R.INACTIVE_USER)
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.begin_authentication(user_id, require_user_verification=False)
    assert caught.value.reason is R.INACTIVE_USER
    (stored,) = await webauthn.credentials.list(user_id)
    assert stored.last_used_at is None


async def test_an_sso_only_user_gets_nothing(
    webauthn: WebAuthn, make_user: UserFactory, db: Database
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, PASSKEY)
    options = await webauthn.begin_authentication(None, require_user_verification=True)
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE warden.users SET sign_in_method = %s WHERE id = %s",
            (SignInMethod.SSO_ONLY.value, user_id),
        )
    await _refused(webauthn, None, authenticator.authenticate(options.public_key), R.SSO_ONLY)
    with pytest.raises(WebAuthnError) as caught:
        await webauthn.begin_authentication(user_id, require_user_verification=False)
    assert caught.value.reason is R.SSO_ONLY


# Single use under concurrency.


@pytest.mark.parametrize("discoverable", [False, True])
async def test_the_same_assertion_submitted_concurrently_is_accepted_once(
    webauthn: WebAuthn, make_user: UserFactory, discoverable: bool
) -> None:
    user_id, authenticator = await _enrolled(webauthn, make_user, PASSKEY, counter_step=0)
    who = None if discoverable else user_id
    options = await webauthn.begin_authentication(who, require_user_verification=True)
    response = authenticator.authenticate(options.public_key)
    outcomes = await race(
        *(lambda: webauthn.finish_authentication(who, response) for _ in range(8))
    )
    accepted = [o for o in outcomes if not isinstance(o, BaseException)]
    assert len(accepted) == 1
    assert {refusal(o) for o in outcomes if isinstance(o, BaseException)} == {R.CHALLENGE_USED}


async def test_two_assertions_with_the_same_counter_race_and_one_is_a_suspected_clone(
    webauthn: WebAuthn, make_user: UserFactory
) -> None:
    # Two authenticators holding one key (a clone) answer two ceremonies with
    # the same counter at once: the guarded counter write lets one through.
    user_id, authenticator = await _enrolled(webauthn, make_user)
    first = await webauthn.begin_authentication(user_id, require_user_verification=False)
    second = await webauthn.begin_authentication(user_id, require_user_verification=False)
    responses = [authenticator.authenticate(o.public_key, counter=7) for o in (first, second)]
    outcomes = await race(
        *(lambda r=r: webauthn.finish_authentication(user_id, r) for r in responses)
    )
    accepted = [o for o in outcomes if not isinstance(o, BaseException)]
    assert len(accepted) == 1
    assert [refusal(o) for o in outcomes if isinstance(o, BaseException)] == [R.SUSPECTED_CLONE]
