"""Password reset by emailed link: refusal paths, single use (#127), sessions ended."""

from __future__ import annotations

import pytest
from identity_support import PASSWORD, RecordingSender, UserFactory, audit_rows, race

from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, SignInMethod, UserError, UserStatus
from warden.identity.mail import MailDeliveryError, MailKind, format_expiry

pytestmark = pytest.mark.db

NEW_PASSWORD = "a brand new passphrase"


async def _reasons(db: Database, action: str) -> list[tuple[str, str | None]]:
    return [(r["outcome"], r["details"].get("reason")) for r in await audit_rows(db, action)]


async def test_a_reset_link_is_mailed_to_an_active_password_user(
    identity: Identity, db: Database, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user("reset-me@example.com")
    assert await identity.resets.request("RESET-ME@example.com") is None
    assert [(m.kind, m.to) for m in mail.sent] == [
        (MailKind.PASSWORD_RESET, "reset-me@example.com")
    ]
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT expires_at FROM warden.single_use_tokens WHERE user_id = %s", (user.id,)
        )
        row = await cur.fetchone()
    assert row is not None and format_expiry(row[0]) in mail.sent[0].text
    assert await _reasons(db, "warden.identity.password.reset_requested") == [("success", None)]


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ({"method": SignInMethod.SSO_ONLY}, "sso_only"),
        ({"status": UserStatus.SUSPENDED}, "user_suspended"),
        ({"status": UserStatus.DEACTIVATED}, "user_deactivated"),
    ],
)
async def test_no_link_is_sent_where_a_password_cannot_be_used(
    identity: Identity,
    db: Database,
    mail: RecordingSender,
    make_user: UserFactory,
    setup: dict[str, object],
    reason: str,
) -> None:
    user = await make_user("blocked@example.com")
    if "method" in setup:
        await identity.users.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="t")
    if "status" in setup:
        status = setup["status"]
        assert isinstance(status, UserStatus)
        await identity.users.set_status(user.id, status, actor="t")
    assert await identity.resets.request("blocked@example.com") == reason
    assert mail.sent == []
    assert await _reasons(db, "warden.identity.password.reset_requested") == [("failure", reason)]


@pytest.mark.parametrize("email", ["nobody@example.com", "not an address", None, 7])
async def test_an_unknown_address_gets_no_mail(
    identity: Identity, db: Database, mail: RecordingSender, email: object
) -> None:
    assert await identity.resets.request(email) in {"unknown_user", "malformed"}
    assert mail.sent == []


async def test_a_new_request_revokes_earlier_links(
    identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    await identity.resets.request(user.email)
    first = mail.token()
    await identity.resets.request(user.email)
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(first, NEW_PASSWORD)
    await identity.resets.complete(mail.token(), NEW_PASSWORD)


async def test_a_failed_send_leaves_no_link(
    identity: Identity, db: Database, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    mail.fail = True
    with pytest.raises(MailDeliveryError):
        await identity.resets.request(user.email)
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.single_use_tokens")
        assert await cur.fetchone() == (0,)
    assert await _reasons(db, "warden.identity.password.reset_requested") == [
        ("failure", "delivery_failed")
    ]


async def test_completing_a_reset_sets_the_password_and_ends_every_session(
    identity: Identity, db: Database, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    first = await identity.sign_in(user.email, PASSWORD)
    second = await identity.sign_in(user.email, PASSWORD)
    assert first.tokens is not None and second.tokens is not None
    await identity.resets.request(user.email)
    assert await identity.resets.complete(mail.token(), NEW_PASSWORD) == user.id
    for pair in (first.tokens, second.tokens):
        with pytest.raises(AuthenticationRefused):
            await identity.authenticate(pair.access_token)
        with pytest.raises(AuthenticationRefused):
            await identity.refresh(pair.refresh_token)
    with pytest.raises(AuthenticationRefused):
        await identity.sign_in(user.email, PASSWORD)
    assert (await identity.sign_in(user.email, NEW_PASSWORD)).tokens is not None
    rows = await audit_rows(db, "warden.identity.password.reset")
    assert [(r["outcome"], r["details"]["sessions_ended"]) for r in rows] == [("success", 2)]


async def test_a_reset_link_works_once(
    identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    await identity.resets.request(user.email)
    token = mail.token()
    await identity.resets.complete(token, NEW_PASSWORD)
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(token, "yet another passphrase")


async def test_concurrent_completions_use_a_reset_link_once(
    identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    """#127 for reset tokens."""
    user = await make_user()
    for _ in range(3):
        await identity.resets.request(user.email)
        token = mail.token()
        results = await race(
            *[lambda token=token: identity.resets.complete(token, NEW_PASSWORD) for _ in range(4)]
        )
        assert sum(r == user.id for r in results) == 1, results
        assert sum(isinstance(r, AuthenticationRefused) for r in results) == 3, results


async def test_a_weak_password_leaves_the_link_usable(
    identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    await identity.resets.request(user.email)
    with pytest.raises(UserError):
        await identity.resets.complete(mail.token(), "short")
    await identity.resets.complete(mail.token(), NEW_PASSWORD)


@pytest.mark.parametrize("change", ["sso_only", "suspended"])
async def test_a_link_is_refused_and_spent_if_the_account_changed_since(
    identity: Identity,
    db: Database,
    mail: RecordingSender,
    make_user: UserFactory,
    change: str,
) -> None:
    user = await make_user()
    await identity.resets.request(user.email)
    token = mail.token()
    if change == "sso_only":
        await identity.users.set_sign_in_method(user.id, SignInMethod.SSO_ONLY, actor="t")
        expected = "sso_only"
    else:
        await identity.users.set_status(user.id, UserStatus.SUSPENDED, actor="t")
        expected = "user_suspended"
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(token, NEW_PASSWORD)
    await identity.users.set_sign_in_method(user.id, SignInMethod.PASSWORD_AND_SSO, actor="t")
    await identity.users.set_status(user.id, UserStatus.ACTIVE, actor="t")
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(token, NEW_PASSWORD)
    assert await _reasons(db, "warden.identity.password.reset") == [
        ("failure", expected),
        ("failure", "token_not_live"),
    ]
    # The old password still works: nothing was changed.
    assert (await identity.sign_in(user.email, PASSWORD)).tokens is not None


async def test_an_expired_link_is_refused(
    identity: Identity, db: Database, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    await identity.resets.request(user.email)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.single_use_tokens SET created_at = now() - interval '2 hours',"
            " expires_at = now() - interval '1 second'"
        )
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(mail.token(), NEW_PASSWORD)


async def test_an_invitation_link_is_not_a_reset_link(
    identity: Identity, mail: RecordingSender
) -> None:
    await identity.invitations.create("invited@example.com", actor="admin-1")
    with pytest.raises(AuthenticationRefused):
        await identity.resets.complete(mail.token(), NEW_PASSWORD)
