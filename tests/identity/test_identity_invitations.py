"""Invitations: create, resend, revoke and accept (#127, #128, #129, #154).

Acceptance is one generic service function with a password variant and a
single sign-on entry point; the SSO entry point is driven here with a fake,
already-verified identity. No OIDC code is involved.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from identity_support import RecordingSender, UserFactory, audit_rows, race
from psycopg import AsyncConnection

from warden.db import Database
from warden.identity import (
    AuthenticationRefused,
    Identity,
    RoleError,
    SignInMethod,
    UserError,
    UserStatus,
)
from warden.identity.invitations import (
    InvitationError,
    InvitationMismatch,
    StagedGrant,
    VerifiedIdentity,
)
from warden.identity.mail import MailDeliveryError, MailKind, format_expiry

pytestmark = pytest.mark.db

NEW_PASSWORD = "a brand new passphrase"
ISSUER = "https://idp.example.org"


class FakePins:
    """Stands in for single sign-on's subject pinning; records pins made in the transaction."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[uuid.UUID, str, str]] = []

    async def __call__(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, issuer: str, subject: str
    ) -> None:
        # Prove the pin runs inside the acceptance transaction.
        cur = await conn.execute("SELECT status FROM warden.users WHERE id = %s", (user_id,))
        assert await cur.fetchone() is not None
        if self.fail:
            raise psycopg.errors.UniqueViolation("subject already pinned")
        self.calls.append((user_id, issuer, subject))


async def _invite(
    identity: Identity,
    email: str | None = None,
    *,
    grants: tuple[StagedGrant, ...] = (),
    method: SignInMethod = SignInMethod.PASSWORD_AND_SSO,
) -> uuid.UUID:
    invitation = await identity.invitations.create(
        email or f"invitee-{uuid.uuid4().hex[:8]}@example.com",
        actor="admin-1",
        grants=grants,
        sign_in_method=method,
    )
    return invitation.user_id


async def _status(db: Database, user_id: uuid.UUID) -> str | None:
    async with db.connection() as conn:
        cur = await conn.execute("SELECT status FROM warden.users WHERE id = %s", (user_id,))
        row = await cur.fetchone()
    return None if row is None else str(row[0])


async def _accept(identity: Identity, token: str) -> uuid.UUID:
    return (await identity.invitations.accept_with_password(token, NEW_PASSWORD)).user_id


# Create


async def test_an_invited_user_is_staged_and_mailed(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    invitation = await identity.invitations.create(
        "Ivy@Example.com",
        actor="admin-1",
        display_name="Ivy",
        grants=(StagedGrant("viewer"),),
    )
    user = await identity.users.get(invitation.user_id)
    assert user is not None
    assert user.status is UserStatus.INVITED
    assert not user.has_password  # nothing anyone could sign in with
    assert await identity.roles.roles_of(user.id) == []  # grants wait for acceptance
    assert [m.kind for m in mail.sent] == [MailKind.INVITATION]
    assert mail.sent[0].to == "Ivy@Example.com"
    created = await audit_rows(db, "warden.identity.invitation.created")
    assert [r["outcome"] for r in created] == ["success"]
    assert created[0]["actor"] == "admin-1"
    assert created[0]["details"]["roles"] == ["viewer"]
    assert "token" not in str(created[0]["details"])


async def test_an_invited_user_cannot_sign_in(identity: Identity, mail: RecordingSender) -> None:
    await identity.invitations.create("pending@example.com", actor="admin-1")
    with pytest.raises(AuthenticationRefused):
        await identity.sign_in("pending@example.com", "")


async def test_the_mailed_expiry_is_the_token_row_s_own(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    user_id = await _invite(identity)
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT expires_at FROM warden.single_use_tokens WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    assert format_expiry(row[0]) in mail.sent[-1].text


async def test_a_failed_send_leaves_no_user_or_token_behind(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    mail.fail = True
    with pytest.raises(MailDeliveryError):
        await identity.invitations.create(
            "lost@example.com", actor="admin-1", grants=(StagedGrant("viewer"),)
        )
    assert await identity.users.get_by_email("lost@example.com") is None
    async with db.connection() as conn:
        for name in ("single_use_tokens", "invitation_grants", "users"):
            cur = await conn.execute(f"SELECT count(*) FROM warden.{name}")  # noqa: S608
            assert await cur.fetchone() == (0,), name
    created = await audit_rows(db, "warden.identity.invitation.created")
    assert [(r["outcome"], r["details"]["reason"]) for r in created] == [
        ("failure", "delivery_failed")
    ]
    assert await audit_rows(db, "warden.identity.user.created") == []


async def test_inviting_an_existing_address_is_refused(
    identity: Identity, make_user: UserFactory
) -> None:
    await make_user("taken@example.com")
    with pytest.raises(InvitationError, match="already exists"):
        await identity.invitations.create("TAKEN@example.com", actor="admin-1")


@pytest.mark.parametrize(
    "grant",
    [
        StagedGrant("no-such-role"),
        StagedGrant("admin", expires_at=datetime.now(UTC) + timedelta(days=1)),
        StagedGrant("viewer", expires_at=datetime.now(UTC) - timedelta(seconds=1)),
    ],
)
async def test_staged_grants_are_checked_before_anything_is_written(
    identity: Identity, db: Database, mail: RecordingSender, grant: StagedGrant
) -> None:
    with pytest.raises(RoleError):
        await identity.invitations.create("g@example.com", actor="admin-1", grants=(grant,))
    assert await identity.users.get_by_email("g@example.com") is None
    assert mail.sent == []


async def test_an_invitation_needs_a_mail_sender(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    from warden.identity.mail import Mailer, MailError

    identity.invitations._mailer = Mailer(identity.config.mail, None)
    with pytest.raises(MailError):
        await identity.invitations.create("nomail@example.com", actor="admin-1")
    assert await identity.users.get_by_email("nomail@example.com") is None


# Accept (password variant)


async def test_accepting_activates_sets_the_password_and_applies_staged_grants(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    expiry = datetime.now(UTC) + timedelta(days=30)
    user_id = await _invite(
        identity, grants=(StagedGrant("viewer"), StagedGrant("analyst", expires_at=expiry))
    )
    accepted = await identity.invitations.accept_with_password(mail.token(), NEW_PASSWORD)
    assert accepted.user_id == user_id and accepted.method == "password"
    assert await _status(db, user_id) == "active"
    assignments = {a.role: a for a in await identity.roles.assignments_of(user_id)}
    assert set(assignments) == {"viewer", "analyst"}
    assert assignments["viewer"].expires_at is None
    assert assignments["analyst"].expires_at == expiry
    assert assignments["viewer"].granted_by == "admin-1"
    user = await identity.users.get(user_id)
    assert user is not None
    result = await identity.sign_in(user.email, NEW_PASSWORD)
    assert result.tokens is not None
    accepted_rows = await audit_rows(db, "warden.identity.invitation.accepted")
    assert [(r["outcome"], r["details"]["method"]) for r in accepted_rows] == [
        ("success", "password")
    ]


async def test_a_weak_password_leaves_the_invitation_usable(
    identity: Identity, mail: RecordingSender
) -> None:
    await _invite(identity)
    with pytest.raises(UserError):
        await identity.invitations.accept_with_password(mail.token(), "short")
    await _accept(identity, mail.token())


@pytest.mark.parametrize("token", [None, "", "x" * 43, "not a token"])
async def test_a_bad_token_is_refused_and_audited(
    identity: Identity, db: Database, token: object
) -> None:
    with pytest.raises(AuthenticationRefused):
        await identity.invitations.accept_with_password(token, NEW_PASSWORD)
    rows = await audit_rows(db, "warden.identity.invitation.accepted")
    assert [r["outcome"] for r in rows] == ["failure"]
    assert rows[0]["details"]["reason"] in {"malformed", "unknown_token"}


async def test_an_invitation_is_accepted_once(identity: Identity, mail: RecordingSender) -> None:
    await _invite(identity)
    token = mail.token()
    await _accept(identity, token)
    with pytest.raises(AuthenticationRefused):
        await _accept(identity, token)


async def test_an_expired_invitation_is_refused(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    user_id = await _invite(identity)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.single_use_tokens SET created_at = now() - interval '9 days',"
            " expires_at = now() - interval '1 second'"
        )
    with pytest.raises(AuthenticationRefused):
        await _accept(identity, mail.token())
    assert await _status(db, user_id) == "invited"


async def test_concurrent_acceptances_use_an_invitation_once(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    """#127: concurrent submits of one invitation: exactly one is accepted."""
    for _ in range(3):
        user_id = await _invite(identity, grants=(StagedGrant("viewer"),))
        token = mail.token()
        results = await race(*[lambda token=token: _accept(identity, token) for _ in range(4)])
        assert sum(r == user_id for r in results) == 1, results
        assert sum(isinstance(r, AuthenticationRefused) for r in results) == 3, results
        assert await identity.roles.roles_of(user_id) == ["viewer"]


async def test_concurrent_password_and_sso_acceptances_use_an_invitation_once(
    identity: Identity, mail: RecordingSender
) -> None:
    pins = FakePins()
    for _ in range(3):
        user_id = await _invite(identity, "both@example.com")
        token = mail.token()
        verified = VerifiedIdentity(ISSUER, f"sub-{uuid.uuid4().hex}", "both@example.com")
        results = await race(
            lambda token=token: _accept(identity, token),
            lambda token=token, verified=verified: identity.invitations.accept_with_sso(
                token, verified, pin=pins
            ),
        )
        assert sum(not isinstance(r, Exception) for r in results) == 1, results
        await identity.users.set_status(user_id, UserStatus.DEACTIVATED, actor="t")
        async with identity.db.connection() as conn:
            await conn.execute("DELETE FROM warden.users WHERE id = %s", (user_id,))


# Status (#128) and method (#154)


async def test_acceptance_checks_the_user_s_current_status(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    """#128, and #154's second half: a status refusal uses the invitation up."""
    user_id = await _invite(identity)
    token = mail.token()
    await identity.users.set_status(user_id, UserStatus.SUSPENDED, actor="admin-1")
    with pytest.raises(AuthenticationRefused):
        await _accept(identity, token)
    assert await _status(db, user_id) == "suspended"
    # Even once the user is back in the invited state, the invitation is spent.
    await identity.users.set_status(user_id, UserStatus.INVITED, actor="admin-1")
    with pytest.raises(AuthenticationRefused):
        await _accept(identity, token)
    reasons = [
        r["details"]["reason"] for r in await audit_rows(db, "warden.identity.invitation.accepted")
    ]
    assert reasons == ["user_suspended", "token_not_live"]


async def test_a_suspension_racing_an_acceptance_always_wins_in_the_end(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    """#128 under concurrency: an acceptance never activates a suspended user."""
    for _ in range(5):
        user_id = await _invite(identity)
        token = mail.token()
        await race(
            lambda token=token: _accept(identity, token),
            lambda user_id=user_id: identity.users.set_status(
                user_id, UserStatus.SUSPENDED, actor="admin-1"
            ),
        )
        assert await _status(db, user_id) == "suspended"


async def test_a_suspension_during_an_acceptance_is_never_overwritten(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    """#128, deterministically: a suspension lands between the status check and activation.

    The pin runs inside the acceptance transaction, after the status was read.
    It starts a suspension and gives it time to commit. Holding the user row
    makes the suspension wait for the acceptance, so it is applied last.
    """
    user_id = await _invite(identity, "racer@example.com")
    suspension: list[asyncio.Task[object]] = []

    async def pin(conn: AsyncConnection[Any], uid: uuid.UUID, issuer: str, subject: str) -> None:
        suspension.append(
            asyncio.create_task(
                identity.users.set_status(uid, UserStatus.SUSPENDED, actor="admin-1")
            )
        )
        await asyncio.sleep(0.5)

    verified = VerifiedIdentity(ISSUER, "subject-r", "racer@example.com")
    await identity.invitations.accept_with_sso(mail.token(), verified, pin=pin)
    await suspension[0]
    assert await _status(db, user_id) == "suspended"


async def test_a_wrong_method_leaves_the_invitation_usable(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    """#154: an sso_only invitee using a password is refused without using the invitation."""
    user_id = await _invite(identity, "sso-only@example.com", method=SignInMethod.SSO_ONLY)
    token = mail.token()
    with pytest.raises(InvitationMismatch, match="single sign-on"):
        await _accept(identity, token)
    assert await _status(db, user_id) == "invited"
    pins = FakePins()
    verified = VerifiedIdentity(ISSUER, "subject-1", "SSO-ONLY@example.com")
    accepted = await identity.invitations.accept_with_sso(token, verified, pin=pins)
    assert accepted.user_id == user_id and accepted.method == "sso"
    assert pins.calls == [(user_id, ISSUER, "subject-1")]
    assert await _status(db, user_id) == "active"
    reasons = [
        (r["outcome"], r["details"].get("reason"))
        for r in await audit_rows(db, "warden.identity.invitation.accepted")
    ]
    assert reasons == [("failure", "method_mismatch"), ("success", None)]


# Accept (single sign-on entry point)


async def test_sso_acceptance_pins_the_subject_and_sets_no_password(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    user_id = await _invite(identity, "pinned@example.com", grants=(StagedGrant("viewer"),))
    pins = FakePins()
    verified = VerifiedIdentity(ISSUER, "subject-42", "pinned@example.com")
    accepted = await identity.invitations.accept_with_sso(mail.token(), verified, pin=pins)
    assert accepted.method == "sso" and accepted.roles == ("viewer",)
    assert pins.calls == [(user_id, ISSUER, "subject-42")]
    user = await identity.users.get(user_id)
    assert user is not None and not user.has_password
    rows = await audit_rows(db, "warden.identity.invitation.accepted")
    assert rows[-1]["details"]["issuer"] == ISSUER
    assert "subject-42" not in str(rows[-1]["details"])


async def test_sso_acceptance_for_another_address_leaves_the_invitation_usable(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    user_id = await _invite(identity, "right@example.com")
    pins = FakePins()
    wrong = VerifiedIdentity(ISSUER, "subject-1", "wrong@example.com")
    with pytest.raises(InvitationMismatch):
        await identity.invitations.accept_with_sso(mail.token(), wrong, pin=pins)
    assert pins.calls == []
    assert await _status(db, user_id) == "invited"
    right = VerifiedIdentity(ISSUER, "subject-1", "Right@Example.com")
    await identity.invitations.accept_with_sso(mail.token(), right, pin=pins)


async def test_a_failed_pin_rolls_the_acceptance_back(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    user_id = await _invite(identity, "clash@example.com", grants=(StagedGrant("viewer"),))
    verified = VerifiedIdentity(ISSUER, "taken-subject", "clash@example.com")
    with pytest.raises(psycopg.errors.UniqueViolation):
        await identity.invitations.accept_with_sso(mail.token(), verified, pin=FakePins(fail=True))
    assert await _status(db, user_id) == "invited"
    assert await identity.roles.roles_of(user_id) == []
    await identity.invitations.accept_with_sso(mail.token(), verified, pin=FakePins())
    assert await identity.roles.roles_of(user_id) == ["viewer"]


# Resend


async def test_resend_replaces_the_link_and_keeps_the_staged_grants(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    expiry = datetime.now(UTC) + timedelta(days=10)
    user_id = await _invite(identity, grants=(StagedGrant("analyst", expires_at=expiry),))
    first = mail.token()
    async with db.connection() as conn:
        # The first link has lapsed and been pruned; the staged grants must survive.
        await conn.execute("DELETE FROM warden.single_use_tokens")
    resent = await identity.invitations.resend(user_id, actor="admin-2")
    assert resent.user_id == user_id
    assert [(g.role, g.expires_at) for g in resent.grants] == [("analyst", expiry)]
    second = mail.token()
    assert second != first
    await _accept(identity, second)
    assignments = await identity.roles.assignments_of(user_id)
    assert [(a.role, a.expires_at) for a in assignments] == [("analyst", expiry)]


async def test_resend_revokes_the_previous_link(identity: Identity, mail: RecordingSender) -> None:
    user_id = await _invite(identity)
    first = mail.token()
    await identity.invitations.resend(user_id, actor="admin-1")
    with pytest.raises(AuthenticationRefused):
        await _accept(identity, first)
    await _accept(identity, mail.token())


async def test_a_failed_resend_keeps_the_previous_link(
    identity: Identity, mail: RecordingSender
) -> None:
    user_id = await _invite(identity)
    first = mail.token()
    mail.fail = True
    with pytest.raises(MailDeliveryError):
        await identity.invitations.resend(user_id, actor="admin-1")
    mail.fail = False
    await _accept(identity, first)


async def test_resend_is_refused_once_accepted(identity: Identity, mail: RecordingSender) -> None:
    user_id = await _invite(identity)
    await _accept(identity, mail.token())
    with pytest.raises(InvitationError, match="not pending"):
        await identity.invitations.resend(user_id, actor="admin-1")


# Revoke (#129)


async def test_revoking_removes_the_invited_user(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    user_id = await _invite(identity)
    token = mail.token()
    await identity.invitations.revoke(user_id, actor="admin-1")
    assert await identity.users.get(user_id) is None
    with pytest.raises(AuthenticationRefused):
        await _accept(identity, token)
    revoked = await audit_rows(db, "warden.identity.invitation.revoked")
    assert [(r["outcome"], r["resource_id"]) for r in revoked] == [("success", str(user_id))]


async def test_revoking_an_accepted_invitation_is_refused(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    user_id = await _invite(identity)
    await _accept(identity, mail.token())
    with pytest.raises(InvitationError, match="not pending"):
        await identity.invitations.revoke(user_id, actor="admin-1")
    assert await _status(db, user_id) == "active"


async def test_a_revocation_racing_an_acceptance_never_deletes_an_accepted_user(
    identity: Identity, db: Database, mail: RecordingSender
) -> None:
    """#129: exactly one of the two wins, and an accepted user always survives."""
    for _ in range(6):
        user_id = await _invite(identity)
        token = mail.token()
        accepted, revoked = await race(
            lambda token=token: _accept(identity, token),
            lambda user_id=user_id: identity.invitations.revoke(user_id, actor="admin-1"),
        )
        accept_won = accepted == user_id
        revoke_won = revoked is None
        assert accept_won != revoke_won, (accepted, revoked)
        if accept_won:
            assert isinstance(revoked, InvitationError)
            assert await _status(db, user_id) == "active"
        else:
            assert isinstance(accepted, AuthenticationRefused)
            assert await _status(db, user_id) is None


# Listing


async def test_pending_invitations_are_listed_with_their_expiry(
    identity: Identity, mail: RecordingSender
) -> None:
    waiting = await _invite(identity, grants=(StagedGrant("viewer"),))
    done = await _invite(identity)
    await _accept(identity, mail.token())
    pending = await identity.invitations.pending()
    assert [p.user.id for p in pending] == [waiting]
    assert pending[0].expires_at is not None
    assert [g.role for g in pending[0].grants] == ["viewer"]
    assert done not in {p.user.id for p in pending}
