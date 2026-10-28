"""The MFA-enrolled notice: sent once enrolment is confirmed, never at its expense."""

from __future__ import annotations

import pytest
from identity_support import PASSWORD, RecordingSender, UserFactory, current_code

from warden.db import Database
from warden.identity import Identity, MfaError
from warden.identity.mail import Mailer, MailKind, format_expiry

pytestmark = pytest.mark.db


async def _signed_in(identity: Identity, email: str) -> object:
    result = await identity.sign_in(email, PASSWORD)
    assert result.tokens is not None
    return await identity.authenticate(result.tokens.access_token)


async def _confirmed_at(db: Database, user_id: object) -> object:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT confirmed_at FROM warden.totp_credentials WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    return row[0]


async def test_a_signed_in_enrolment_sends_the_notice(
    identity: Identity, db: Database, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user(display_name="Enid")
    principal = await _signed_in(identity, user.email)
    enrolment = await identity.begin_enrolment(principal=principal)  # type: ignore[arg-type]
    await identity.confirm_enrolment(current_code(enrolment.secret), principal=principal)  # type: ignore[arg-type]
    assert [(m.kind, m.to) for m in mail.sent] == [(MailKind.MFA_ENROLLED, user.email)]
    assert format_expiry(await _confirmed_at(db, user.id)) in mail.sent[0].text  # type: ignore[arg-type]
    assert "Enid" in mail.sent[0].text


async def test_an_enrolment_under_a_challenge_sends_the_notice(
    identity: Identity, mail: RecordingSender, make_user: UserFactory, db: Database
) -> None:
    await identity.policy.update(actor="t", require_mfa=True)
    user = await make_user()
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.challenge is not None
    enrolment = await identity.begin_enrolment(challenge=result.challenge.token)
    codes, pair = await identity.confirm_enrolment(
        current_code(enrolment.secret), challenge=result.challenge.token
    )
    assert pair is not None and codes
    assert [m.kind for m in mail.sent] == [MailKind.MFA_ENROLLED]


async def test_a_wrong_code_sends_nothing(
    identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    principal = await _signed_in(identity, user.email)
    await identity.begin_enrolment(principal=principal)  # type: ignore[arg-type]
    with pytest.raises(MfaError):
        await identity.confirm_enrolment("000000", principal=principal)  # type: ignore[arg-type]
    assert mail.sent == []


async def test_a_failed_notice_does_not_undo_the_enrolment(
    identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    user = await make_user()
    principal = await _signed_in(identity, user.email)
    enrolment = await identity.begin_enrolment(principal=principal)  # type: ignore[arg-type]
    mail.fail = True
    codes, _ = await identity.confirm_enrolment(
        current_code(enrolment.secret),
        principal=principal,  # type: ignore[arg-type]
    )
    assert codes
    assert await identity.mfa.has_confirmed_totp(user.id)


async def test_without_a_sender_the_notice_is_skipped(
    identity: Identity, mail: RecordingSender, make_user: UserFactory
) -> None:
    identity.mailer = Mailer(identity.config.mail, None)
    user = await make_user()
    principal = await _signed_in(identity, user.email)
    enrolment = await identity.begin_enrolment(principal=principal)  # type: ignore[arg-type]
    codes, _ = await identity.confirm_enrolment(
        current_code(enrolment.secret),
        principal=principal,  # type: ignore[arg-type]
    )
    assert codes and mail.sent == []
