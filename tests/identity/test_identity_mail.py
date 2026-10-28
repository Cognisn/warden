"""Mail: the sender protocol, warden's templates and the product's overrides.

No mail service is ever called: a recording sender stands in for the product's.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone

import pytest

from warden.config import MailConfig
from warden.identity.mail import (
    MailDeliveryError,
    Mailer,
    MailError,
    MailKind,
    MailMessage,
    MailTemplate,
    format_expiry,
)


class RecordingSender:
    def __init__(self) -> None:
        self.sent: list[MailMessage] = []

    async def send(self, message: MailMessage) -> None:
        self.sent.append(message)


class FailingSender:
    async def send(self, message: MailMessage) -> None:
        raise ConnectionError("smtp.example.com refused the connection")


EXPIRES = datetime(2026, 11, 4, 3, 7, 59, tzinfo=UTC)


def _values(**extra: object) -> dict[str, object]:
    return {
        "email": "invitee@example.com",
        "display_name": "Ivy Invitee",
        "link": "https://app.example.com/accept?t=abc",
        "expires_at": EXPIRES,
        **extra,
    }


@pytest.fixture
def package() -> Iterator[str]:
    """Install a throwaway template package under a unique name."""
    name = "warden_test_templates"
    module = types.ModuleType(name)
    sys.modules[name] = module
    try:
        yield name
    finally:
        del sys.modules[name]


def test_format_expiry_is_utc_to_the_minute() -> None:
    aest = timezone(timedelta(hours=10))
    assert format_expiry(EXPIRES) == "4 November 2026 at 03:07 UTC"
    assert format_expiry(EXPIRES.astimezone(aest)) == "4 November 2026 at 03:07 UTC"


def test_default_invitation() -> None:
    message = Mailer(MailConfig(from_address="noreply@example.com"), None).render(
        MailKind.INVITATION, **_values()
    )
    assert message.kind is MailKind.INVITATION
    assert message.to == "invitee@example.com"
    assert message.from_address == "noreply@example.com"
    assert "https://app.example.com/accept?t=abc" in message.text
    assert "4 November 2026 at 03:07 UTC" in message.text
    assert message.html is not None and "4 November 2026 at 03:07 UTC" in message.html


def test_subject_prefix() -> None:
    mailer = Mailer(MailConfig(subject_prefix="[Example]"), None)
    message = mailer.render(MailKind.PASSWORD_RESET, **_values())
    assert message.subject.startswith("[Example] ")


@pytest.mark.parametrize("kind", list(MailKind))
def test_every_kind_has_a_default_template(kind: MailKind) -> None:
    message = Mailer(MailConfig(), None).render(kind, **_values(enrolled_at=EXPIRES))
    assert message.subject and message.text


def test_a_product_template_replaces_warden_s_template_by_template() -> None:
    mailer = Mailer(MailConfig(template_package="mail_overrides"), None)
    invitation = mailer.render(MailKind.INVITATION, **_values())
    assert invitation.subject == "Join the Example workspace"
    assert invitation.text == (
        "Welcome Ivy Invitee. Accept at https://app.example.com/accept?t=abc"
        " before 4 November 2026 at 03:07 UTC."
    )
    assert invitation.html is None
    # Templates the package does not define stay warden's.
    reset = mailer.render(MailKind.PASSWORD_RESET, **_values())
    assert (
        reset.subject
        == Mailer(MailConfig(), None).render(MailKind.PASSWORD_RESET, **_values()).subject
    )


def test_a_missing_template_package_fails_at_start_up() -> None:
    with pytest.raises(MailError, match=r"mail\.template_package"):
        Mailer(MailConfig(template_package="no_such_package_anywhere"), None)


def test_a_template_that_is_not_a_mail_template_fails_at_start_up(package: str) -> None:
    sys.modules[package].PASSWORD_RESET = "Reset: $link"  # type: ignore[attr-defined]
    with pytest.raises(MailError, match="PASSWORD_RESET"):
        Mailer(MailConfig(template_package=package), None)


@pytest.mark.parametrize(
    "template",
    [
        MailTemplate(subject="Hi", text="Your token is $token"),
        MailTemplate(subject="Hi $password", text="x"),
        MailTemplate(subject="Hi", text="x", html="<p>${config}</p>"),
        MailTemplate(subject="Hi", text="Broken $"),
    ],
)
def test_a_template_may_use_only_its_own_placeholders(package: str, template: MailTemplate) -> None:
    sys.modules[package].INVITATION = template  # type: ignore[attr-defined]
    with pytest.raises(MailError, match="INVITATION"):
        Mailer(MailConfig(template_package=package), None)


def test_values_cannot_break_out_of_the_subject_line(package: str) -> None:
    sys.modules[package].INVITATION = MailTemplate(  # type: ignore[attr-defined]
        subject="Invitation for $display_name", text="$link"
    )
    message = Mailer(MailConfig(template_package=package), None).render(
        MailKind.INVITATION, **_values(display_name="Eve\r\nBcc: victim@example.org")
    )
    assert "\r" not in message.subject and "\n" not in message.subject
    assert "\r" not in message.text


def test_html_values_are_escaped(package: str) -> None:
    sys.modules[package].INVITATION = MailTemplate(  # type: ignore[attr-defined]
        subject="Hi", text="$display_name", html="<p>$display_name</p>"
    )
    message = Mailer(MailConfig(template_package=package), None).render(
        MailKind.INVITATION, **_values(display_name="<script>x</script>")
    )
    assert message.text == "<script>x</script>"
    assert message.html == "<p>&lt;script&gt;x&lt;/script&gt;</p>"


async def test_send_hands_the_message_to_the_product_s_sender() -> None:
    sender = RecordingSender()
    await Mailer(MailConfig(), sender).send(MailKind.INVITATION, **_values())
    assert [m.to for m in sender.sent] == ["invitee@example.com"]


async def test_send_without_a_sender_is_refused() -> None:
    with pytest.raises(MailError, match="no mail sender"):
        await Mailer(MailConfig(), None).send(MailKind.INVITATION, **_values())


async def test_a_delivery_failure_is_reported_without_the_sender_s_detail() -> None:
    with pytest.raises(MailDeliveryError) as raised:
        await Mailer(MailConfig(), FailingSender()).send(MailKind.INVITATION, **_values())
    assert "smtp.example.com" not in str(raised.value)
