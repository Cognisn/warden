"""Mail: the sender protocol the product implements, and warden's message templates.

warden never talks to a mail service. The product implements ``MailSender``
(over SES, SMTP, Microsoft 365 or anything else) and warden hands it one
rendered ``MailMessage`` at a time. A sender that cannot deliver raises;
warden reports that as ``MailDeliveryError`` without the sender's detail.

Templates use ``string.Template`` placeholders (``$link``), which can only
substitute a value, never reach into an object. A product replaces warden's
templates one at a time through ``mail.template_package``: a module whose
``INVITATION``, ``PASSWORD_RESET``, ``MFA_ENROLLED`` or
``PASSKEY_REGISTRATION`` attribute, if present, is a ``MailTemplate`` used
instead of warden's. Every template is
checked when the ``Mailer`` is built, so a bad one fails at start-up.

Every value has its control characters replaced before substitution, so
no value can add a header line to the subject, and values are HTML-escaped
in the HTML part. An expiry is rendered from the token row's own
``expires_at``, in UTC to the minute.
"""

from __future__ import annotations

import html
import importlib
import string
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from warden.config import MailConfig

__all__ = [
    "DEFAULT_TEMPLATES",
    "MailDeliveryError",
    "MailError",
    "MailKind",
    "MailMessage",
    "MailSender",
    "MailTemplate",
    "Mailer",
    "format_expiry",
]


class MailError(Exception):
    """Mail is misconfigured, or no sender is installed."""


class MailDeliveryError(MailError):
    """The product's sender could not deliver a message."""


class MailKind(StrEnum):
    INVITATION = "invitation"
    PASSWORD_RESET = "password_reset"  # noqa: S105 - a message kind, not a password
    MFA_ENROLLED = "mfa_enrolled"
    PASSKEY_REGISTRATION = "passkey_registration"


@dataclass(frozen=True, slots=True)
class MailTemplate:
    """A message's subject, plain-text body and optional HTML body."""

    subject: str
    text: str
    html: str | None = None


@dataclass(frozen=True, slots=True)
class MailMessage:
    """One rendered message, ready for the product's sender."""

    kind: MailKind
    to: str
    subject: str
    text: str
    html: str | None
    from_address: str | None
    from_name: str | None
    reply_to: str | None


class MailSender(Protocol):
    """Implemented by the product. Raise to report that a message was not delivered."""

    async def send(self, message: MailMessage) -> None: ...


# The placeholders each kind of message may use.
PLACEHOLDERS: Mapping[MailKind, frozenset[str]] = {
    MailKind.INVITATION: frozenset({"email", "display_name", "link", "expires_at"}),
    MailKind.PASSWORD_RESET: frozenset({"email", "display_name", "link", "expires_at"}),
    MailKind.MFA_ENROLLED: frozenset({"email", "display_name", "enrolled_at"}),
    MailKind.PASSKEY_REGISTRATION: frozenset({"email", "display_name", "link", "expires_at"}),
}

DEFAULT_TEMPLATES: Mapping[MailKind, MailTemplate] = {
    MailKind.INVITATION: MailTemplate(
        subject="You have been invited",
        text=(
            "Hello $display_name,\n\n"
            "You have been invited to sign in as $email. Accept the invitation here:\n\n"
            "$link\n\n"
            "The link can be used once and expires on $expires_at.\n\n"
            "If you were not expecting this invitation, you can ignore this message.\n"
        ),
        html=(
            "<p>Hello $display_name,</p>"
            "<p>You have been invited to sign in as $email.</p>"
            '<p><a href="$link">Accept the invitation</a></p>'
            "<p>The link can be used once and expires on $expires_at.</p>"
            "<p>If you were not expecting this invitation, you can ignore this message.</p>"
        ),
    ),
    MailKind.PASSWORD_RESET: MailTemplate(
        subject="Reset your password",
        text=(
            "Hello $display_name,\n\n"
            "A password reset was requested for $email. Choose a new password here:\n\n"
            "$link\n\n"
            "The link can be used once and expires on $expires_at. Resetting your password"
            " signs you out everywhere.\n\n"
            "If you did not ask for this, you can ignore this message; your password is"
            " unchanged.\n"
        ),
        html=(
            "<p>Hello $display_name,</p>"
            "<p>A password reset was requested for $email.</p>"
            '<p><a href="$link">Choose a new password</a></p>'
            "<p>The link can be used once and expires on $expires_at. Resetting your password"
            " signs you out everywhere.</p>"
            "<p>If you did not ask for this, you can ignore this message; your password is"
            " unchanged.</p>"
        ),
    ),
    MailKind.MFA_ENROLLED: MailTemplate(
        subject="Two-step verification was set up",
        text=(
            "Hello $display_name,\n\n"
            "Two-step verification was set up on $email on $enrolled_at.\n\n"
            "If this was not you, contact your administrator straight away.\n"
        ),
        html=(
            "<p>Hello $display_name,</p>"
            "<p>Two-step verification was set up on $email on $enrolled_at.</p>"
            "<p>If this was not you, contact your administrator straight away.</p>"
        ),
    ),
    MailKind.PASSKEY_REGISTRATION: MailTemplate(
        subject="Set up your passkey",
        text=(
            "Hello $display_name,\n\n"
            "Your administrator has sent you a link to set up a passkey for $email."
            " Register it here:\n\n"
            "$link\n\n"
            "The link can be used once and expires on $expires_at. It does not sign you in;"
            " sign in with the passkey afterwards.\n\n"
            "If you were not expecting this, contact your administrator straight away.\n"
        ),
        html=(
            "<p>Hello $display_name,</p>"
            "<p>Your administrator has sent you a link to set up a passkey for $email.</p>"
            '<p><a href="$link">Register your passkey</a></p>'
            "<p>The link can be used once and expires on $expires_at. It does not sign you in;"
            " sign in with the passkey afterwards.</p>"
            "<p>If you were not expecting this, contact your administrator straight away.</p>"
        ),
    ),
}

# Attribute names a product's template package may define, one per kind.
_ATTRIBUTES: Mapping[MailKind, str] = {kind: kind.value.upper() for kind in MailKind}


def format_expiry(moment: datetime) -> str:
    """A time for a message: UTC, to the minute, such as ``4 November 2026 at 03:07 UTC``."""
    utc = moment.astimezone(UTC)
    return f"{utc.day} {utc:%B %Y} at {utc:%H:%M} UTC"


def _neutralise(value: str) -> str:
    # C0 controls, DEL, C1 controls (NEL among them) and the Unicode line and
    # paragraph separators.
    return "".join(" " if _is_control(ord(ch)) else ch for ch in value)


def _is_control(code: int) -> bool:
    return code < 0x20 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029)


def _check(kind: MailKind, template: MailTemplate) -> None:
    name = _ATTRIBUTES[kind]
    allowed = PLACEHOLDERS[kind]
    for part in (template.subject, template.text, template.html):
        if part is None:
            continue
        if not isinstance(part, str):
            raise MailError(f"mail template {name} must hold text")
        parsed = string.Template(part)
        if not parsed.is_valid():
            raise MailError(f"mail template {name} has a malformed placeholder")
        unknown = set(parsed.get_identifiers()) - allowed
        if unknown:
            names = ", ".join("$" + p for p in sorted(allowed))
            raise MailError(f"mail template {name} may use only {names}")


def _load(package: str | None) -> dict[MailKind, MailTemplate]:
    templates = dict(DEFAULT_TEMPLATES)
    if package is not None:
        try:
            module = importlib.import_module(package)
        except ImportError:
            raise MailError("mail.template_package cannot be imported") from None
        for kind, attribute in _ATTRIBUTES.items():
            override = getattr(module, attribute, None)
            if override is None:
                continue
            if not isinstance(override, MailTemplate):
                raise MailError(f"mail template {attribute} must be a warden MailTemplate")
            templates[kind] = override
    for kind, template in templates.items():
        _check(kind, template)
    return templates


class Mailer:
    """Renders warden's messages and hands them to the product's sender."""

    def __init__(self, config: MailConfig, sender: MailSender | None) -> None:
        self._config = config
        self._sender = sender
        self._templates = _load(config.template_package)

    @property
    def configured(self) -> bool:
        """Whether a sender is installed."""
        return self._sender is not None

    def render(self, kind: MailKind, *, email: str, **values: object) -> MailMessage:
        """Render one message to ``email``. Datetime values are formatted with ``format_expiry``."""
        texts: dict[str, str] = {"email": _neutralise(email)}
        for key, value in values.items():
            if isinstance(value, datetime):
                texts[key] = format_expiry(value)
            else:
                texts[key] = _neutralise("" if value is None else str(value))
        if not texts.get("display_name"):
            texts["display_name"] = texts["email"]
        template = self._templates[kind]
        subject = string.Template(template.subject).safe_substitute(texts)
        if self._config.subject_prefix:
            subject = f"{self._config.subject_prefix} {subject}"
        escaped = {key: html.escape(value) for key, value in texts.items()}
        return MailMessage(
            kind=kind,
            to=email,
            subject=_neutralise(subject),
            text=string.Template(template.text).safe_substitute(texts),
            html=None
            if template.html is None
            else string.Template(template.html).safe_substitute(escaped),
            from_address=self._config.from_address,
            from_name=self._config.from_name,
            reply_to=self._config.reply_to,
        )

    async def deliver(self, message: MailMessage) -> None:
        """Hand a rendered message to the sender; ``MailDeliveryError`` if it fails."""
        if self._sender is None:
            raise MailError("no mail sender is configured; pass mail_sender to Identity")
        try:
            await self._sender.send(message)
        except Exception:
            raise MailDeliveryError(f"the {message.kind.value} message was not delivered") from None

    async def send(self, kind: MailKind, *, email: str, **values: object) -> MailMessage:
        """Render and deliver one message; returns what was sent."""
        message = self.render(kind, email=email, **values)
        await self.deliver(message)
        return message
