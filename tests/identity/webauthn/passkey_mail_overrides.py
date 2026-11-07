"""A product's mail template package overriding the passkey registration message."""

from warden.identity.mail import MailTemplate

PASSKEY_REGISTRATION = MailTemplate(
    subject="Set up your Example passkey",
    text="Hello $display_name. Register a passkey for $email at $link before $expires_at.",
)
