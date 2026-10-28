"""A product's mail template package, for the mail tests (``mail.template_package``)."""

from warden.identity.mail import MailTemplate

INVITATION = MailTemplate(
    subject="Join the Example workspace",
    text="Welcome $display_name. Accept at $link before $expires_at.",
)
