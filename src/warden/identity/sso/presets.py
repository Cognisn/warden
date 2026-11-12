"""Provider presets: labels with setup guidance, and nothing else.

``sso.provider_preset`` tells an administrator's setup screen which guidance
to show. It never changes how sign-in behaves: every provider gets the same
discovery, validation and matching. A tripwire test fails if any sign-in
module reads the preset.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["PRESETS", "PresetGuide"]


@dataclass(frozen=True, slots=True)
class PresetGuide:
    preset: str
    label: str
    issuer_hint: str
    notes: str


PRESETS: tuple[PresetGuide, ...] = (
    PresetGuide(
        "entra",
        "Microsoft Entra ID",
        "https://login.microsoftonline.com/<tenant id>/v2.0",
        "Register a web application, add the callback URI as a redirect URI, and create a "
        "client secret. Configure the optional email claim; single sign-on needs a verified "
        "email (email_verified) on first sign-in.",
    ),
    PresetGuide(
        "google",
        "Google",
        "https://accounts.google.com",
        "Create an OAuth client of type web application and add the callback URI as an "
        "authorised redirect URI.",
    ),
    PresetGuide(
        "okta",
        "Okta",
        "https://<your domain>.okta.com/oauth2/default",
        "Create an OIDC web application with the authorisation code grant and add the callback "
        "URI as a sign-in redirect URI.",
    ),
    PresetGuide(
        "generic",
        "Other OpenID Connect provider",
        "The provider's issuer, exactly as its discovery document states it",
        "The provider must support the authorisation code flow with PKCE (S256) and publish a "
        "discovery document and JWKS over https.",
    ),
)
