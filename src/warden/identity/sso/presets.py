"""Provider presets: setup guidance for an administrator, and nothing else.

``sso.provider_preset`` tells an administrator's setup screen which guidance
to show. It never changes how sign-in behaves: every provider gets the same
discovery, validation and matching. A tripwire test fails if any sign-in
module reads the preset.

Each preset carries ordered steps (ruling CS15): what to do in that
provider's admin console, with the instance's own values filled in by
``setup_guide`` and the three values to copy back into warden. Products
display the steps and never write their own. The sources each step was
checked against are listed, with the date, in ``docs/guide/sso-providers.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from warden.identity.sso.settings import SsoSettings

__all__ = [
    "COPY_BACK_SETTINGS",
    "PLACEHOLDERS",
    "PRESETS",
    "CopyBack",
    "GuideStep",
    "PresetGuide",
    "SetupGuide",
    "SetupStep",
    "setup_guide",
]

PLACEHOLDERS: tuple[str, ...] = ("callback_uri", "scopes", "issuer", "display_name")
"""The values ``setup_guide`` fills into a step's text, as ``{name}``."""

COPY_BACK_SETTINGS: tuple[str, ...] = ("issuer_url", "client_id", "client_secret")
"""The warden settings an administrator pastes a provider value into."""

_GENERIC = "generic"
_TOKEN = re.compile(r"\{(\w+)\}")


@dataclass(frozen=True, slots=True)
class CopyBack:
    """A value to copy from the provider's console into a warden setting."""

    setting: str
    """One of ``COPY_BACK_SETTINGS``."""
    label: str
    """What the value is, in plain words."""


@dataclass(frozen=True, slots=True)
class GuideStep:
    """One step as written: ``text`` holds ``{placeholder}`` tokens."""

    title: str
    text: str
    placeholders: tuple[str, ...] = ()
    copy_back: tuple[CopyBack, ...] = ()


@dataclass(frozen=True, slots=True)
class PresetGuide:
    preset: str
    label: str
    issuer_hint: str
    notes: str
    steps: tuple[GuideStep, ...] = field(default=())


@dataclass(frozen=True, slots=True)
class SetupStep:
    """A step with its placeholders filled in."""

    number: int
    title: str
    text: str
    values: dict[str, str]
    """The placeholders this step uses, with the values filled in, so a screen
    can offer a copy button for each."""
    copy_back: tuple[CopyBack, ...]


@dataclass(frozen=True, slots=True)
class SetupGuide:
    preset: str
    """The preset the steps are for: ``generic`` when the one asked for is unknown."""
    label: str
    issuer_hint: str
    notes: str
    steps: tuple[SetupStep, ...]


def _step(title: str, text: str, *copy_back: CopyBack) -> GuideStep:
    return GuideStep(
        title=title,
        text=text,
        placeholders=tuple(dict.fromkeys(_TOKEN.findall(text))),
        copy_back=copy_back,
    )


_ISSUER = CopyBack("issuer_url", "the issuer URL")
_CLIENT_ID = CopyBack("client_id", "the client ID")
_SECRET = CopyBack("client_secret", "the client secret")

_ENTRA = (
    _step(
        "Register the application",
        "Sign in to the Microsoft Entra admin center as at least an Application Developer. "
        "Go to Entra ID, App registrations, New registration. Name the application "
        "{display_name}. Under Supported account types choose Single tenant only, so that only "
        "people in your own directory can sign in. Leave the redirect URI blank for now and "
        "select Register.",
    ),
    _step(
        "Add the redirect URI",
        "In the app registration open Authentication, select Add Redirect URI, choose the Web "
        "platform and enter exactly {callback_uri}. Select Configure. Leave the implicit grant "
        "and hybrid flow options unticked: warden uses the authorisation code flow, and it "
        "sends a PKCE S256 challenge with every sign-in, so nothing else needs switching on.",
    ),
    _step(
        "Create a client secret",
        "Open Certificates and secrets, then Client secrets, then New client secret. Add a "
        "description, choose an expiry (Microsoft recommends under 12 months and allows at most "
        "24) and select Add. Copy the secret's Value now, because Entra never shows it again, "
        "and keep a reminder to replace it before it expires. Paste it into warden as the client "
        "secret.",
        _SECRET,
    ),
    _step(
        "Find the client ID and the issuer",
        "On the application's Overview page copy the Application (client) ID and the Directory "
        "(tenant) ID. The issuer is https://login.microsoftonline.com/<tenant id>/v2.0 with the "
        "Directory (tenant) ID in place of the placeholder; it is {issuer} until you set it. "
        "Use the tenant ID, never common or organizations: those endpoints issue tokens with a "
        "different issuer, and warden requires an exact match. To check, open Endpoints, open "
        "the OpenID Connect metadata document and confirm its issuer value is the same.",
        _CLIENT_ID,
        _ISSUER,
    ),
    _step(
        "Request the email claim",
        "warden asks for the scopes {scopes}. For a member of your own directory the email "
        "claim is not in the ID token by default, so open Token configuration, select Add "
        "optional claim, choose the ID token type, tick email and select Add. Accept the prompt "
        "to add the Microsoft Graph email permission if one appears. Every user who will sign in "
        "needs an email address on their account, and it must be the address warden holds for "
        "them.",
    ),
    _step(
        "Check the verified email",
        "warden refuses a first sign-in unless the ID token says email_verified is true. "
        "Microsoft's published ID token and optional claim lists do not include an "
        "email_verified claim; the nearest is the optional xms_edov claim, which reports "
        "whether the owner of the email domain has been verified. If every Entra sign-in is "
        "refused and the audit trail shows the reason email_unverified, the tenant's tokens do "
        "not carry the claim, and this provider cannot satisfy that rule yet. Run the "
        "configuration test and one real sign-in before relying on it.",
    ),
    _step(
        "Limit who can sign in",
        "Open Entra ID, Enterprise apps, select the application, then Properties, and set "
        "Assignment required to Yes. Then open Users and groups, select Add user/group and "
        "assign the people or groups who may sign in (group assignment needs Entra ID P1 or "
        "P2). Because assignment is required, an administrator must grant tenant-wide admin "
        "consent under API permissions first. warden also only signs in people an administrator "
        "has already created or invited, and its allowed email domains setting narrows the list "
        "further.",
    ),
    _step(
        "Save and test in warden",
        "In {display_name} enter the issuer URL and client ID, store the client secret, set the "
        "provider to Microsoft Entra ID and save. Then run the configuration test. It checks "
        "discovery, the signing keys and the secret, and signs nobody in.",
    ),
)

_GOOGLE = (
    _step(
        "Choose the project and audience",
        "Open the Google Cloud console and select or create a project for {display_name}. Open "
        "Google Auth Platform and complete the setup. Under Audience choose Internal if your "
        "organisation uses Google Workspace, which limits sign-in to members of that "
        "organisation, or External for any Google Account. Under Branding enter the "
        "application name.",
    ),
    _step(
        "Set the scopes",
        "warden asks for the scopes {scopes}. Under Data Access add the openid, email and "
        "profile scopes if the console lists them for approval.",
    ),
    _step(
        "Create the OAuth client",
        "Open Google Auth Platform, Clients, and select Create client. Choose the Web "
        "application type and name it {display_name}. Under Authorised redirect URIs add "
        "exactly {callback_uri}. Google requires https (localhost excepted) and refuses "
        "wildcards and fragments. Select Create. warden sends a PKCE S256 challenge itself, so "
        "there is no PKCE setting to change.",
    ),
    _step(
        "Copy the client ID and secret",
        "Copy the Client ID, and copy the Client secret straight away: Google shows the full "
        "secret only when the client is created and afterwards shows its last four characters. "
        "If it is lost, add a new secret to the client. Paste the secret into warden as the "
        "client secret.",
        _CLIENT_ID,
        _SECRET,
    ),
    _step(
        "Enter the issuer",
        "The issuer is {issuer} and its discovery document is at "
        "https://accounts.google.com/.well-known/openid-configuration. Enter the issuer exactly "
        "as shown, with no trailing slash.",
        _ISSUER,
    ),
    _step(
        "Check the email claims",
        "With the email scope Google puts both email and email_verified in the ID token, and "
        "warden needs both: it refuses a first sign-in unless email_verified is true. For "
        "accounts in a Google Workspace organisation Google also adds an hd claim with the "
        "domain; warden does not read it.",
    ),
    _step(
        "Limit who can sign in",
        "Google does not assign individual people to an OAuth client. Choose the Internal "
        "audience to keep everyone outside your Workspace organisation out, and use warden's "
        "allowed email domains setting to name the domains that may sign in. warden also only "
        "signs in people an administrator has already created or invited.",
    ),
    _step(
        "Save and test in warden",
        "In {display_name} enter the issuer URL and client ID, store the client secret, set the "
        "provider to Google and save. Then run the configuration test. It checks discovery, the "
        "signing keys and the secret, and signs nobody in.",
    ),
)

_OKTA = (
    _step(
        "Create the application integration",
        "In the Okta Admin Console go to Applications, Applications, and select Create App "
        "Integration. Choose OIDC - OpenID Connect as the sign-in method and Web Application as "
        "the application type, then select Next. Name the integration {display_name}.",
    ),
    _step(
        "Choose the grant and client authentication",
        "Leave the grant type as Authorization Code: for a web application it is the default "
        "and cannot be changed. Keep client authentication on a client secret. warden sends a "
        "PKCE S256 challenge with every sign-in, which Okta accepts; if the integration offers "
        "Require PKCE you may leave it on.",
    ),
    _step(
        "Add the sign-in redirect URI",
        "Under Sign-in redirect URIs enter exactly {callback_uri}. Okta needs an absolute URI "
        "and refuses sign-in to one that is not registered. Do not use a wildcard.",
    ),
    _step(
        "Limit who can sign in",
        "Under Assignments the default lets everyone in the Okta organisation use the "
        "integration. To limit it, choose Limit access to selected groups and name the groups, "
        "or choose Skip group assignment for now and assign people on the Assignments tab "
        "later. warden also only signs in people an administrator has already created or "
        "invited, and its allowed email domains setting narrows the list further.",
    ),
    _step(
        "Save and copy the credentials",
        "Select Save. On the General tab, under Client Credentials, copy the Client ID. Copy the "
        "Client secret from the same panel and paste it into warden as the client secret.",
        _CLIENT_ID,
        _SECRET,
    ),
    _step(
        "Find the issuer",
        "The issuer depends on the authorisation server. The Okta organisation authorisation "
        "server's issuer is your Okta domain, https://<your domain>.okta.com. A custom "
        "authorisation server's issuer is https://<your domain>.okta.com/oauth2/<server id>, "
        "and the one named default ends in /oauth2/default; custom servers need the API Access "
        "Management add-on in production. Copy the issuer from the authorisation server's "
        "settings or from its discovery document and enter it exactly. It is {issuer} until you "
        "set it.",
        _ISSUER,
    ),
    _step(
        "Check the email claims",
        "warden asks for the scopes {scopes}. With the email scope Okta puts email and "
        "email_verified in the ID token. email_verified is true only when the user's primary "
        "email has been verified, and warden refuses a first sign-in when it is false, so "
        "make sure each user has completed activation.",
    ),
    _step(
        "Save and test in warden",
        "In {display_name} enter the issuer URL and client ID, store the client secret, set the "
        "provider to Okta and save. Then run the configuration test. It checks discovery, the "
        "signing keys and the secret, and signs nobody in.",
    ),
)

_OIDC = (
    _step(
        "Check the provider can work with warden",
        "The provider must support the authorisation code flow with PKCE using the S256 method, "
        "publish an OpenID Connect discovery document (/.well-known/openid-configuration) and "
        "its signing keys over https, and sign ID tokens with RS256, ES256 or PS256. It must "
        "also put email and email_verified in the ID token for the scopes {scopes}. warden "
        "refuses a first sign-in unless email_verified is true.",
    ),
    _step(
        "Create a confidential web client",
        "In the provider's admin console register a new client for {display_name}. Choose the "
        "confidential or web application type that authenticates with a client secret, and the "
        "authorisation code grant. Leave implicit and password grants off.",
    ),
    _step(
        "Add the redirect URI",
        "Register exactly {callback_uri} as an allowed redirect URI, character for character. "
        "Do not use a wildcard.",
    ),
    _step(
        "Allow the scopes",
        "Make sure the client may request the scopes {scopes}. warden always sends a PKCE S256 "
        "challenge, a state value and a nonce.",
    ),
    _step(
        "Find the issuer",
        "Open the provider's discovery document and copy its issuer value. warden requires the "
        "ID token's issuer to equal it exactly, including any trailing slash, and the issuer "
        "must use https. It is {issuer} until you set it.",
        _ISSUER,
    ),
    _step(
        "Copy the client ID and secret",
        "Copy the client ID and the client secret the provider generated. Paste the secret into "
        "warden as the client secret. The provider must offer client_secret_basic or "
        "client_secret_post for the token endpoint.",
        _CLIENT_ID,
        _SECRET,
    ),
    _step(
        "Limit who can sign in",
        "Use the provider's own assignment or access rules to name who may use the client, and "
        "warden's allowed email domains setting to name the domains that may sign in. warden "
        "also only signs in people an administrator has already created or invited.",
    ),
    _step(
        "Save and test in warden",
        "In {display_name} enter the issuer URL and client ID, store the client secret, set the "
        "provider to Other OpenID Connect provider and save. Then run the configuration test. "
        "It checks discovery, the signing keys and the secret, and signs nobody in.",
    ),
)

PRESETS: tuple[PresetGuide, ...] = (
    PresetGuide(
        "entra",
        "Microsoft Entra ID",
        "https://login.microsoftonline.com/<tenant id>/v2.0",
        "Register a web application, add the callback URI as a redirect URI, and create a "
        "client secret. Configure the optional email claim; single sign-on needs a verified "
        "email (email_verified) on first sign-in.",
        _ENTRA,
    ),
    PresetGuide(
        "google",
        "Google",
        "https://accounts.google.com",
        "Create an OAuth client of type web application and add the callback URI as an "
        "authorised redirect URI.",
        _GOOGLE,
    ),
    PresetGuide(
        "okta",
        "Okta",
        "https://<your domain>.okta.com/oauth2/default",
        "Create an OIDC web application with the authorisation code grant and add the callback "
        "URI as a sign-in redirect URI.",
        _OKTA,
    ),
    PresetGuide(
        "generic",
        "Other OpenID Connect provider",
        "The provider's issuer, exactly as its discovery document states it",
        "The provider must support the authorisation code flow with PKCE (S256) and publish a "
        "discovery document and JWKS over https.",
        _OIDC,
    ),
)


def setup_guide(
    preset: str, *, settings: SsoSettings, callback_uri: str, display_name: str
) -> SetupGuide:
    """The steps for ``preset`` with the instance's values filled in.

    ``callback_uri`` is the product's redirect URI (``http.sso_callback_url``)
    and ``display_name`` what the product calls this instance. The issuer is
    the one saved in ``settings``, or the preset's hint until one is saved. An
    unknown preset gets the generic guide.
    """
    by_name = {p.preset: p for p in PRESETS}
    entry = by_name.get(preset) or by_name[_GENERIC]
    values = {
        "callback_uri": callback_uri,
        "scopes": " ".join(settings.scopes),
        "issuer": settings.issuer_url or entry.issuer_hint,
        "display_name": display_name,
    }
    steps = tuple(
        SetupStep(
            number=number,
            title=step.title,
            text=_TOKEN.sub(lambda m: values[m.group(1)], step.text),
            values={name: values[name] for name in step.placeholders},
            copy_back=step.copy_back,
        )
        for number, step in enumerate(entry.steps, start=1)
    )
    return SetupGuide(
        preset=entry.preset,
        label=entry.label,
        issuer_hint=entry.issuer_hint,
        notes=entry.notes,
        steps=steps,
    )
