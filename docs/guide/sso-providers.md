# Single sign-on setup guides

warden carries the instructions an administrator follows in an identity provider's admin console, so they are written and corrected once and every product shows the same ones (ruling CS15). A product never writes its own. This page is the prose form of the data in `warden.identity.sso.presets`; a test fails if the two drift apart.

There is one guide for each provider preset: Microsoft Entra ID, Google, Okta and any other OpenID Connect provider. Each is a numbered list of steps. A step has a title, plain text, and where the administrator copies a value back into warden, which setting it goes into (`issuer_url`, `client_id` or `client_secret`).

In the text below, `<callback URI>`, `<scopes>`, `<issuer URL>` and `<product name>` stand for values warden fills in when it serves the guide: the product's own callback URI (`http.sso_callback_url`), the configured scopes, the saved issuer URL (or the preset's hint until one is saved) and the product's name (`identity.totp_issuer`, else the host of `http.public_base_url`). The guides hold no real tenant, client or domain identifiers.

Presets are guidance only. Choosing one changes nothing about how sign-in works, and no sign-in code reads it.

## Getting the steps

- `GET <admin>/sso/settings` carries `setup_guide`, the steps for the current provider preset.
- `GET <admin>/sso/setup-guide` answers the same for the current preset, or for `?preset=entra|google|okta|generic`. An unknown preset gets the generic guide. Both sit behind the product's `authorise` dependency and are never cached.
- In Python, `warden.identity.sso.presets.setup_guide(preset, settings=..., callback_uri=..., display_name=...)` returns the same steps with the placeholders filled in.

A step answers as `{number, title, text, values, copy_back}`: `text` is ready to show, `values` holds the filled placeholders the step uses (so a screen can offer a copy button for each), and `copy_back` lists `{setting, label}` for each value to paste into warden.

## What every guide shares

warden needs the same from every provider:

- the authorisation code flow, with a PKCE S256 challenge, a state value and a nonce, which warden sends itself;
- a discovery document and signing keys over https, and an issuer that exactly equals the one warden holds;
- ID tokens signed with RS256, ES256 or PS256;
- `email` and `email_verified` in the ID token. warden refuses the person unless `email_verified` is exactly true, the address matches an existing or invited user, and (when set) its domain is in the allowed email domains.

Microsoft Entra ID is the one exception to the `email_verified` rule, because it publishes no such claim. When the configured issuer is Entra ID's v2.0 issuer for a tenant (`https://login.microsoftonline.com/<tenant id>/v2.0`, matched in full on the issuer URL, never by the chosen preset), an `xms_edov` claim that is exactly true, together with a non-empty `email` claim, counts as a verified email. From any other issuer `xms_edov` is ignored. The allowed email domains apply either way.

## Microsoft Entra ID

Single tenant is the supported shape: it gives an issuer that warden can match exactly.

Issuer hint: https://login.microsoftonline.com/<tenant id>/v2.0

**Checked on 2026-11-23** against the sources listed at the end of this section. Steps 5 and 6 rechecked on 2026-11-24 against the optional claims reference, for `xms_edov`.

1. Register the application

   Sign in to the Microsoft Entra admin center as at least an Application Developer. Go to Entra ID, App registrations, New registration. Name the application <product name>. Under Supported account types choose Single tenant only, so that only people in your own directory can sign in. Leave the redirect URI blank for now and select Register.

2. Add the redirect URI

   In the app registration open Authentication, select Add Redirect URI, choose the Web platform and enter exactly <callback URI>. Select Configure. Leave the implicit grant and hybrid flow options unticked: warden uses the authorisation code flow, and it sends a PKCE S256 challenge with every sign-in, so nothing else needs switching on.

3. Create a client secret

   Open Certificates and secrets, then Client secrets, then New client secret. Add a description, choose an expiry (Microsoft recommends under 12 months and allows at most 24) and select Add. Copy the secret's Value now, because Entra never shows it again, and keep a reminder to replace it before it expires. Paste it into warden as the client secret.

   Copy back: the client secret, into warden's `client_secret`.

4. Find the client ID and the issuer

   On the application's Overview page copy the Application (client) ID and the Directory (tenant) ID. The issuer is https://login.microsoftonline.com/<tenant id>/v2.0 with the Directory (tenant) ID in place of the placeholder; it is <issuer URL> until you set it. Use the tenant ID, never common or organizations: those endpoints issue tokens with a different issuer, and warden requires an exact match. To check, open Endpoints, open the OpenID Connect metadata document and confirm its issuer value is the same.

   Copy back: the client ID, into warden's `client_id`.

   Copy back: the issuer URL, into warden's `issuer_url`.

5. Request the email and xms_edov claims

   warden asks for the scopes <scopes>. Neither the email claim nor the xms_edov claim is in the ID token by default, so open Token configuration, select Add optional claim, choose the ID token type, tick both email and xms_edov and select Add. Accept the prompt to add the Microsoft Graph email permission if one appears. Every user who will sign in needs an email address on their account, and it must be the address warden holds for them.

6. Check the verified email

   Entra puts no email_verified claim in its ID tokens. When the issuer is Entra's v2.0 issuer for your tenant, warden accepts instead the optional xms_edov claim with the value true, together with the email claim: xms_edov is true when the owner of the email's domain has been verified. Microsoft counts an address as domain verified when it belongs to your tenant and a tenant administrator has verified its domain, so add and verify each email domain your users sign in with as a custom domain name in Entra ID. warden refuses a sign-in whose ID token carries neither email_verified true nor xms_edov true with an email, and records the reason email_unverified in the audit trail. Run the configuration test and one real sign-in before relying on it.

7. Limit who can sign in

   Open Entra ID, Enterprise apps, select the application, then Properties, and set Assignment required to Yes. Then open Users and groups, select Add user/group and assign the people or groups who may sign in (group assignment needs Entra ID P1 or P2). Because assignment is required, an administrator must grant tenant-wide admin consent under API permissions first. warden also only signs in people an administrator has already created or invited, and its allowed email domains setting narrows the list further.

8. Save and test in warden

   In <product name> enter the issuer URL and client ID, store the client secret, set the provider to Microsoft Entra ID and save. Then run the configuration test. It checks discovery, the signing keys and the secret, and signs nobody in.

**Sources**

- Register an application in Microsoft Entra ID: <https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app>
- How to add a redirect URI to your application: <https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri>
- Add and manage app credentials in Microsoft Entra ID: <https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials>
- OpenID Connect (OIDC) on the Microsoft identity platform: <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc>
- Microsoft identity platform and OAuth 2.0 authorization code flow: <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow>
- ID token claims reference: <https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference>
- Optional claims reference: <https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference> (checked again on 2026-11-24: `xms_edov` is a Boolean saying whether the user's email domain owner has been verified; an email is domain verified when it belongs to the tenant where the user account resides and the tenant administrator has verified the domain, or comes from a Microsoft account, a Google account or the one-time passcode flow; Facebook and SAML/WS-Fed accounts have no verified domain; the claim is returned only when the `email` claim is present)
- Configure and manage optional claims in ID tokens, access tokens, and SAML tokens: <https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims>
- Scopes and permissions in the Microsoft identity platform: <https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc>
- Manage access to apps (requiring user assignment): <https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/what-is-access-management>
- Manage users and groups assignment to an application: <https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal>

## Google

Google has no per-person assignment for an OAuth client, so limiting who can sign in uses the Internal audience and warden's allowed email domains.

Issuer hint: https://accounts.google.com

**Checked on 2026-11-23** against the sources listed at the end of this section.

1. Choose the project and audience

   Open the Google Cloud console and select or create a project for <product name>. Open Google Auth Platform and complete the setup. Under Audience choose Internal if your organisation uses Google Workspace, which limits sign-in to members of that organisation, or External for any Google Account. Under Branding enter the application name.

2. Set the scopes

   warden asks for the scopes <scopes>. Under Data Access add the openid, email and profile scopes if the console lists them for approval.

3. Create the OAuth client

   Open Google Auth Platform, Clients, and select Create client. Choose the Web application type and name it <product name>. Under Authorised redirect URIs add exactly <callback URI>. Google requires https (localhost excepted) and refuses wildcards and fragments. Select Create. warden sends a PKCE S256 challenge itself, so there is no PKCE setting to change.

4. Copy the client ID and secret

   Copy the Client ID, and copy the Client secret straight away: Google shows the full secret only when the client is created and afterwards shows its last four characters. If it is lost, add a new secret to the client. Paste the secret into warden as the client secret.

   Copy back: the client ID, into warden's `client_id`.

   Copy back: the client secret, into warden's `client_secret`.

5. Enter the issuer

   The issuer is <issuer URL> and its discovery document is at https://accounts.google.com/.well-known/openid-configuration. Enter the issuer exactly as shown, with no trailing slash.

   Copy back: the issuer URL, into warden's `issuer_url`.

6. Check the email claims

   With the email scope Google puts both email and email_verified in the ID token, and warden needs both: it refuses a first sign-in unless email_verified is true. For accounts in a Google Workspace organisation Google also adds an hd claim with the domain; warden does not read it.

7. Limit who can sign in

   Google does not assign individual people to an OAuth client. Choose the Internal audience to keep everyone outside your Workspace organisation out, and use warden's allowed email domains setting to name the domains that may sign in. warden also only signs in people an administrator has already created or invited.

8. Save and test in warden

   In <product name> enter the issuer URL and client ID, store the client secret, set the provider to Google and save. Then run the configuration test. It checks discovery, the signing keys and the secret, and signs nobody in.

**Sources**

- Google Identity, OpenID Connect guide: <https://developers.google.com/identity/openid-connect/openid-connect>
- Google Cloud Console Help, creating and managing OAuth clients (answer 6158849): <https://support.google.com/cloud/answer/6158849>
- Google Cloud Console Help, Google Auth Platform audience, branding, data access and clients (answer 15544987): <https://support.google.com/cloud/answer/15544987>

## Okta

The same steps work for the organisation authorisation server and for a custom one; only the issuer differs.

Issuer hint: https://<your domain>.okta.com/oauth2/default

**Checked on 2026-11-23** against the sources listed at the end of this section.

1. Create the application integration

   In the Okta Admin Console go to Applications, Applications, and select Create App Integration. Choose OIDC - OpenID Connect as the sign-in method and Web Application as the application type, then select Next. Name the integration <product name>.

2. Choose the grant and client authentication

   Leave the grant type as Authorization Code: for a web application it is the default and cannot be changed. Keep client authentication on a client secret. warden sends a PKCE S256 challenge with every sign-in, which Okta accepts; if the integration offers Require PKCE you may leave it on.

3. Add the sign-in redirect URI

   Under Sign-in redirect URIs enter exactly <callback URI>. Okta needs an absolute URI and refuses sign-in to one that is not registered. Do not use a wildcard.

4. Limit who can sign in

   Under Assignments the default lets everyone in the Okta organisation use the integration. To limit it, choose Limit access to selected groups and name the groups, or choose Skip group assignment for now and assign people on the Assignments tab later. warden also only signs in people an administrator has already created or invited, and its allowed email domains setting narrows the list further.

5. Save and copy the credentials

   Select Save. On the General tab, under Client Credentials, copy the Client ID. Copy the Client secret from the same panel and paste it into warden as the client secret.

   Copy back: the client ID, into warden's `client_id`.

   Copy back: the client secret, into warden's `client_secret`.

6. Find the issuer

   The issuer depends on the authorisation server. The Okta organisation authorisation server's issuer is your Okta domain, https://<your domain>.okta.com. A custom authorisation server's issuer is https://<your domain>.okta.com/oauth2/<server id>, and the one named default ends in /oauth2/default; custom servers need the API Access Management add-on in production. Copy the issuer from the authorisation server's settings or from its discovery document and enter it exactly. It is <issuer URL> until you set it.

   Copy back: the issuer URL, into warden's `issuer_url`.

7. Check the email claims

   warden asks for the scopes <scopes>. With the email scope Okta puts email and email_verified in the ID token. email_verified is true only when the user's primary email has been verified, and warden refuses a first sign-in when it is false, so make sure each user has completed activation.

8. Save and test in warden

   In <product name> enter the issuer URL and client ID, store the client secret, set the provider to Okta and save. Then run the configuration test. It checks discovery, the signing keys and the secret, and signs nobody in.

**Sources**

- Okta Developer, authorization code flow guide: <https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/>
- Okta Developer, OpenID Connect and OAuth 2.0 API reference (claims and issuers): <https://developer.okta.com/docs/reference/api/oidc/>
- Okta Help Centre, OIDC app integration wizard (redirect URIs, PKCE, assignments, credentials): <https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm>

## Other OpenID Connect provider

Use this for any provider that is not one of the three above, such as Keycloak, Auth0 or Ping.

Issuer hint: The provider's issuer, exactly as its discovery document states it

**Checked on 2026-11-23** against the sources listed at the end of this section.

1. Check the provider can work with warden

   The provider must support the authorisation code flow with PKCE using the S256 method, publish an OpenID Connect discovery document (/.well-known/openid-configuration) and its signing keys over https, and sign ID tokens with RS256, ES256 or PS256. It must also put email and email_verified in the ID token for the scopes <scopes>. warden refuses a first sign-in unless email_verified is true.

2. Create a confidential web client

   In the provider's admin console register a new client for <product name>. Choose the confidential or web application type that authenticates with a client secret, and the authorisation code grant. Leave implicit and password grants off.

3. Add the redirect URI

   Register exactly <callback URI> as an allowed redirect URI, character for character. Do not use a wildcard.

4. Allow the scopes

   Make sure the client may request the scopes <scopes>. warden always sends a PKCE S256 challenge, a state value and a nonce.

5. Find the issuer

   Open the provider's discovery document and copy its issuer value. warden requires the ID token's issuer to equal it exactly, including any trailing slash, and the issuer must use https. It is <issuer URL> until you set it.

   Copy back: the issuer URL, into warden's `issuer_url`.

6. Copy the client ID and secret

   Copy the client ID and the client secret the provider generated. Paste the secret into warden as the client secret. The provider must offer client_secret_basic or client_secret_post for the token endpoint.

   Copy back: the client ID, into warden's `client_id`.

   Copy back: the client secret, into warden's `client_secret`.

7. Limit who can sign in

   Use the provider's own assignment or access rules to name who may use the client, and warden's allowed email domains setting to name the domains that may sign in. warden also only signs in people an administrator has already created or invited.

8. Save and test in warden

   In <product name> enter the issuer URL and client ID, store the client secret, set the provider to Other OpenID Connect provider and save. Then run the configuration test. It checks discovery, the signing keys and the secret, and signs nobody in.

**Sources**

- OpenID Connect Core 1.0 (sections 2, 3.1 and 3.1.3.7 read; the discovery path and PKCE support are also confirmed by the Microsoft and Google pages above): <https://openid.net/specs/openid-connect-core-1_0.html>
