# warden sample console

A small sample product that integrates warden and exercises it in a browser.

**For local development only.** It is not a deployment template: its secrets are fixed `-dev-only` values, its notes and mail outbox live in memory, its outbox needs no sign-in so an invitee can follow a link, and it serves plain HTTP on the loopback interface. It is not part of the `cognisn-warden` package: the wheel builds only `src/warden` and the sdist leaves `examples/` out.

## What it shows

How a product integrates warden, using only warden's public surface (names a warden package exports, public modules, and warden's HTTP routes). A tripwire, `tests/examples/test_examples_public_surface.py`, fails if anything here reaches into a private warden module or name.

| File | What a product does there |
|---|---|
| `settings.py`, `console.template.yaml` | Reads warden's settings through konfig and validates them into one `WardenConfig` at start-up. |
| `app.py` | Hands warden its own connection pool, installs the audit recorder, opens the key store, constructs `Identity`, runs the syslog forwarder, and mounts warden's routers under the configured prefixes, each guarded by a permission it chose. |
| `product.py` | Declares the product's permissions and roles (`viewer`, `editor`, `notes-admin`, `auditor`, `administrator`) and its audit actions (`console.note.*`). |
| `notes.py` | A product resource gated by `require_permission`, narrowed by a resource-scope hook (only a note's owner, or a holder of `notes.admin`, may change it), with an audit event per change. |
| `outbox.py` | A `MailSender` that keeps messages in memory, so invitation and reset links can be followed. |
| `console_routes.py` | The sample's own routes for what warden leaves to the product (see "Gaps"). |
| `bootstrap.py` | Creates the first administrator: warden's CLI cannot, because the roles are the product's. |
| `security.py` | A strict Content Security Policy on every answer: scripts and styles only from the app, no inline script or style. |
| `static/` | The console: plain HTML, CSS and JavaScript modules, with no build step, framework or CDN. `static/js/webauthn.js` is the browser side of passkeys and security keys: it hands warden's options to `navigator.credentials` and sends the answer back as JSON, with the WebAuthn Level 3 helpers where the browser has them and a fallback where it does not. |

The console holds the access and refresh tokens in memory only (never `localStorage`), refreshes once at a time shortly before the access token expires, never sends a spent refresh token again, and retries a refused call once after a refresh. Reloading the page signs you out.

## Running it against a sandbox

On a workstation with the worktree recipe (`dev/worktree.json`), the sandbox's `ports.txt` lists the ports: `postgres`, `syslog_tls`, `stub_idp` and `console`. Everything binds to `127.0.0.1`. The commands below use PowerShell with the sandbox in `$sb`; adjust for another shell.

1. Install warden with the examples extra (uvicorn, the psycopg pool and binary driver):

   ```
   pip install -e ".[dev,examples]"
   ```

2. Start the sandbox stack with the stub provider and the syslog collector, after writing their certificates (the stack counts as one heavy workload):

   ```
   python tests/syslogfwd/live/make_certs.py $sb/certs
   python tests/identity/sso/live/make_certs.py $sb/idp-certs
   <compose_up from ports.txt, with --profile idp --profile syslog added>
   ```

3. Write the console's configuration (`$sb/console.yaml`) and seed konfig's secrets store (an encrypted file in the sandbox) with the TOTP encryption key and the provider's client secret:

   ```
   python -m examples.console init --sandbox $sb
   ```

4. Migrate, create a signing key, and create the first administrator, as a product's deployment would:

   ```
   warden --config $sb/console.yaml migrate
   warden --config $sb/console.yaml keys rotate
   python -m examples.console create-admin --config $sb/console.yaml --email admin@example.com
   ```

5. Start the console on `127.0.0.1` at the console port, and open `http://localhost:<console port>/`:

   ```
   python -m examples.console serve --config $sb/console.yaml
   ```

Use `localhost` rather than `127.0.0.1` in the browser: the public base URL is `http://localhost:<port>`, and the single sign-on login cookie is `Secure`, which browsers accept over plain HTTP only for `localhost`.

The example configuration requires MFA, so the first sign-in asks the administrator to set up a second factor: an authenticator app or a security key or passkey. For an authenticator app the console shows the `otpauth://` URI and the secret as text; it draws no QR code.

### Resetting second factors

An administrator who opens a user under Users has two resets. **Reset second factors** (warden's `DELETE <admin>/users/{user_id}/mfa`) removes the authenticator, every security key and passkey and every recovery code, and ends the user's sessions, so their next sign-in sets up a second factor again. **Reset TOTP** (`DELETE <admin>/users/{user_id}/totp`) removes only the authenticator and the recovery codes, and leaves keys in place. Recovery codes cannot yet be replaced by the user; that is planned for warden 0.2.0.

### Passkeys and security keys

The console needs no WebAuthn settings: with `http://localhost:<port>` as the public base URL, the relying party ID is `localhost` and the only allowed origin is the console's own. Open the console at `http://localhost:<port>/`, never `127.0.0.1`: a browser refuses an IP address as a relying party, and a credential made for `localhost` works nowhere else. Every passkey made on this walk belongs to `localhost`; delete them from the key or password manager afterwards.

What each screen does:

- **Account** (signed in): **Security keys and passkeys** registers a key with an optional nickname, lists the keys (nickname, kind, when registered and last used), renames and removes them. Removing the only second factor while the policy requires one is refused with warden's 409, shown as it is. The first second factor of either kind comes with recovery codes, shown once.
- **Sign in**: when the password step answers `mfa_required`, the second-factor card offers **Use your security key or passkey** when `methods` lists `webauthn`, the authenticator code when it lists `totp`, and a recovery code always. A forced enrolment (`mfa_enrolment_required`) offers a key or an authenticator app. **Sign in with a passkey** asks the browser for any passkey for this site, with no email first; where the browser supports conditional mediation, the email field's autofill offers the passkeys too. A passkey sign-in has no second step (`amr` `["hwk", "mfa"]`). A passkey picked from the autofill after its challenge has expired (five minutes by default) gets the uniform refusal, and the autofill starts again.
- **Users and roles**: the sign-in method `passkey_only`, with a notice when the user holds no passkey yet; **Send a passkey registration link**; **Reset second factors**; and how many keys the user holds.
- **Invitations**: invite with `passkey_only`. The invitee follows the link from the outbox to `/accept` and chooses **With a passkey**.
- **Outbox**: the registration link (`http.passkey_registration_link`, `/passkey?t=...` in the example configuration) opens the **Register a passkey** page, which registers a passkey without signing in and shows any recovery codes once.

#### With a real YubiKey

Set a FIDO2 PIN on the key first (for example in Yubico Authenticator): a passkey needs user verification, and without a PIN the key can only be a second factor.

1. Sign in as the administrator and finish the forced enrolment with **Register a security key or passkey**: touch the key and enter its PIN. The account's list shows it as a passkey on the device; the recovery codes appear once.
2. Sign out, then sign in again with the password: the second-factor card offers the key. Touch it.
3. Sign out and choose **Sign in with a passkey**, or click into the email field and pick the key from the autofill: enter the PIN and touch it. The account screen shows `amr` `["hwk", "mfa"]`.
4. Under **Invitations**, invite a second user with `passkey_only`, follow the link from the outbox, and accept **With a passkey** on the same key (a YubiKey holds several). Sign in as that user with **Sign in with a passkey**.
5. As the administrator, **Reset second factors** for that user: their passkey no longer signs in. **Send a passkey registration link**, follow it from the outbox, and register again.
6. On the account screen, try to remove the administrator's only key: the 409 says why. Register a second key or an authenticator app, then remove the first.

#### With a synced passkey

A synced passkey lives in a password manager (iCloud Keychain, Google Password Manager, Windows Hello or a third-party manager) or on a phone reached by QR code. Walk the same steps, choosing the platform's passkey when the browser asks. The account's list shows it as a synced passkey. Synced passkeys usually have no signature counter; warden accepts them, and still accepts each challenge only once.

#### Only YubiKeys: attestation roots

With trusted attestation roots configured, warden asks for direct attestation at registration and accepts only authenticators whose attestation chains to one of the roots. To try it with Yubico's roots:

1. Download Yubico's attestation root certificates in PEM from Yubico's PKI page (`https://developers.yubico.com/PKI/`). Recent keys chain to the **Yubico FIDO Root CA Serial 450203556**, older ones to the **Yubico U2F Root CA Serial 457200631**. Put both in to accept either.
2. Add them to `console.yaml` under `warden`, each certificate's lines indented as a block:

   ```yaml
   warden:
     webauthn:
       attestation_roots: |
         -----BEGIN CERTIFICATE-----
         ...
         -----END CERTIFICATE-----
   ```

   A product would usually keep the roots in konfig's secrets store and write `attestation_roots: secret://<name>` instead.
3. Restart `serve`. Registering a YubiKey now works (the browser may ask to let the site see the key's make and model: allow it). Registering a synced passkey, or a key from another maker, is refused with a 400 (`credential not accepted`): synced passkeys usually carry no attestation, so a roots policy refuses them, which is its intent. Keys registered before the roots were set keep working.

Remove the block and restart to accept any authenticator again.

### Single sign-on

Single sign-on starts disabled. To try it, sign in as the administrator, open **Single sign-on**, tick **Enabled** and save (the issuer and client id come from the configuration; the stub provider accepts any client secret, and `init` stored one). **Test the configuration** runs discovery and fetches the provider's keys. Then pre-provision a user (for example an invitation with sign-in method `sso_only`), and sign in through the stub provider's login page, entering the user's email address as the username and claims such as `{"email": "carol@example.org", "email_verified": true}`.

For break-glass sign-in, stop the provider (`docker compose ... stop idp`) and sign in with a password: single sign-on fails with its one generic message, and password sign-in still works.

## Gaps

These are things the console needed that warden's public surface does not provide. Each is recorded as a numbered question in warden 0.1.0's release tracking, and the screen that needs it says so. The sample works around none of them; where it builds its own route, it does so only from public names, as any product would have to.

- No HTTP route for the session policy: the sample's own `/api/policy` uses `Identity.policy` (question 7).
- No HTTP route to anchor the audit chain head or to check exported anchors: the sample's own `/api/audit/anchor` and `/api/audit/anchors/verify` use `warden.audit.anchor` and `verify_anchors` (question 8).
- Syslog settings come only from start-up configuration; nothing changes them at run time (question 9).
- No setting for the identity provider's CA: the sample sets `SSL_CERT_FILE` for its own process (httpx reads it) so warden trusts the stub provider (question 10).
- No "who am I" route: the sample's own `/api/me` answers it from `require_user` (question 11).
- warden's CLI cannot create the first administrator, since the roles are the product's: the sample has its own `create-admin` command (question 11).

## Tests

`tests/examples/` starts the console against a testcontainers Postgres: every router mounted, the Content Security Policy on every page and asset, a password sign-in round trip, an invitation followed from the outbox, and the notes refused without their permission and allowed with it. The passkey tests use the test suite's software authenticator in place of a browser and a key: every warden route a screen calls is mounted, a key registered, renamed and removed, the last second factor kept, a key as the second factor and in a forced enrolment, a passkey sign-in round trip, `passkey_only` with the registration link followed from the outbox, the administrator's reset, and a `passkey_only` invitation accepted with a passkey. Type checking: `mypy --strict examples/console`.
