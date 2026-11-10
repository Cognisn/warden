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
| `devclock.py`, `data/` | The development clock (`serve --dev-clock`) and a small synthetic import file, both for walking password policies (see "Password policies"). |
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

### Without a mail sender

The screens ask warden what the deployment can do before offering a control: the sign-in screen reads `GET <auth>/capabilities` (anonymous) and the Users and Invitations screens read `GET <admin>/capabilities` (see the client guide, section 17). To see them follow it, start the console with no mail sender, as a product without mail would:

```
python -m examples.console serve --config $sb/console.yaml --without-mail
```

The sign-in screen then says reset links cannot be mailed instead of offering **Forgotten password**. Under **Users and roles**, **Send a password reset link** and **Send a passkey registration link** are disabled with a notice that mail is not configured; under **Invitations**, **Invite** and **Resend** are too. warden's own refusals have not changed: a call made anyway still gets its 503 `mail is not configured`, and the public reset request still answers 202 and sends nothing. Remove `passkey_registration_link` from `console.yaml` instead, and only the passkey registration link is disabled, with a notice naming the missing setting. The sign-in screen also hides single sign-on until it is enabled, and passkeys when there is no relying party (a base URL on an IP address).

## Password policies

The console shows warden's password policies and watch lists end to end: a live checklist wherever a password is set, the forced change at sign-in, and the administration of policies, role mapping, pins, watch lists and the exposure report. It uses warden's routes and public Python names only. The walk below is the one for the rc1 gate; each step says what you should see.

What is in the sample, and what is only for seeing it without waiting:

| What | Where | Notes |
|---|---|---|
| Browser rules | `static/js/passwordrules.js` | Evaluates the policy description (`rules` from the policy routes) as the user types. `tests/examples/test_console_password_rules.py` runs every case of `docs/contract/password-rule-vectors.json` through this very file under Node. |
| Live checklist | `static/js/checklist.js` | Shows each rule, the passphrase path (`Passphrase: 3 of 4 words`), and the tier with its change period; after the typing pauses (500 ms) it calls the check route to show a watch-list match and its reason. It is feedback: warden decides when you save. |
| Administration | `static/js/passwords.js` | Under **Passwords**: **Password policies**, **Watch lists** and **Exposure report**; a user's effective policy, pin and "change at next sign-in" are on **Users and roles** (Manage). |
| Recheck and clock | `static/js/dev.js`, `devclock.py` | Under **Development**. Sample only: warden schedules nothing, and a product does not move its clock. |
| Synthetic import file | `data/synthetic-pwned.txt` | Four SHA-1 hashes of invented passwords, with counts, in the Pwned Passwords downloader format (`HASH:count`). |

The administration routes are guarded by a permission the sample chose, `passwords.manage` (`admin_router(password_policies=...)`), which the `administrator` role holds.

### Before the walk

Use a sandbox set up as under "Running it against a sandbox". Three things make the walk quicker:

1. `init` writes `warden.passwords.fingerprint_key_secret` into `console.yaml` and seeds the key, so a policy can enable the sealed fingerprint (and the recheck has something to compare). Delete those two lines to see the notice the policy form shows when the key is not configured.
2. The example configuration requires a second factor. For the walk set `warden.identity.require_mfa: false` in `$sb/console.yaml`, so each invited user can sign in with a password alone. (A forced change works the same after a second factor.)
3. Start the console with the development clock, so expiry can be walked without waiting. **This is for development only**: warden uses the clock for session lifetimes and password ages, and a product leaves it alone.

   ```
   python -m examples.console serve --config $sb/console.yaml --dev-clock
   ```

Sign in as the administrator. The people for the walk are invented: `alice@example.com` (role `editor`) and `bob@example.com` (role `viewer`); invite each from **Invitations**, then follow the link from the **Outbox**.

### Create policies

Open **Password policies** and choose **New policy**.

- **Staff**, priority 10: minimum length 12, at least 3 kinds of character, no character repeated more than 3 times, refuse part of the email or name (until the library defect in Skuld question 39 is fixed, saving with this ticked fails with 500: leave it unticked), recognise a passphrase (minimum length 20, 4 words, excused the kinds rule), remember 3 past passwords, tiers `passphrase` (met by a passphrase, never changes), `strong` (16 characters, 3 kinds, 365 days) and `standard` (12 characters, 0 kinds, 90 days), warning 14 days, and tick the fingerprint. Choose **Preview affected users** first: it shows the users under the policy now and with this priority, and saving does not change anyone else.
- **Short expiry**, priority 20: minimum length 12, one tier `standard` (12 characters, 0 kinds, 30 days), warning 10 days, fingerprint on.

You should see both in the table with their users, rules, checks and tiers. **Up**, **Down** and **Set priority** reorder them; a priority in use is refused. If the fingerprint key were missing, the form would say so and disable the fingerprint.

### Map roles and pin a user

Under **Role mapping** on the same screen, choose `editor`, pick **Staff** and read the preview (users under Staff now, and after the mapping) before choosing **Map**. Map `viewer` to **Short expiry** the same way. Invite alice and bob now, so they land under those policies.

Then open **Users and roles**, **Manage** a user and read the **Password policy** card: the policy that applies, why (`from the role editor`, `pinned on this user` or `the default policy`), the tier, when the password was set and when it expires. Pin **Short expiry** on alice, see the reason change to `pinned`, and remove the pin again.

### The live checklist

The checklist appears at all four places a password is set: accepting an invitation (**Outbox**, follow the link), a reset link, **Account** under **Change password**, and the forced change below. Accept alice's invitation and type a password slowly:

- each rule turns from `Not yet` to `Met` as you type, in the browser, with no request;
- type `correct-horse-battery-staple` and watch `Passphrase: 3 of 4 words` reach `Passphrase met`, the kinds rule shown as `Excused by the passphrase`, and the tier become `passphrase (no change period)`;
- type a short mixed password and see the tier `standard (change every 90 days)`;
- pause for half a second and the line under the list reports `Not on any watch list.`, or the list's reason when it is.

The rules that compare the password with the user's email or name show `Checked when you save` where the page does not know them (an invitation or reset page); warden checks them on submit.

### A watch list refusal

Open **Watch lists** and create a **manual** list `Known weak` with the reason `Chosen too often here`. Choose **Manage**, add the exact password `Walkthrough-Pass-1!` and the term `examplecorp` (warden hashes the password at once and shows counts only), then **Attach** it to **Staff**. As alice, on **Account** type `Walkthrough-Pass-1!`, or any password containing `examplecorp`: after the pause the checklist shows `On a watch list: Chosen too often here`, and **Change password** is refused with 400 and the same reason. A list attached to a policy cannot be deleted until it is detached (409).

### Import a Pwned Passwords file

Create an **imported** list `Pwned sample` with the reason `This password appeared in a breach`. Choose **Manage** and **Import the sample file**: it loads `data/synthetic-pwned.txt` (four invented passwords: `Sample-Breached-Pass1`, `sample breached passphrase one`, `Winter2099!sample` and `letmein-sample-9`), replacing the list, and shows the count. **Attach** it to **Staff** and type `Sample-Breached-Pass1`: refused with the reason. warden itself imports from the command line, which also takes a real downloader file and a `--threshold`:

```
warden --config $sb/console.yaml passwords import --list "Pwned sample" --file examples/console/data/synthetic-pwned.txt --threshold 10
```

### Recheck, then a forced change

A recheck finds passwords already in use that have since reached a list. alice's password was set before the lists were attached, and its fingerprint (a sealed digest, never the password) was written when she set it or signed in. As the administrator, open **Watch lists**, **Manage** `Known weak` and add alice's current password as an exact password. Then open **Development** and choose **Run a recheck**: the counts show one password matched and one user newly required to change. The **Exposure report** now lists alice, with the list. Alice signs in: instead of a session she sees `Your password is on a watch list: Chosen too often here.` and the change form with the live checklist; the new password completes the sign-in and ends her other sessions. The same happens, with the words `An administrator has asked you to change your password.`, after **Require a change at next sign-in** on a user's **Password policy** card (**Clear the required change** undoes it). The command line does the same recheck: `warden --config $sb/console.yaml passwords recheck`.

### Expiry warning, then a forced change

bob is under **Short expiry** (30 days, warning from 10 days). Sign in as bob once, so his password's clock starts, and sign out. Under **Development**, set the clock to 25 days ahead. Moving the clock ends every current session, as time would, so sign in again: bob signs in, and **Account** shows `Your password expires in 5 days.` (warden's `password_expires_in_days`). Set the clock to 40 days and sign in again: now sign-in answers `password_change_required` with `Your password has reached the end of its change period.` and the same checklist. After the change the clock keeps its offset, so leave it or restart the console: **Back to real time** puts the clock behind passwords set under the offset.

### The real range API

A policy can also ask the Pwned Passwords range API (ruling PW7). In **Edit** for a policy, tick the range API and choose what happens when it cannot be reached (`allow` or `refuse`). Nothing else is needed: the default `warden.passwords.hibp_range_url` is `https://api.pwnedpasswords.com/range/`, the console's host needs outbound HTTPS to it, and only the first five characters of the password's SHA-1 are sent, never the password, and only for a policy that enables it. Type a password well known from breaches that the built-in list does not hold; after the pause the checklist shows `This password has appeared in a data breach`. To see the unavailable mode, block outbound HTTPS to that host and choose `refuse`: the checklist says the online check could not be reached and warden refuses on save. A self-hosted mirror is a different `hibp_range_url` in the `passwords` section of `console.yaml`.

## Gaps

These are things the console needed that warden's public surface does not provide. Each is recorded as a numbered question in warden 0.1.0's release tracking, and the screen that needs it says so. The sample works around none of them; where it builds its own route, it does so only from public names, as any product would have to.

- No HTTP route for the session policy: the sample's own `/api/policy` uses `Identity.policy` (question 7).
- No HTTP route to anchor the audit chain head or to check exported anchors: the sample's own `/api/audit/anchor` and `/api/audit/anchors/verify` use `warden.audit.anchor` and `verify_anchors` (question 8).
- Syslog settings come only from start-up configuration; nothing changes them at run time (question 9).
- No setting for the identity provider's CA: the sample sets `SSL_CERT_FILE` for its own process (httpx reads it) so warden trusts the stub provider (question 10).
- No "who am I" route: the sample's own `/api/me` answers it from `require_user` (question 11).
- Creating or changing a password policy over HTTP with `forbid_user_details` in the body answers 500, so that rule cannot be set from the console yet; the policy form sends the field only when ticked (question 39, a defect in the admin route rather than a missing feature).
- warden's CLI cannot create the first administrator, since the roles are the product's: the sample has its own `create-admin` command (question 11).

## Tests

`tests/examples/` runs the browser's password rules against warden's test vectors under Node (`test_console_password_rules.py`; in CI a missing Node fails the run), and starts the console against a testcontainers Postgres: every router mounted, the Content Security Policy on every page and asset, a password sign-in round trip, an invitation followed from the outbox, and the notes refused without their permission and allowed with it. The passkey tests use the test suite's software authenticator in place of a browser and a key: every warden route a screen calls is mounted, a key registered, renamed and removed, the last second factor kept, a key as the second factor and in a forced enrolment, a passkey sign-in round trip, `passkey_only` with the registration link followed from the outbox, the administrator's reset, and a `passkey_only` invitation accepted with a passkey. The password policy tests check the permission the sample chose for the new routes, the development clock, the recheck and import helpers, a forced change round trip and expiry walked on the clock. The capability tests build the console with and without a mail sender, and without the passkey link setting, and check both capability routes, the unchanged 503 and the screens that read them. Type checking: `mypy --strict examples/console`.
