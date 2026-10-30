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
| `static/` | The console: plain HTML, CSS and JavaScript modules, with no build step, framework or CDN. |

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

The example configuration requires MFA, so the first sign-in asks the administrator to set up an authenticator. The console shows the `otpauth://` URI and the secret as text; it draws no QR code.

### Single sign-on

Single sign-on starts disabled. To try it, sign in as the administrator, open **Single sign-on**, tick **Enabled** and save (the issuer and client id come from the configuration; the stub provider accepts any client secret, and `init` stored one). **Test the configuration** runs discovery and fetches the provider's keys. Then pre-provision a user (for example an invitation with sign-in method `sso_only`), and sign in through the stub provider's login page, entering the user's email address as the username and claims such as `{"email": "carol@example.org", "email_verified": true}`.

For break-glass sign-in, stop the provider (`docker compose ... stop idp`) and sign in with a password: single sign-on fails with its one generic message, and password sign-in still works.

## Gaps

These are things the console needed that warden's public surface does not provide. Each is recorded as a question for warden's maintainers, and the screen that needs it says so. The sample works around none of them; where it builds its own route, it does so only from public names, as any product would have to.

- No way to reset a user's TOTP enrolment or to issue new recovery codes.
- No HTTP route for the session policy: the sample's own `/api/policy` uses `Identity.policy`.
- No HTTP route to anchor the audit chain head or to check exported anchors: the sample's own `/api/audit/anchor` and `/api/audit/anchors/verify` use `warden.audit.anchor` and `verify_anchors`.
- Syslog settings come only from start-up configuration; nothing changes them at run time.
- No setting for the identity provider's CA: the sample sets `SSL_CERT_FILE` for its own process (httpx reads it) so warden trusts the stub provider.
- No "who am I" route: the sample's own `/api/me` answers it from `require_user`.
- warden's CLI cannot create the first administrator, since the roles are the product's: the sample has its own `create-admin` command.

## Tests

`tests/examples/` starts the console against a testcontainers Postgres: every router mounted, the Content Security Policy on every page and asset, a password sign-in round trip, an invitation followed from the outbox, and the notes refused without their permission and allowed with it. Type checking: `mypy --strict examples/console`.
