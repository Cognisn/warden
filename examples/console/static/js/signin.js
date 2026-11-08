// Sign-in, second factors, single sign-on completion and the account screen.

import { adopt, call, me, prefixes, refresh, sessionTimes, signOut, signedIn } from "./api.js";
import { action, card, field, form, h, input, json, outcome, recoveryCodes, status, table, when } from "./dom.js";
import { gap } from "./gaps.js";
import { conditionalAvailable, create, described, get, supported } from "./webauthn.js";

// What warden returns when single sign-on fails in the browser leg; the
// reason is only in the audit trail (warden.identity.SSO_FAILURE_MESSAGE).
const SSO_FAILED = "Single sign-on did not complete. Try again, or contact your administrator.";

function go(hash) {
  window.location.hash = hash;
}

// The browser's own prompt, with its errors put plainly.
async function prompt(run) {
  try {
    return await run();
  } catch (error) {
    throw new Error(described(error));
  }
}

// After a password: tokens, or a second-factor challenge, or enrolment under a challenge.
function afterPassword(body, area) {
  if (body.status === "signed_in") {
    adopt(body);
    go("#/account");
    return null;
  }
  if (body.status === "mfa_required") return secondFactorStep(body, area);
  return forcedEnrolment(body.challenge, area);
}

// mfa_required lists the kinds of second factor the user holds: a key is
// offered beside the code when the list has "webauthn". A recovery code is
// always accepted.
function secondFactorStep({ challenge, methods }, area) {
  const held = methods || ["totp"];
  const done = (answer) => {
    if (!answer.ok) return outcome(answer);
    adopt(answer.data);
    go("#/account");
    return null;
  };
  const keyArea = h("div", {});
  const byKey = h(
    "div",
    {},
    action(
      "Use your security key or passkey",
      async () => {
        const { auth } = await prefixes();
        const options = await call("POST", `${auth}/webauthn/verify/options`, { body: { challenge }, anonymous: true });
        if (!options.ok) return outcome(options);
        const credential = await prompt(() => get(options.data.public_key));
        return done(await call("POST", `${auth}/webauthn/verify`, { body: { challenge, credential }, anonymous: true }));
      },
      keyArea,
    ),
    keyArea,
  );
  const codeForm = form(
    "inline",
    [field("Authenticator code", input("code", { inputmode: "numeric", autocomplete: "one-time-code", required: true })), h("button", {}, "Verify")],
    async ({ code }) => {
      const { auth } = await prefixes();
      return done(await call("POST", `${auth}/totp/verify`, { body: { challenge, code }, anonymous: true }));
    },
  );
  const recoveryForm = form(
    "inline",
    [field("Or a recovery code", input("code", { autocomplete: "off", required: true })), h("button", { class: "quiet" }, "Use recovery code")],
    async ({ code }) => {
      const { auth } = await prefixes();
      return done(await call("POST", `${auth}/recovery-code`, { body: { challenge, code }, anonymous: true }));
    },
  );
  area.replaceChildren(
    card(
      "Second factor",
      held.includes("webauthn") ? byKey : null,
      held.includes("totp") ? codeForm : null,
      recoveryForm,
    ),
  );
  return status("info", `Password accepted: a second factor is needed (${held.join(" or ")}).`);
}

// TOTP enrolment, either under a sign-in challenge (``{challenge}``) or for the
// signed-in user (``{}``, with the bearer token).
function enrolStep(under, area) {
  const begin = async () => {
    const { auth } = await prefixes();
    const answer = await call("POST", `${auth}/totp/enrolment`, {
      body: under.challenge ? { challenge: under.challenge } : {},
      anonymous: Boolean(under.challenge),
    });
    if (!answer.ok) return outcome(answer);
    return h(
      "div",
      {},
      h("p", {}, "Add this account to an authenticator app with the URI or the secret, then enter a code."),
      field("otpauth URI", h("pre", {}, answer.data.uri)),
      field("Secret (base32)", h("pre", {}, answer.data.secret)),
      h("p", { class: "muted" }, "The URI is shown as text; the sample draws no QR code."),
      confirm,
    );
  };
  const confirm = form(
    "inline",
    [field("Code from the app", input("code", { inputmode: "numeric", required: true })), h("button", {}, "Confirm")],
    async ({ code }) => {
      const { auth } = await prefixes();
      const body = under.challenge ? { challenge: under.challenge, code } : { code };
      const answer = await call("POST", `${auth}/totp/enrolment/confirm`, {
        body,
        anonymous: Boolean(under.challenge),
      });
      if (!answer.ok) return outcome(answer);
      if (answer.data.access_token) adopt(answer.data);
      return h(
        "div",
        {},
        status("ok", "Enrolled."),
        recoveryCodes(answer.data.recovery_codes) ?? h("p", { class: "muted" }, "The recovery codes you already hold cover the authenticator too."),
        signedIn() ? h("p", {}, h("a", { href: "#/account" }, "Continue to your account")) : null,
      );
    },
  );
  const target = h("div", {});
  area.replaceChildren(card("Set up an authenticator", target));
  begin().then((node) => target.replaceChildren(node), (e) => target.replaceChildren(status("error", String(e))));
  return under.challenge ? status("info", "Password accepted: this account must set up an authenticator first.") : null;
}

// Registering a security key or passkey with a nickname, either under a
// sign-in challenge (forced enrolment, which signs in) or for the signed-in
// user. ``after`` runs once a key is registered.
function keyRegistration(under, after = async () => {}) {
  return form(
    "inline",
    [
      field("Nickname (optional)", input("nickname", { maxlength: 64, autocomplete: "off", placeholder: "Blue YubiKey" })),
      h("button", {}, "Register a security key or passkey"),
    ],
    async ({ nickname }) => {
      const { auth } = await prefixes();
      const anonymous = Boolean(under.challenge);
      const options = await call("POST", `${auth}/webauthn/registration`, {
        body: anonymous ? { challenge: under.challenge } : {},
        anonymous,
      });
      if (!options.ok) return outcome(options);
      const credential = await prompt(() => create(options.data.public_key));
      const body = { credential, nickname: nickname || null };
      if (anonymous) body.challenge = under.challenge;
      const answer = await call("POST", `${auth}/webauthn/registration/confirm`, { body, anonymous });
      if (!answer.ok) return outcome(answer);
      if (answer.data.access_token) adopt(answer.data);
      await after();
      return h(
        "div",
        {},
        status("ok", `Registered ${answer.data.credential.nickname ?? "the key"}.`),
        recoveryCodes(answer.data.recovery_codes),
        anonymous ? h("p", {}, h("a", { href: "#/account" }, "Continue to your account")) : null,
      );
    },
  );
}

// mfa_enrolment_required: the account must have a second factor first; either kind will do.
function forcedEnrolment(challenge, area) {
  const target = h("div", {});
  area.replaceChildren(
    card(
      "Set up a second factor",
      h("p", { class: "muted" }, "This account needs a second factor before it can sign in. Set up an authenticator app or register a security key or passkey; the recovery codes come with the first."),
      supported() ? keyRegistration({ challenge }) : status("info", "This browser cannot use security keys or passkeys."),
      h("p", {}, action("Set up an authenticator app instead", async () => enrolStep({ challenge }, target), target, "quiet")),
      target,
    ),
  );
  return status("info", "Password accepted: this account must set up a second factor first.");
}

// What a sign-in screen may offer (GET <auth>/capabilities): the same answer for
// everyone. If it is missing, everything is offered and warden's routes refuse.
async function signInCapabilities(auth) {
  const answer = await call("GET", `${auth}/capabilities`, { anonymous: true });
  return answer.ok ? answer.data : { password_reset: true, single_sign_on: true, passkey_sign_in: true };
}

export async function signInScreen(main) {
  const { auth } = await prefixes();
  const offered = await signInCapabilities(auth);
  const next = h("div", {});
  let autofill = null;
  const stopAutofill = () => {
    if (autofill) autofill.abort();
    autofill = null;
  };
  const signedInWith = async (credential) => {
    const answer = await call("POST", `${auth}/passkey/sign-in`, { body: { credential }, anonymous: true });
    if (!answer.ok) return outcome(answer);
    stopAutofill();
    adopt(answer.data);
    go("#/account");
    return null;
  };

  // Conditional mediation: the browser offers the user's passkeys in the
  // email field's autofill. The options carry no allowCredentials, so they
  // are the same for everyone and reveal nothing about any account.
  const startAutofill = async () => {
    if (!offered.passkey_sign_in || !(await conditionalAvailable())) return;
    stopAutofill();
    const controller = new AbortController();
    autofill = controller;
    const options = await call("POST", `${auth}/passkey/options`, { anonymous: true });
    if (!options.ok || controller.signal.aborted) return;
    try {
      const credential = await get(options.data.public_key, { mediation: "conditional", signal: controller.signal });
      const shown = await signedInWith(credential);
      if (shown) {
        next.replaceChildren(shown);
        startAutofill();
      }
    } catch (error) {
      if (controller.signal.aborted || (error && error.name === "AbortError")) return;
      next.replaceChildren(status("error", described(error)));
    }
  };

  const passwordForm = form(
    "stack",
    [
      field("Email", input("email", { type: "email", autocomplete: "username webauthn", required: true })),
      field("Password", input("password", { type: "password", autocomplete: "current-password", required: true })),
      h("button", {}, "Sign in"),
    ],
    async ({ email, password }) => {
      const answer = await call("POST", `${auth}/sign-in`, { body: { email, password }, anonymous: true });
      if (!answer.ok) return outcome(answer);
      stopAutofill();
      return afterPassword(answer.data, next);
    },
  );
  const passkeyArea = h("div", {});
  const passkey = action(
    "Sign in with a passkey",
    async () => {
      // One WebAuthn request at a time: the autofill's waiting request ends first.
      stopAutofill();
      const options = await call("POST", `${auth}/passkey/options`, { anonymous: true });
      if (!options.ok) return outcome(options);
      const credential = await prompt(() => get(options.data.public_key));
      const shown = await signedInWith(credential);
      if (shown) startAutofill();
      return shown;
    },
    passkeyArea,
  );
  const sso = h(
    "button",
    { type: "button", class: "quiet", onclick: () => window.location.assign(`${auth}/sso/start`) },
    "Sign in with single sign-on",
  );
  const reset = form(
    "inline",
    [field("Email", input("email", { type: "email", required: true })), h("button", { class: "quiet" }, "Send a reset link")],
    async ({ email }) => outcome(await call("POST", `${auth}/password-reset`, { body: { email }, anonymous: true }), "requested; see the outbox if the account exists"),
  );
  main.replaceChildren(
    h("h2", {}, "Sign in"),
    card("Password", passwordForm),
    next,
    offered.passkey_sign_in
      ? card(
          "Passkey",
          h("p", { class: "muted" }, "No email needed: the browser offers this site's passkeys, here or in the email field's autofill. A passkey signs you in on its own, with no second step."),
          supported() ? passkey : status("info", "This browser cannot use passkeys."),
          passkeyArea,
        )
      : card("Passkey", status("info", "Passkeys are not available here: warden has no relying party for this address.")),
    offered.single_sign_on
      ? card("Single sign-on", h("p", { class: "muted" }, "Goes to the configured identity provider and back to /signed-in."), sso)
      : card("Single sign-on", status("info", "Single sign-on is not enabled. An administrator can enable it under Single sign-on.")),
    offered.password_reset
      ? card("Forgotten password", reset)
      : card("Forgotten password", status("info", "Reset links cannot be mailed here (mail is not configured), so ask an administrator.")),
  );
  // Leaving the screen ends the autofill's waiting request.
  window.addEventListener("hashchange", stopAutofill, { once: true });
  startAutofill();
}

// The SSO completion link: /signed-in?code=... (or ?error=sso_failed).
export async function ssoLanding(main) {
  const params = new URLSearchParams(window.location.search);
  window.history.replaceState(null, "", "/signed-in");
  if (params.get("error") || !params.get("code")) {
    main.replaceChildren(h("h2", {}, "Single sign-on"), status("error", SSO_FAILED), h("a", { href: "/#/signin" }, "Back to sign-in"));
    return;
  }
  const { auth } = await prefixes();
  const answer = await call("POST", `${auth}/sso/handoff`, { body: { code: params.get("code") }, anonymous: true });
  if (!answer.ok) {
    main.replaceChildren(h("h2", {}, "Single sign-on"), status("error", SSO_FAILED), outcome(answer));
    return;
  }
  adopt(answer.data);
  // Same document, so the tokens in memory survive: no navigation, no reload.
  window.history.replaceState(null, "", "/#/account");
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}

function kind(key) {
  // `passkey` is warden's own answer: discoverable and registered with user verification.
  if (!key.passkey) return "security key (second factor)";
  return key.backup_eligible ? "passkey (synced)" : "passkey (on the device)";
}

// The signed-in user's own security keys and passkeys: register, list, rename, remove.
function keysCard(auth) {
  const listArea = h("div", {});
  const out = h("div", {});
  const load = async () => {
    const answer = await call("GET", `${auth}/webauthn/credentials`);
    if (!answer.ok) return outcome(answer);
    const keys = answer.data.credentials;
    if (keys.length === 0) return status("info", "No security keys or passkeys yet.");
    return table(
      ["Nickname", "Kind", "Registered", "Last used", ""],
      keys.map((key) =>
        h(
          "tr",
          {},
          h("td", {}, key.nickname ?? "(none)"),
          h("td", {}, kind(key)),
          h("td", {}, when(key.created_at)),
          h("td", {}, when(key.last_used_at) || "never"),
          h(
            "td",
            { class: "actions" },
            form(
              "inline",
              [input("nickname", { value: key.nickname ?? "", maxlength: 64, "aria-label": "New nickname" }), h("button", { class: "quiet" }, "Rename")],
              async ({ nickname }) => {
                const result = await call("PATCH", `${auth}/webauthn/credentials/${encodeURIComponent(key.id)}`, { body: { nickname: nickname || null } });
                if (result.ok) listArea.replaceChildren(await load());
                out.replaceChildren(outcome(result, "renamed"));
                return null;
              },
            ),
            action(
              "Remove",
              async () => {
                const result = await call("DELETE", `${auth}/webauthn/credentials/${encodeURIComponent(key.id)}`);
                listArea.replaceChildren(await load());
                if (result.status === 409) {
                  return status(
                    "error",
                    `Not removed: ${result.data.detail}. Register another key or set up an authenticator app first, then remove this one.`,
                  );
                }
                return outcome(result, "removed");
              },
              out,
              "danger",
            ),
          ),
        ),
      ),
    );
  };
  const reload = async () => listArea.replaceChildren(await load());
  load().then((node) => listArea.replaceChildren(node));
  return card(
    "Security keys and passkeys",
    h("p", { class: "muted" }, "A security key or passkey is a second factor beside the authenticator app. One that is a passkey (registered with a PIN or biometric, and kept on the key or synced) also signs you in alone with Sign in with a passkey."),
    listArea,
    out,
    supported() ? keyRegistration({}, reload) : status("info", "This browser cannot use security keys or passkeys."),
  );
}

export async function accountScreen(main) {
  const { auth } = await prefixes();
  const who = await me();
  if (!who) {
    main.replaceChildren(h("h2", {}, "Account"), status("info", "Not signed in."), h("a", { href: "#/signin" }, "Sign in"));
    return;
  }
  const times = sessionTimes();
  const out = h("div", {});
  const enrolArea = h("div", {});
  const enrolNote = h("div", {});
  const passwordForm = form(
    "stack",
    [
      field("Current password", input("current_password", { type: "password", autocomplete: "current-password", required: true })),
      field("New password", input("new_password", { type: "password", autocomplete: "new-password", required: true })),
      h("button", {}, "Change password"),
    ],
    async (values) => outcome(await call("POST", `${auth}/password`, { body: values }), "password changed"),
  );
  main.replaceChildren(
    h("h2", {}, "Account"),
    card(
      "Signed in",
      json(who),
      h("p", { class: "muted" }, `Access token expires ${new Date(times.accessExpiresAt).toLocaleTimeString("en-AU")}; refresh token ${new Date(times.refreshExpiresAt).toLocaleTimeString("en-AU")}. Both are held in memory only.`),
      action("Refresh now", async () => ((await refresh()) ? status("ok", "Refreshed: a new token pair; the old refresh token is spent.") : status("error", "Refresh refused: signed out.")), out, "quiet"),
      " ",
      action("Sign out", async () => {
        const answer = await signOut();
        go("#/signin");
        return answer ? outcome(answer, "signed out") : null;
      }, out, "danger"),
      out,
    ),
    keysCard(auth),
    card(
      "Authenticator (TOTP)",
      h("p", { class: "muted" }, "Enrol an authenticator for this account. If one is already enrolled, warden answers 409."),
      action("Set up an authenticator", async () => enrolStep({}, enrolArea), enrolNote, "quiet"),
      enrolNote,
      enrolArea,
      h("p", { class: "muted" }, "Lost every second factor and your recovery codes? An administrator can reset them (Users, Manage, Reset second factors), and you set one up again at your next sign-in; a passkey-only account gets a registration link instead. Replacing your own recovery codes is planned for warden 0.2.0."),
    ),
    card("Change password", passwordForm),
  );
}
