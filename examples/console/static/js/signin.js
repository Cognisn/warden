// Sign-in, second factors, single sign-on completion and the account screen.

import { adopt, call, me, prefixes, refresh, sessionTimes, signOut, signedIn } from "./api.js";
import { action, card, field, form, h, input, json, outcome, status } from "./dom.js";
import { gap } from "./gaps.js";

// What warden returns when single sign-on fails in the browser leg; the
// reason is only in the audit trail (warden.identity.SSO_FAILURE_MESSAGE).
const SSO_FAILED = "Single sign-on did not complete. Try again, or contact your administrator.";

function go(hash) {
  window.location.hash = hash;
}

// After a password: tokens, or a TOTP challenge, or enrolment under a challenge.
function afterPassword(body, area) {
  if (body.status === "signed_in") {
    adopt(body);
    go("#/account");
    return null;
  }
  if (body.status === "mfa_required") return totpStep(body.challenge, area);
  return enrolStep({ challenge: body.challenge }, area);
}

function totpStep(challenge, area) {
  const codeForm = form(
    "inline",
    [field("Authenticator code", input("code", { inputmode: "numeric", autocomplete: "one-time-code", required: true })), h("button", {}, "Verify")],
    async ({ code }) => {
      const { auth } = await prefixes();
      const answer = await call("POST", `${auth}/totp/verify`, { body: { challenge, code }, anonymous: true });
      if (!answer.ok) return outcome(answer);
      adopt(answer.data);
      go("#/account");
      return null;
    },
  );
  const recoveryForm = form(
    "inline",
    [field("Or a recovery code", input("code", { autocomplete: "off", required: true })), h("button", { class: "quiet" }, "Use recovery code")],
    async ({ code }) => {
      const { auth } = await prefixes();
      const answer = await call("POST", `${auth}/recovery-code`, { body: { challenge, code }, anonymous: true });
      if (!answer.ok) return outcome(answer);
      adopt(answer.data);
      go("#/account");
      return null;
    },
  );
  area.replaceChildren(card("Second factor", codeForm, recoveryForm));
  return status("info", "Password accepted: a second factor is needed.");
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
        status("ok", "Enrolled. Keep these recovery codes somewhere safe: each works once, and they are not shown again."),
        h("div", { class: "codes" }, answer.data.recovery_codes.map((c) => h("div", {}, c))),
        signedIn() ? h("p", {}, h("a", { href: "#/account" }, "Continue to your account")) : null,
      );
    },
  );
  const target = h("div", {});
  area.replaceChildren(card("Set up an authenticator", target));
  begin().then((node) => target.replaceChildren(node), (e) => target.replaceChildren(status("error", String(e))));
  return under.challenge ? status("info", "Password accepted: this account must set up an authenticator first.") : null;
}

export async function signInScreen(main) {
  const { auth } = await prefixes();
  const next = h("div", {});
  const passwordForm = form(
    "stack",
    [
      field("Email", input("email", { type: "email", autocomplete: "username", required: true })),
      field("Password", input("password", { type: "password", autocomplete: "current-password", required: true })),
      h("button", {}, "Sign in"),
    ],
    async ({ email, password }) => {
      const answer = await call("POST", `${auth}/sign-in`, { body: { email, password }, anonymous: true });
      if (!answer.ok) return outcome(answer);
      return afterPassword(answer.data, next);
    },
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
    card("Single sign-on", h("p", { class: "muted" }, "Goes to the configured identity provider and back to /signed-in."), sso),
    card("Forgotten password", reset),
  );
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
    card(
      "Authenticator (TOTP)",
      h("p", { class: "muted" }, "Enrol an authenticator for this account. If one is already enrolled, warden answers 409."),
      action("Set up an authenticator", async () => enrolStep({}, enrolArea), enrolNote, "quiet"),
      enrolNote,
      enrolArea,
      gap("mfaReset"),
    ),
    card("Change password", passwordForm),
  );
}
