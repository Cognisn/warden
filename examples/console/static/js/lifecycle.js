// Invitation acceptance, password reset, passkey registration links and the mail outbox.

import { call, prefixes } from "./api.js";
import { action, card, field, form, h, input, outcome, recoveryCodes, status, when } from "./dom.js";
import { create, described, supported } from "./webauthn.js";

function linkToken() {
  return new URLSearchParams(window.location.search).get("t") || "";
}

// Registering a passkey from a link's token, without signing in: ``begin``
// asks for the options, ``finish`` sends the browser's answer. Used by a
// passkey_only invitation and by an administrator's registration link; both
// may answer with recovery codes, shown here once.
function passkeyFromLink(token, { begin, finish }, label, done) {
  if (!supported()) return status("info", "This browser cannot use passkeys.");
  return form(
    "inline",
    [
      field("Nickname (optional)", input("nickname", { maxlength: 64, autocomplete: "off", placeholder: "Work laptop" })),
      h("button", {}, label),
    ],
    async ({ nickname }) => {
      const options = await begin();
      if (!options.ok) return outcome(options);
      let credential;
      try {
        credential = await create(options.data.public_key);
      } catch (error) {
        return status("error", described(error));
      }
      const answer = await finish({ token, credential, nickname: nickname || null });
      if (!answer.ok) return outcome(answer);
      return h(
        "div",
        {},
        status("ok", done(answer.data)),
        recoveryCodes(answer.data.recovery_codes),
        h("p", {}, "You are not signed in yet: ", h("a", { href: "/#/signin" }, "sign in with your passkey"), "."),
      );
    },
  );
}

// /accept?t=...: by password, through single sign-on, or with a passkey.
export async function acceptScreen(main) {
  const { auth } = await prefixes();
  const token = linkToken();
  if (!token) {
    main.replaceChildren(h("h2", {}, "Accept an invitation"), status("error", "This link has no invitation token."));
    return;
  }
  const byPassword = form(
    "stack",
    [
      field("Choose a password", input("password", { type: "password", autocomplete: "new-password", required: true })),
      h("button", {}, "Accept with a password"),
    ],
    async ({ password }) => {
      const answer = await call("POST", `${auth}/invitations/accept`, { body: { token, password }, anonymous: true });
      if (!answer.ok) return outcome(answer);
      return h("div", {}, status("ok", `Accepted for ${answer.data.email}.`), h("a", { href: "/#/signin" }, "Sign in"));
    },
  );
  // A real, top-level form post (urlencoded) to warden's SSO start: the token
  // goes in the body, never in a URL, and warden seals it into the login.
  const bySso = h(
    "form",
    { method: "post", action: `${auth}/sso/start` },
    h("input", { type: "hidden", name: "invitation", value: token }),
    h("button", { class: "quiet" }, "Accept with single sign-on"),
  );
  const byPasskey = passkeyFromLink(
    token,
    {
      begin: () => call("POST", `${auth}/invitations/accept/passkey/options`, { body: { token }, anonymous: true }),
      finish: (body) => call("POST", `${auth}/invitations/accept/passkey`, { body, anonymous: true }),
    },
    "Accept with a passkey",
    (data) => `Accepted for ${data.email}, with the passkey ${data.credential.nickname ?? "registered"}.`,
  );
  main.replaceChildren(
    h("h2", {}, "Accept an invitation"),
    card("By password", byPassword, h("p", { class: "muted" }, "An invitation for single sign-on only, or for a passkey only, is refused here with 409.")),
    card("By single sign-on", bySso),
    card(
      "With a passkey",
      h("p", { class: "muted" }, "For an invitation to sign in with a passkey only. The browser asks for a passkey that verifies you (a PIN or biometric); another kind of invitation is refused with 409."),
      byPasskey,
    ),
  );
}

// /reset?t=...: set a new password with a reset link.
export async function resetScreen(main) {
  const { auth } = await prefixes();
  const token = linkToken();
  const complete = form(
    "stack",
    [
      field("New password", input("new_password", { type: "password", autocomplete: "new-password", required: true })),
      h("button", {}, "Set password"),
    ],
    async ({ new_password }) => {
      const answer = await call("POST", `${auth}/password-reset/complete`, { body: { token, new_password }, anonymous: true });
      if (!answer.ok) return outcome(answer);
      return h("div", {}, status("ok", "Password set. Every session of this account has ended."), h("a", { href: "/#/signin" }, "Sign in"));
    },
  );
  main.replaceChildren(h("h2", {}, "Reset your password"), token ? card("New password", complete) : status("error", "This link has no reset token."));
}

// /passkey?t=...: register a passkey from an administrator's link
// (http.passkey_registration_link), without signing in.
export async function passkeyRegistrationScreen(main) {
  const { auth } = await prefixes();
  const token = linkToken();
  if (!token) {
    main.replaceChildren(h("h2", {}, "Register a passkey"), status("error", "This link has no registration token."));
    return;
  }
  main.replaceChildren(
    h("h2", {}, "Register a passkey"),
    card(
      "New passkey",
      h("p", { class: "muted" }, "An administrator sent this link. It works once, and sending another stops this one working."),
      passkeyFromLink(
        token,
        {
          begin: () => call("POST", `${auth}/passkey-registration/options`, { body: { token }, anonymous: true }),
          finish: (body) => call("POST", `${auth}/passkey-registration`, { body, anonymous: true }),
        },
        "Register a passkey",
        (data) => (data.credential.nickname ? `Registered the passkey ${data.credential.nickname}.` : "Registered the passkey."),
      ),
    ),
  );
}

// Links in a message that lead back into this app, so they can be followed.
function sameOriginLinks(text) {
  const found = [];
  for (const word of text.split(/\s+/)) {
    try {
      const url = new URL(word.replace(/[.,)]+$/, ""), window.location.origin);
      if (url.origin === window.location.origin && /^https?:/.test(word)) found.push(url.pathname + url.search);
    } catch {
      // Not a URL.
    }
  }
  return found;
}

export async function outboxScreen(main) {
  const list = h("div", {});
  const load = async () => {
    const answer = await call("GET", "/api/outbox", { anonymous: true });
    if (!answer.ok) return outcome(answer);
    const messages = answer.data.messages;
    if (messages.length === 0) return status("info", "No messages yet.");
    return h(
      "div",
      {},
      messages.map((m) =>
        card(
          `${m.subject}`,
          h("p", { class: "muted" }, `${m.kind} to ${m.to}, ${when(m.sent_at)}`),
          sameOriginLinks(m.text).map((link) => h("p", {}, h("a", { href: link }, `Follow ${link.split("?")[0]} link`))),
          h("pre", {}, m.text),
        ),
      ),
    );
  };
  main.replaceChildren(
    h("h2", {}, "Outbox"),
    h(
      "p",
      { class: "muted" },
      "Messages warden asked the sample's mail sender to deliver, kept in memory (newest first). " +
        "The outbox needs no sign-in, so an invitee can follow a link: acceptable only in a local sample.",
    ),
    action("Reload", load, list, "quiet"),
    list,
  );
  list.replaceChildren(await load());
}
