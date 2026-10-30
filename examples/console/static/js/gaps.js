// What warden's public surface does not offer, shown on the screen that needs
// it. Each is recorded as a question for warden's maintainers; the console
// works around none of them.

import { h } from "./dom.js";

export const GAPS = {
  mfaReset: {
    question: "Q?",
    text:
      "warden has no way to reset or remove a user's TOTP enrolment, or to issue new " +
      "recovery codes, either over HTTP or in its public Python API. A user who loses " +
      "their authenticator and their recovery codes cannot be helped.",
  },
  policyRoute: {
    question: "Q?",
    text:
      "warden has no HTTP route for the session policy. This screen uses the sample's own " +
      "routes over Identity.policy, as any product would have to.",
  },
  anchorRoute: {
    question: "Q?",
    text:
      "warden has no HTTP route to anchor the chain head or to check exported anchors; " +
      "only the CLI (warden audit anchor, warden audit verify --anchors). This screen uses " +
      "the sample's own routes over warden.audit.anchor and verify_anchors.",
  },
  syslogSettings: {
    question: "Q?",
    text:
      "Syslog settings come only from start-up configuration: warden has no route or store " +
      "to change them at run time (the forwarder offers reconfigure, but nothing persists " +
      "it). This screen shows the effective settings read-only.",
  },
  providerCa: {
    question: "Q?",
    text:
      "warden has no setting for the identity provider's CA. The sample trusts the stub " +
      "provider's private CA through SSL_CERT_FILE for its own process.",
  },
  whoAmI: {
    question: "Q?",
    text:
      "warden's routes have no 'who am I' route; the sample answers it from require_user " +
      "(GET /api/me).",
  },
};

export function gap(name) {
  const entry = GAPS[name];
  return h(
    "div",
    { class: "gap" },
    h("strong", {}, `Gap (Skuld ${entry.question}): `),
    entry.text,
  );
}
