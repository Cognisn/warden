// What warden's public surface does not offer, shown on the screen that needs
// it. Each is recorded as a question (numbered as in warden 0.1.0's release
// tracking) for warden's maintainers.

import { h } from "./dom.js";

export const GAPS = {
  policyRoute: {
    question: "Q7",
    text:
      "warden has no HTTP route for the session policy. This screen uses the sample's own " +
      "routes over Identity.policy, as any product would have to.",
  },
  anchorRoute: {
    question: "Q8",
    text:
      "warden has no HTTP route to anchor the chain head or to check exported anchors; " +
      "only the CLI (warden audit anchor, warden audit verify --anchors). This screen uses " +
      "the sample's own routes over warden.audit.anchor and verify_anchors.",
  },
  syslogSettings: {
    question: "Q9",
    text:
      "Syslog settings come only from start-up configuration: warden has no route or store " +
      "to change them at run time (the forwarder offers reconfigure, but nothing persists " +
      "it). This screen shows the effective settings read-only.",
  },
  providerCa: {
    question: "Q10",
    text:
      "warden has no setting for the identity provider's CA. The sample trusts the stub " +
      "provider's private CA through SSL_CERT_FILE for its own process.",
  },
  passkeyKind: {
    question: "Q29",
    text:
      "warden's list of a user's keys does not say whether each was registered with user " +
      "verification, so this screen cannot tell which discoverable key signs in alone. It " +
      "calls every discoverable key a passkey.",
  },
  whoAmI: {
    question: "Q11",
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
