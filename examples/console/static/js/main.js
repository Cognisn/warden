// The console's single page: a menu of screens chosen by the URL.
//
// Paths that warden's emailed links and the SSO completion link land on
// (/accept, /reset, /passkey, /signed-in) open their screen directly; everything else
// is chosen by the hash (#/notes, #/users, ...).

import { me, onSessionChange, signedIn } from "./api.js";
import { h, status } from "./dom.js";
import { gap } from "./gaps.js";
import { accountScreen, signInScreen, ssoLanding } from "./signin.js";
import { acceptScreen, outboxScreen, passkeyRegistrationScreen, resetScreen } from "./lifecycle.js";
import { notesScreen } from "./notes.js";
import { apiKeysScreen, invitationsScreen, policyScreen, ssoScreen, usersScreen } from "./admin.js";
import { anchorsScreen, auditScreen, keysScreen, syslogScreen } from "./audit.js";

// [hash, label, screen, permission needed to show it in the menu]
const MENU = [
  ["Sign-in", [
    ["#/signin", "Sign in", signInScreen, null],
    ["#/account", "Account", accountScreen, "signed-in"],
  ]],
  ["Product", [["#/notes", "Notes", notesScreen, "notes.read"]]],
  ["Lifecycle", [["#/outbox", "Outbox", outboxScreen, null]]],
  ["Administration", [
    ["#/users", "Users and roles", usersScreen, "users.manage"],
    ["#/invitations", "Invitations", invitationsScreen, "users.manage"],
    ["#/api-keys", "API keys", apiKeysScreen, "keys.manage"],
    ["#/policy", "Session policy", policyScreen, "policy.manage"],
    ["#/sso", "Single sign-on", ssoScreen, "sso.manage"],
  ]],
  ["Audit", [
    ["#/audit", "Events", auditScreen, "audit.read"],
    ["#/anchors", "Anchors", anchorsScreen, "audit.read"],
    ["#/syslog", "Syslog", syslogScreen, "syslog.manage"],
    ["#/keys", "Signing keys", keysScreen, null],
  ]],
];

const PATHS = {
  "/accept": acceptScreen,
  "/reset": resetScreen,
  "/passkey": passkeyRegistrationScreen,
  "/signed-in": ssoLanding,
};

let who = null;

function allowed(permission) {
  if (permission === null) return true;
  if (permission === "signed-in") return who !== null;
  return who !== null && who.permissions.includes(permission);
}

function drawMenu() {
  const hash = window.location.hash || "#/signin";
  document.getElementById("nav").replaceChildren(
    ...MENU.map(([heading, items]) => {
      const shown = items.filter(([, , , permission]) => allowed(permission));
      if (shown.length === 0) return "";
      return h(
        "div",
        {},
        h("h2", {}, heading),
        shown.map(([target, label]) => h("a", { href: target, class: hash === target ? "current" : "" }, label)),
      );
    }),
  );
  document.getElementById("who").textContent = who ? `${who.email} (${who.roles.join(", ") || "no roles"})` : "signed out";
}

async function route() {
  const main = document.getElementById("screen");
  const byPath = PATHS[window.location.pathname];
  const hash = window.location.hash || (signedIn() ? "#/account" : "#/signin");
  const entry = MENU.flatMap(([, items]) => items).find(([target]) => target === hash);
  drawMenu();
  try {
    if (byPath) await byPath(main);
    else if (entry) await entry[2](main);
    else main.replaceChildren(status("error", "No such screen."));
  } catch (error) {
    main.replaceChildren(status("error", String(error.message || error)));
  }
  main.focus();
}

onSessionChange(async () => {
  who = await me();
  drawMenu();
});

window.addEventListener("hashchange", () => {
  // A hash change on one of the link paths returns to the main page.
  if (PATHS[window.location.pathname]) window.history.replaceState(null, "", `/${window.location.hash}`);
  route();
});

// The sample's own "who am I" route stands in for one warden does not ship.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelector(".foot").append(" ", gap("whoAmI"));
  route();
});
