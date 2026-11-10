// The live password checklist: what a product shows wherever a user sets a password.
//
// Three things happen as the user types, and none needs the password to leave the
// page until a pause:
//
// 1. at once, in the browser: each rule from the policy description is checked
//    (passwordrules.js, tested against warden's vectors), with the passphrase
//    path ("Passphrase: 3 of 4 words") and the tier with its change period;
// 2. after the typing pauses (debounced), the password goes to warden's check
//    route, which alone knows the watch lists, and the answer shows whether it
//    matched one and why;
// 3. on submit, warden decides. The checklist is feedback, never the authority:
//    the server refuses what the rules refuse, and its refusal is shown below.
//
// Each set point (the signed-in change, an invitation, a reset, a forced change)
// has its own pair of routes; the caller passes them as ``load`` and ``check``.

import { h, status } from "./dom.js";
import { evaluate, passphraseLine, ruleLabel, tierLine } from "./passwordrules.js";

// How long the typing must pause before the check route is called.
export const PAUSE_MS = 500;

function ruleItem(result, rules, known) {
  const pending = !known && (result.code === "no_email" || result.code === "no_display_name");
  const kind = pending ? "pending" : result.passed ? "met" : "unmet";
  const lead = pending ? "Checked when you save" : result.passed ? (result.waived ? "Excused by the passphrase" : "Met") : "Not yet";
  return h("li", { class: `rule ${kind}` }, h("span", { class: "mark" }, `${lead}: `), ruleLabel(result.code, rules));
}

// The checklist and its password input. ``load()`` answers the policy route
// (``{ok, data: {rules}}``) and ``check(password)`` the check route; ``user()``
// gives {email, display_name} where the page knows them, for the user-detail rules.
export function livePassword({ load, check, user = () => null, name = "new_password", label = "New password" }) {
  const list = h("ul", { class: "rules", "aria-live": "polite" });
  const phrase = h("p", { class: "muted" });
  const tier = h("p", { class: "muted" });
  const watch = h("div", { class: "watch", "aria-live": "polite" });
  const body = h("div", { class: "checklist" }, status("info", "Loading the password policy."));
  const input = h("input", { name, type: "password", autocomplete: "new-password", required: true });
  let rules = null;
  let timer = null;
  let ticket = 0;

  const known = () => {
    const who = user();
    return Boolean(who && who.email);
  };

  const redraw = () => {
    if (!rules) return;
    const evaluation = evaluate(input.value, rules, user());
    list.replaceChildren(...evaluation.results.map((result) => ruleItem(result, rules, known())));
    phrase.textContent = passphraseLine(rules, evaluation) ?? "";
    tier.textContent = tierLine(rules, evaluation) ?? "";
  };

  const ask = async () => {
    const mine = ++ticket;
    const password = input.value;
    if (!password) {
      watch.replaceChildren();
      return;
    }
    watch.replaceChildren(h("p", { class: "muted" }, "Checking the watch lists."));
    let answer;
    try {
      answer = await check(password);
    } catch {
      answer = { ok: false, status: 0 };
    }
    // A later keystroke made this answer stale.
    if (mine !== ticket) return;
    if (!answer.ok) {
      const why = answer.status === 429 ? "too many checks just now; slow down" : `HTTP ${answer.status}`;
      watch.replaceChildren(h("p", { class: "muted" }, `The watch list check is unavailable (${why}). Saving is still checked by warden.`));
      return;
    }
    const found = answer.data;
    if (found.watch_list) {
      watch.replaceChildren(status("error", `On a watch list: ${found.watch_list.reason}`));
    } else if (found.watch_list_unavailable) {
      watch.replaceChildren(h("p", { class: "muted" }, "The online breached-password check could not be reached, so only the other lists were checked."));
    } else {
      watch.replaceChildren(h("p", { class: "good" }, "Not on any watch list."));
    }
  };

  input.addEventListener("input", () => {
    redraw();
    ++ticket;
    watch.replaceChildren();
    clearTimeout(timer);
    if (input.value) timer = setTimeout(ask, PAUSE_MS);
  });

  load().then(
    (answer) => {
      if (!answer.ok) {
        body.replaceChildren(status("error", `The password policy could not be loaded (HTTP ${answer.status}).`));
        return;
      }
      rules = answer.data.rules;
      const extra = [];
      if (answer.data.history_count > 0) {
        extra.push(h("p", { class: "muted" }, `Not one of your last ${answer.data.history_count} passwords (checked when you save).`));
      }
      body.replaceChildren(list, phrase, tier, ...extra, watch);
      redraw();
    },
    () => body.replaceChildren(status("error", "The password policy could not be loaded.")),
  );

  const node = h("div", { class: "live-password" }, h("label", {}, label, input), body);
  return node;
}

// What warden says when it refuses a new password (400, ``failures``).
export function refusal(answer) {
  const failures = answer.data && Array.isArray(answer.data.failures) ? answer.data.failures : [];
  return h(
    "div",
    {},
    status("error", `${answer.status}: the password was not accepted`),
    failures.length
      ? h("ul", { class: "rules" }, failures.map((failure) => h("li", { class: "rule unmet" }, h("span", { class: "mark" }, `${failure.code}: `), failure.message)))
      : null,
  );
}
