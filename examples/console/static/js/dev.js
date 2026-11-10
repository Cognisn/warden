// Seeing password policies work without waiting: a recheck on demand, and (when
// the console was started with --dev-clock) a clock that moves forward.
//
// Both are for the sample only. warden schedules nothing, so a product runs the
// recheck on its own timetable (the command line, or Identity.password_recheck.run);
// and the clock is the ``clock`` argument of Identity, which a product leaves alone.

import { call, consoleSettings } from "./api.js";
import { action, card, field, form, h, input, json, outcome, status } from "./dom.js";

function counts(data) {
  return h(
    "div",
    {},
    status("ok", `Rechecked ${data.checked} password${data.checked === 1 ? "" : "s"}: ${data.matched} matched, ${data.flagged} newly required to change, ${data.sessions_ended} sessions ended.`),
    json(data),
  );
}

async function clockCard() {
  const area = h("div", {});
  const show = async () => {
    const answer = await call("GET", "/api/dev/clock", { anonymous: true });
    if (!answer.ok) return outcome(answer);
    const days = answer.data.offset_days;
    return status("info", days === 0 ? "The clock reads real time." : `The clock is ${days} day${Math.abs(days) === 1 ? "" : "s"} ${days > 0 ? "ahead of" : "behind"} real time.`);
  };
  const move = (days) => async () => {
    const answer = await call("PUT", "/api/dev/clock", { body: { days }, anonymous: true });
    area.replaceChildren(await show());
    return answer.ok ? null : outcome(answer);
  };
  const out = h("div", {});
  area.replaceChildren(await show());
  return card(
    "Development clock (DEVELOPMENT ONLY)",
    h("p", { class: "muted" }, "warden is using this clock for session lifetimes and password ages. Move it forward to pass a change period or its warning window, then sign in again: moving it ends your current session, as time would."),
    area,
    form(
      "inline",
      [field("Days ahead of real time", input("days", { type: "number", min: -3650, max: 3650, value: 0, required: true })), h("button", {}, "Set the clock")],
      async ({ days }) => {
        await move(Number(days))();
        return null;
      },
    ),
    h("p", {}, action("Add 30 days", async () => {
      const current = await call("GET", "/api/dev/clock", { anonymous: true });
      return move((current.ok ? current.data.offset_days : 0) + 30)();
    }, out, "quiet"), " ", action("Back to real time", move(0), out, "quiet")),
    out,
  );
}

export async function devScreen(main) {
  const settings = await consoleSettings();
  const out = h("div", {});
  main.replaceChildren(
    h("h2", {}, "Development"),
    h("p", { class: "muted" }, "Help for walking password policies at a gate without waiting. Nothing here is part of warden."),
    card(
      "Recheck now",
      h("p", { class: "muted" }, "Compares the sealed fingerprint of each password in use with the watch lists and flags matches for a forced change at next sign-in (needs a policy that enables the fingerprint, and the fingerprint key). A product runs this on its own schedule: warden passwords recheck, or Identity.password_recheck.run. Needs the passwords.manage permission."),
      action("Run a recheck", async () => {
        const answer = await call("POST", "/api/passwords/recheck");
        return answer.ok ? counts(answer.data) : outcome(answer);
      }, out),
      out,
    ),
    settings.dev_clock
      ? await clockCard()
      : card("Development clock", status("info", "Off. Start the console with --dev-clock to move time forward and walk password expiry: python -m examples.console serve --config <console.yaml> --dev-clock.")),
  );
}
