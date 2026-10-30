// The audit trail: events with filters, CSV export, chain verification,
// anchors, syslog forwarding and the published signing keys.

import { call, prefixes, syslogConfigured } from "./api.js";
import { action, card, field, form, h, input, json, outcome, select, status, table, when, zoned } from "./dom.js";
import { gap } from "./gaps.js";

const FILTERS = ["action", "actor", "resource_type", "resource_id"];

function query(values) {
  const params = new URLSearchParams();
  for (const name of FILTERS) if (values[name]) params.append(name, values[name]);
  if (values.outcome) params.append("outcome", values.outcome);
  const since = zoned(values.since);
  const until = zoned(values.until);
  if (since) params.append("since", since);
  if (until) params.append("until", until);
  return params;
}

function eventRows(events) {
  return events.map((e) =>
    h(
      "tr",
      {},
      h("td", {}, String(e.id)),
      h("td", {}, when(e.occurred_at)),
      h("td", {}, e.action),
      h("td", {}, e.outcome),
      h("td", {}, e.actor ?? ""),
      h("td", {}, [e.resource_type, e.resource_id].filter(Boolean).join(" ")),
      h("td", {}, e.source_ip ?? ""),
      h("td", {}, h("details", {}, h("summary", {}, "details"), json(e.details))),
    ),
  );
}

// Fetch with the session's token and hand the body to the browser as a file.
async function download(path, filename) {
  const answer = await call("GET", path, { raw: true });
  if (!answer.ok) return status("error", `${answer.status}: refused`);
  const url = URL.createObjectURL(await answer.response.blob());
  const link = h("a", { href: url, download: filename }, `Save ${filename}`);
  link.click();
  return h("div", {}, status("ok", "Exported; the export itself is now an audit event (warden.audit.export)."), link);
}

export async function auditScreen(main) {
  const { audit } = await prefixes();
  const listArea = h("div", {});
  const more = h("div", {});
  const out = h("div", {});
  let current = new URLSearchParams();

  const page = async (beforeId) => {
    const params = new URLSearchParams(current);
    params.set("limit", "50");
    if (beforeId) params.set("before_id", String(beforeId));
    const answer = await call("GET", `${audit}/events?${params}`);
    if (!answer.ok) return { node: outcome(answer), next: null };
    return {
      node: answer.data.events.length ? table(["Row", "When", "Action", "Outcome", "Actor", "Resource", "Source", ""], eventRows(answer.data.events)) : status("info", "No matching events."),
      next: answer.data.next_before_id,
    };
  };

  const show = async () => {
    const first = await page(null);
    listArea.replaceChildren(first.node);
    pager(first.next);
  };

  const pager = (next) => {
    more.replaceChildren(
      next
        ? h("button", {
            type: "button",
            class: "quiet",
            onclick: async () => {
              const following = await page(next);
              listArea.append(following.node);
              pager(following.next);
            },
          }, "Older events")
        : "",
    );
  };

  const filters = form(
    "inline",
    [
      field("Since", input("since", { type: "datetime-local" })),
      field("Until", input("until", { type: "datetime-local" })),
      field("Action", input("action", { placeholder: "warden.identity.sign_in" })),
      field("Actor", input("actor")),
      field("Resource type", input("resource_type")),
      field("Resource id", input("resource_id")),
      field("Outcome", select("outcome", [["", "any"], ["success"], ["failure"]])),
      h("button", {}, "Filter"),
    ],
    async (values) => {
      current = query(values);
      await show();
      return null;
    },
  );

  main.replaceChildren(
    h("h2", {}, "Audit trail"),
    card(
      "Events",
      filters,
      h(
        "p",
        {},
        action("Export these as CSV", async () => download(`${audit}/export?${new URLSearchParams([...current, ["format", "csv"]])}`, "audit-export.csv"), out, "quiet"),
        " ",
        action("Verify the chain", async () => outcome(await call("GET", `${audit}/verify`), "chain checked"), out, "quiet"),
      ),
      out,
      listArea,
      more,
    ),
  );
  await show();
}

export async function anchorsScreen(main) {
  const { audit } = await prefixes();
  const listArea = h("div", {});
  const out = h("div", {});

  const load = async () => {
    const answer = await call("GET", `${audit}/events?action=warden.audit.anchor&limit=50`);
    if (!answer.ok) return outcome(answer);
    if (answer.data.events.length === 0) return status("info", "No anchors yet.");
    return table(["Row", "When", "Action", "Outcome", "Actor", "Resource", "Source", ""], eventRows(answer.data.events));
  };

  // The round trip a SIEM makes possible: export the anchor rows as NDJSON (as
  // a SIEM would hold them), then check them against the chain.
  const verifyExported = async () => {
    const exported = await call("GET", `${audit}/export?format=ndjson&action=warden.audit.anchor`, { raw: true });
    if (!exported.ok) return status("error", `${exported.status}: export refused`);
    const text = await exported.response.text();
    return outcome(await call("POST", "/api/audit/anchors/verify", { body: text }), "anchors checked against the chain");
  };

  const paste = form(
    "stack",
    [field("Anchors exported from a SIEM (NDJSON or forwarded syslog lines)", h("textarea", { name: "lines", rows: 6 })), h("button", { class: "quiet" }, "Check these anchors")],
    async ({ lines }) => outcome(await call("POST", "/api/audit/anchors/verify", { body: lines }), "anchors checked"),
  );

  main.replaceChildren(
    h("h2", {}, "Anchors"),
    gap("anchorRoute"),
    card(
      "Anchor the chain head",
      h("p", { class: "muted" }, "Appends a signed attestation of the committed head (warden.audit.anchor). Forwarded to syslog, it lets a SIEM catch a replaced chain."),
      action("Anchor now", async () => {
        const result = await call("POST", "/api/audit/anchor");
        listArea.replaceChildren(await load());
        return outcome(result, "anchored");
      }, out),
      " ",
      action("Export the anchors and check them", verifyExported, out, "quiet"),
      out,
    ),
    card("Anchors in the trail", listArea),
    card("Check an export", paste),
  );
  listArea.replaceChildren(await load());
}

export async function syslogScreen(main) {
  const { audit } = await prefixes();
  const out = h("div", {});
  if (!(await syslogConfigured())) {
    main.replaceChildren(h("h2", {}, "Syslog"), status("info", "Syslog forwarding is not configured (warden.syslog.enabled is false)."), gap("syslogSettings"));
    return;
  }
  const settings = await call("GET", "/api/syslog/settings");
  const state = h("div", {});
  const refresh = async () => outcome(await call("GET", `${audit}/syslog/status`), "forwarder status");
  main.replaceChildren(
    h("h2", {}, "Syslog"),
    card("Forwarder status", action("Reload status", refresh, state, "quiet"), state),
    card("Test message", h("p", { class: "muted" }, "Sent over a fresh connection with the forwarder's settings, and audited (warden.syslog.test_sent)."), action("Send a test message", async () => outcome(await call("POST", `${audit}/syslog/test`), "sent"), out), out),
    card("Settings in effect", gap("syslogSettings"), outcome(settings, "from start-up configuration")),
  );
  state.replaceChildren(await refresh());
}

export async function keysScreen(main) {
  const { keys } = await prefixes();
  const live = await call("GET", `${keys}/jwks.json`, { anonymous: true });
  const historical = await call("GET", `${keys}/jwks-historical.json`, { anonymous: true });
  main.replaceChildren(
    h("h2", {}, "Published signing keys"),
    h("p", { class: "muted" }, "Public, unauthenticated and cacheable for five minutes, so other components can verify warden's tokens and checkpoints without being able to sign. Rotate with warden keys rotate."),
    card("Live keys (jwks.json)", outcome(live, "keys")),
    card("With retired keys (jwks-historical.json)", outcome(historical, "keys")),
  );
}
