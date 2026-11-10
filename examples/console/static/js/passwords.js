// Administration of password policies and watch lists, all through warden's
// administration routes (guarded by the sample's passwords.manage permission):
//
// - policies: create, edit every rule and tier, history, built-in list, the range
//   API and its mode, fingerprint, ending sessions, enforcing at sign-in, priorities;
// - role mapping, with the number of users it would move shown before saving;
// - a user's effective policy, pin and "change at next sign-in" (on the Users screen);
// - watch lists: create, give a reason, add exact passwords and terms, import the
//   shipped synthetic file, attach to policies;
// - the exposure report.
//
// warden returns counts, never entries, terms or hashes, so none is shown.

import { call, consoleSettings, prefixes } from "./api.js";
import { action, card, field, form, h, input, outcome, select, status, table, when } from "./dom.js";
import { gap } from "./gaps.js";

function chosen(el, value) {
  el.value = value;
  return el;
}

function whole(text) {
  const value = String(text ?? "").trim();
  return /^-?\d+$/.test(value) ? Number(value) : undefined;
}

// A 400 from a policy or watch list route names each field in ``errors``.
function refused(answer) {
  const errors = answer.data && Array.isArray(answer.data.errors) ? answer.data.errors : [];
  return h(
    "div",
    {},
    status("error", `${answer.status}: ${(answer.data && answer.data.detail) || "refused"}`),
    errors.length ? h("ul", {}, errors.map((e) => h("li", {}, e.field ? `${e.field}: ${e.message}` : e.message))) : null,
  );
}

function result(answer, success) {
  return answer.ok ? status("ok", `${answer.status}: ${success}`) : refused(answer);
}

async function listPolicies(admin) {
  const answer = await call("GET", `${admin}/password-policies`);
  if (!answer.ok) throw new Error(`The policies could not be listed (${answer.status}).`);
  return answer.data.policies;
}

async function listWatchLists(admin) {
  const answer = await call("GET", `${admin}/watch-lists`);
  if (!answer.ok) throw new Error(`The watch lists could not be listed (${answer.status}).`);
  return answer.data.watch_lists;
}

async function listRoles(admin) {
  const answer = await call("GET", `${admin}/roles`);
  return answer.ok ? answer.data.roles : [];
}

function summary(policy) {
  const parts = [`${policy.min_length}+ characters`];
  if (policy.min_classes > 0) parts.push(`${policy.min_classes} kinds`);
  if (policy.max_repeat !== null) parts.push(`repeat at most ${policy.max_repeat}`);
  if (policy.forbid_user_details) parts.push("no email or name");
  if (policy.passphrase) parts.push(`passphrase ${policy.passphrase.min_words} words`);
  if (policy.history_count > 0) parts.push(`remembers ${policy.history_count}`);
  return parts.join(", ");
}

function enforcement(policy) {
  const parts = [];
  if (policy.include_builtin) parts.push("built-in list");
  if (policy.watch_list_ids.length) parts.push(`${policy.watch_list_ids.length} watch list${policy.watch_list_ids.length === 1 ? "" : "s"}`);
  if (policy.hibp_enabled) parts.push(`range API (${policy.hibp_on_unavailable} when unavailable)`);
  if (policy.fingerprint_enabled) parts.push("fingerprint");
  if (policy.end_sessions_on_match) parts.push("ends sessions on a match");
  if (policy.enforce_on_sign_in) parts.push("enforced at sign-in");
  return parts.join(", ") || "none";
}

// One tier's row in the policy form.
function tierRow(tier, onRemove) {
  const row = h(
    "div",
    { class: "tier-row" },
    field("Tier name", input("tier_name", { value: tier.name, maxlength: 64, required: true })),
    h("label", { class: "check" }, h("input", { type: "checkbox", name: "tier_passphrase", checked: tier.passphrase }), "Met by a passphrase"),
    field("Min length", input("tier_min_length", { type: "number", min: 0, value: tier.min_length })),
    field("Min kinds", input("tier_min_classes", { type: "number", min: 0, max: 5, value: tier.min_classes })),
    field("Change after (days, blank for never)", input("tier_max_age_days", { type: "number", min: 1, value: tier.max_age_days ?? "" })),
    h("button", { type: "button", class: "quiet", onclick: () => onRemove(row) }, "Remove tier"),
  );
  return row;
}

function readTiers(el) {
  return [...el.querySelectorAll(".tier-row")].map((row) => {
    const get = (name) => row.querySelector(`[name="${name}"]`);
    const age = whole(get("tier_max_age_days").value);
    return {
      name: get("tier_name").value,
      passphrase: get("tier_passphrase").checked,
      min_length: whole(get("tier_min_length").value) ?? 0,
      min_classes: whole(get("tier_min_classes").value) ?? 0,
      max_age_days: age === undefined ? null : age,
    };
  });
}

function checkbox(name, label, checked, attrs = {}) {
  return h("label", { class: "check" }, h("input", { type: "checkbox", name, checked, ...attrs }), label);
}

// The create or edit form for one policy. ``policy`` is null for a new one.
function policyForm({ admin, policy, lists, fingerprint, onSaved }) {
  const fresh = policy === null;
  const base = policy ?? {
    name: "",
    description: "",
    priority: 100,
    min_length: 12,
    max_length: 1024,
    min_classes: 0,
    max_repeat: null,
    forbid_user_details: false,
    passphrase: null,
    tiers: [],
    warning_days: 14,
    history_count: 0,
    min_age_hours: 0,
    include_builtin: true,
    watch_list_ids: [],
    hibp_enabled: false,
    hibp_on_unavailable: "allow",
    fingerprint_enabled: false,
    end_sessions_on_match: false,
    enforce_on_sign_in: false,
    roles: [],
  };
  const phrase = base.passphrase ?? { min_length: 20, min_words: 4, relaxes_classes: false };
  const tiersArea = h("div", {});
  const addTier = (tier) => tiersArea.append(tierRow(tier, (row) => row.remove()));
  base.tiers.forEach(addTier);
  const preview = h("div", { class: "muted" });
  let formEl = null;

  const fingerprintBox = checkbox("fingerprint_enabled", "Seal a fingerprint of each password, so a recheck can find passwords that later appear on a list", base.fingerprint_enabled, { disabled: !fingerprint && !base.fingerprint_enabled });
  const notice = fingerprint
    ? null
    : status("info", "The fingerprint key is not configured (passwords.fingerprint_key_secret is unset), so no policy can enable the fingerprint and a recheck has nothing to compare. See the README, Password policies.");

  const body = (el) => {
    const data = new FormData(el);
    const text = (name) => String(data.get(name) ?? "");
    const values = {
      name: text("name"),
      description: text("description"),
      min_length: whole(text("min_length")),
      max_length: whole(text("max_length")),
      min_classes: whole(text("min_classes")) ?? 0,
      max_repeat: whole(text("max_repeat")) ?? null,
      passphrase: data.has("passphrase_on")
        ? { min_length: whole(text("passphrase_min_length")), min_words: whole(text("passphrase_min_words")), relaxes_classes: data.has("passphrase_relaxes_classes") }
        : null,
      tiers: readTiers(el),
      warning_days: whole(text("warning_days")),
      history_count: whole(text("history_count")) ?? 0,
      min_age_hours: whole(text("min_age_hours")) ?? 0,
      include_builtin: data.has("include_builtin"),
      watch_list_ids: lists.filter((l) => data.has(`list:${l.id}`)).map((l) => l.id),
      hibp_enabled: data.has("hibp_enabled"),
      hibp_on_unavailable: text("hibp_on_unavailable"),
      fingerprint_enabled: data.has("fingerprint_enabled"),
      end_sessions_on_match: data.has("end_sessions_on_match"),
      enforce_on_sign_in: data.has("enforce_on_sign_in"),
    };
    // Only when ticked: the route fails on this field (see the gap shown above the form).
    if (data.has("forbid_user_details")) values.forbid_user_details = true;
    // Leave out what the server needs absent rather than wrong.
    for (const key of ["min_length", "max_length", "warning_days"]) if (values[key] === undefined) delete values[key];
    return values;
  };

  const el = form(
    "stack wide",
    [
      gap("forbidUserDetails"),
      field("Name", input("name", { value: base.name, maxlength: 64, required: true })),
      field("Description", input("description", { value: base.description, maxlength: 500 })),
      fresh ? field("Priority (1 is the highest)", input("priority", { type: "number", min: 1, max: 10000, value: base.priority, required: true })) : null,
      h(
        "fieldset",
        {},
        h("legend", {}, "Rules"),
        field("Minimum length (characters)", input("min_length", { type: "number", min: 8, max: 1024, value: base.min_length, required: true })),
        field("Maximum length", input("max_length", { type: "number", min: 8, max: 1024, value: base.max_length })),
        field("Minimum kinds of character (0 to 5)", input("min_classes", { type: "number", min: 0, max: 5, value: base.min_classes })),
        field("No character repeated more than (blank for no limit)", input("max_repeat", { type: "number", min: 1, value: base.max_repeat ?? "" })),
        checkbox("forbid_user_details", "Refuse a password containing part of the user's email or name", base.forbid_user_details),
      ),
      h(
        "fieldset",
        {},
        h("legend", {}, "Passphrase"),
        checkbox("passphrase_on", "Recognise a passphrase", base.passphrase !== null),
        field("Passphrase minimum length", input("passphrase_min_length", { type: "number", min: 1, value: phrase.min_length })),
        field("Passphrase minimum words", input("passphrase_min_words", { type: "number", min: 1, value: phrase.min_words })),
        checkbox("passphrase_relaxes_classes", "A passphrase is excused the kinds-of-character rule", phrase.relaxes_classes),
      ),
      h(
        "fieldset",
        {},
        h("legend", {}, "Tiers and change periods (strongest first; the last must be met by every password the rules accept)"),
        tiersArea,
        h("button", { type: "button", class: "quiet", onclick: () => addTier({ name: "", passphrase: false, min_length: 0, min_classes: 0, max_age_days: null }) }, "Add a tier"),
        field("Warn this many days before a change is due", input("warning_days", { type: "number", min: 0, max: 365, value: base.warning_days })),
      ),
      h(
        "fieldset",
        {},
        h("legend", {}, "History and age"),
        field("Remember this many past passwords (0 for none)", input("history_count", { type: "number", min: 0, value: base.history_count })),
        field("Minimum hours before the user may change again (0 for none)", input("min_age_hours", { type: "number", min: 0, value: base.min_age_hours })),
      ),
      h(
        "fieldset",
        {},
        h("legend", {}, "Watch lists"),
        checkbox("include_builtin", "Check warden's built-in list of common passwords", base.include_builtin),
        lists.length
          ? lists.map((l) => checkbox(`list:${l.id}`, `${l.name} (${l.kind}): ${l.reason}`, base.watch_list_ids.includes(l.id)))
          : h("p", { class: "muted" }, "No watch lists yet. Create one under Watch lists, then attach it here."),
        checkbox("hibp_enabled", "Also ask the Pwned Passwords range API (sends a five-character hash prefix, never the password)", base.hibp_enabled),
        field("When the range API cannot be reached", chosen(select("hibp_on_unavailable", [["allow", "allow the password"], ["refuse", "refuse the password"]]), base.hibp_on_unavailable)),
      ),
      h(
        "fieldset",
        {},
        h("legend", {}, "After a match"),
        notice,
        fingerprintBox,
        checkbox("end_sessions_on_match", "A recheck match also ends the user's sessions", base.end_sessions_on_match),
        checkbox("enforce_on_sign_in", "Re-evaluate the password against the rules at each sign-in", base.enforce_on_sign_in),
      ),
      h(
        "div",
        { class: "actions-row" },
        h("button", { type: "submit" }, fresh ? "Create policy" : "Save policy"),
        h(
          "button",
          {
            type: "button",
            class: "quiet",
            onclick: async () => {
              const data = new FormData(formEl);
              const proposal = {};
              if (!fresh) proposal.policy_id = base.id;
              const priority = fresh ? whole(data.get("priority")) : base.priority;
              if (priority !== undefined && priority !== null) proposal.priority = priority;
              proposal.roles = base.roles;
              const answer = await call("POST", `${admin}/password-policies/affected-users`, { body: proposal });
              preview.replaceChildren(
                answer.ok
                  ? h("span", {}, `Users under this policy: ${answer.data.current} now, ${answer.data.proposed} with this priority and its mapped roles.`)
                  : refused(answer),
              );
            },
          },
          "Preview affected users",
        ),
        preview,
      ),
    ],
    async (_values, formElement) => {
      const payload = body(formElement);
      const answer = fresh
        ? await call("POST", `${admin}/password-policies`, { body: { ...payload, priority: whole(new FormData(formElement).get("priority")) } })
        : await call("PUT", `${admin}/password-policies/${base.id}`, { body: { ...payload, version: base.version } });
      if (answer.ok) await onSaved();
      return result(answer, fresh ? "policy created" : "policy saved");
    },
  );
  formEl = el;
  return el;
}

// Moving a policy up or down is a reorder of every non-default policy.
async function reorder(admin, policies, id, step) {
  const ordered = policies.filter((p) => !p.is_default).sort((a, b) => a.priority - b.priority).map((p) => p.id);
  const at = ordered.indexOf(id);
  const to = at + step;
  if (at < 0 || to < 0 || to >= ordered.length) return null;
  [ordered[at], ordered[to]] = [ordered[to], ordered[at]];
  return call("PUT", `${admin}/password-policy-order`, { body: { policy_ids: ordered } });
}

function roleMappingCard(admin, policies, roles, reload) {
  const out = h("div", {});
  const named = policies.filter((p) => !p.is_default);
  const rows = roles.map((role) => {
    const current = policies.find((p) => p.roles.includes(role.name));
    const target = select("policy_id", named.map((p) => [p.id, `${p.name} (priority ${p.priority})`]));
    const preview = h("span", { class: "muted" });
    const show = async () => {
      const chosenPolicy = named.find((p) => p.id === target.value);
      if (!chosenPolicy) return;
      const roleSet = [...new Set([...chosenPolicy.roles, role.name])];
      const answer = await call("POST", `${admin}/password-policies/affected-users`, {
        body: { policy_id: chosenPolicy.id, priority: chosenPolicy.priority, roles: roleSet },
      });
      preview.textContent = answer.ok ? `Users under ${chosenPolicy.name}: ${answer.data.current} now, ${answer.data.proposed} after mapping.` : "No preview.";
    };
    target.addEventListener("change", show);
    if (named.length) show();
    return h(
      "tr",
      {},
      h("td", {}, role.name),
      h("td", {}, current && !current.is_default ? current.name : "(the default policy)"),
      h(
        "td",
        { class: "actions" },
        named.length ? target : h("span", { class: "muted" }, "Create a policy first"),
        action(
          "Map",
          async () => {
            const answer = await call("PUT", `${admin}/password-policy-roles/${encodeURIComponent(role.name)}`, { body: { policy_id: target.value } });
            if (answer.ok) await reload();
            return result(answer, `${role.name} now maps to the chosen policy`);
          },
          out,
        ),
        action(
          "Remove mapping",
          async () => {
            const answer = await call("DELETE", `${admin}/password-policy-roles/${encodeURIComponent(role.name)}`);
            if (answer.ok) await reload();
            return result(answer, `${role.name} maps to no policy`);
          },
          out,
          "quiet",
        ),
        preview,
      ),
    );
  });
  return card(
    "Role mapping",
    h("p", { class: "muted" }, "A user is under their pinned policy; else the highest-priority policy mapped from a role they hold; else the default. The count shown is the users under that policy before and after the mapping."),
    table(["Role", "Maps to", ""], rows),
    out,
  );
}

export async function policiesScreen(main) {
  const { admin } = await prefixes();
  const settings = await consoleSettings();
  const out = h("div", {});
  const listArea = h("div", {});
  const editArea = h("div", {});
  const mappingArea = h("div", {});
  let policies = [];
  let lists = [];
  let roles = [];

  const draw = async () => {
    [policies, lists, roles] = await Promise.all([listPolicies(admin), listWatchLists(admin), listRoles(admin)]);
    const counts = await Promise.all(
      policies.map(async (p) => {
        const answer = await call("GET", `${admin}/password-policies/${p.id}/affected-users`);
        return answer.ok ? answer.data.affected_users : "?";
      }),
    );
    listArea.replaceChildren(
      table(
        ["Priority", "Name", "Rules", "Checks", "Tiers", "Roles", "Users", ""],
        policies.map((p, index) =>
          h(
            "tr",
            {},
            h("td", {}, p.is_default ? "default" : String(p.priority)),
            h("td", {}, p.name),
            h("td", {}, summary(p)),
            h("td", {}, enforcement(p)),
            h("td", {}, p.tiers.length ? p.tiers.map((t) => `${t.name}${t.max_age_days === null ? "" : ` (${t.max_age_days}d)`}`).join(", ") : "none"),
            h("td", {}, p.roles.join(", ")),
            h("td", {}, String(counts[index])),
            h(
              "td",
              { class: "actions" },
              h("button", { type: "button", class: "quiet", onclick: () => edit(p) }, "Edit"),
              p.is_default
                ? null
                : [
                    action("Up", async () => {
                      const answer = await reorder(admin, policies, p.id, -1);
                      await draw();
                      return answer ? result(answer, "moved up") : null;
                    }, out, "quiet"),
                    action("Down", async () => {
                      const answer = await reorder(admin, policies, p.id, 1);
                      await draw();
                      return answer ? result(answer, "moved down") : null;
                    }, out, "quiet"),
                    form(
                      "inline",
                      [input("priority", { type: "number", min: 1, max: 10000, value: p.priority, "aria-label": "Priority" }), h("button", { class: "quiet" }, "Set priority")],
                      async ({ priority }) => {
                        const answer = await call("PUT", `${admin}/password-policies/${p.id}/priority`, { body: { priority: whole(priority) } });
                        await draw();
                        return result(answer, "priority set");
                      },
                    ),
                    action("Delete", async () => {
                      const answer = await call("DELETE", `${admin}/password-policies/${p.id}`);
                      await draw();
                      return result(answer, "deleted");
                    }, out, "danger"),
                  ],
            ),
          ),
        ),
      ),
    );
    mappingArea.replaceChildren(roleMappingCard(admin, policies, roles, draw));
  };

  const edit = (policy) => {
    editArea.replaceChildren(
      card(
        policy ? `Edit ${policy.name}` : "New policy",
        policy && policy.is_default ? h("p", { class: "muted" }, "The default policy has no priority and cannot be deleted. It applies to anyone no other policy covers.") : null,
        policyForm({ admin, policy, lists, fingerprint: settings.fingerprint, onSaved: async () => { await draw(); } }),
      ),
    );
    editArea.scrollIntoView?.();
  };

  main.replaceChildren(
    h("h2", {}, "Password policies"),
    h("p", { class: "muted" }, "Rules, tiers and checks that decide what a password must be. The checklist at every place a password is set follows the policy that applies to that user."),
    card("Policies", listArea, h("p", {}, h("button", { type: "button", onclick: () => edit(null) }, "New policy")), out),
    editArea,
    mappingArea,
  );
  await draw();
}

// A user's effective policy, pin and "change at next sign-in", for the Users screen.
export function userPasswordCard(admin, userId) {
  const area = h("div", {});
  const out = h("div", {});
  const load = async () => {
    const [shown, policies] = await Promise.all([call("GET", `${admin}/users/${userId}/password-policy`), listPolicies(admin)]);
    if (!shown.ok) return outcome(shown);
    const state = shown.data;
    const named = policies.filter((p) => !p.is_default);
    const pin = select("policy_id", named.map((p) => [p.id, p.name]));
    const refresh = async () => area.replaceChildren(await load());
    const sourceText = { pin: "pinned on this user", role: `from the role ${state.role ?? ""}`, default: "the default policy" }[state.source] ?? state.source ?? "";
    return h(
      "div",
      {},
      state.applies
        ? h(
            "ul",
            {},
            h("li", {}, `Policy: ${state.policy ? state.policy.name : "none"} (${sourceText})`),
            h("li", {}, `Tier: ${state.tier ?? "not set yet"}`),
            h("li", {}, `Password set: ${state.password_set_at ? when(state.password_set_at) : "not recorded yet"}`),
            h("li", {}, `Expires: ${state.expires_at ? when(state.expires_at) : "never"}`),
            h("li", {}, state.change_required ? `Change required at next sign-in (${state.change_reason}${state.watch_list_source ? `, source ${state.watch_list_source}` : ""})` : "No change required"),
          )
        : status("info", "A password policy does not apply to this user (no password, or a different way of signing in)."),
      named.length
        ? h(
            "div",
            { class: "inline-actions" },
            pin,
            action("Pin this policy", async () => {
              const answer = await call("PUT", `${admin}/users/${userId}/password-policy`, { body: { policy_id: pin.value } });
              await refresh();
              return result(answer, "policy pinned");
            }, out, "quiet"),
          )
        : null,
      h(
        "div",
        { class: "inline-actions" },
        action("Remove the pin", async () => {
          const answer = await call("DELETE", `${admin}/users/${userId}/password-policy`);
          await refresh();
          return result(answer, "pin removed");
        }, out, "quiet"),
        action("Require a change at next sign-in", async () => {
          const answer = await call("PUT", `${admin}/users/${userId}/password-change-required`);
          await refresh();
          return result(answer, "the user must change their password at next sign-in");
        }, out),
        action("Clear the required change", async () => {
          const answer = await call("DELETE", `${admin}/users/${userId}/password-change-required`);
          await refresh();
          return result(answer, "no change required");
        }, out, "quiet"),
      ),
      out,
    );
  };
  load().then((node) => area.replaceChildren(node), (e) => area.replaceChildren(status("error", String(e.message || e))));
  return card("Password policy", area);
}

// Watch lists

function termsAndEntries(admin, list, out, reload) {
  const makeForm = (label, send, key, verb, placeholder, done) =>
    form(
      "stack",
      [
        field(label, h("textarea", { name: "lines", placeholder, rows: 4 })),
        h("button", { class: "quiet" }, verb),
      ],
      async ({ lines }) => {
        const values = lines.split(/\r?\n/).filter((line) => line.length > 0);
        if (values.length === 0) return status("info", "Nothing entered.");
        const answer = await send(values);
        if (answer.ok) await reload();
        const count = answer.ok ? (answer.data.added ?? answer.data.removed ?? 0) : 0;
        return result(answer, `${count} ${key} ${done}`);
      },
    );
  return h(
    "div",
    {},
    h("p", { class: "muted" }, "An exact password is hashed at once and never kept in the clear. A term refuses any password that contains it (3 to 64 characters). Neither is ever shown again: warden returns counts only."),
    makeForm("Exact passwords to add (one per line, up to 100)", (passwords) => call("POST", `${admin}/watch-lists/${list.id}/entries`, { body: { passwords } }), "passwords", "Add exact passwords", "synthetic-password-1", "added"),
    makeForm("Exact passwords to remove", (passwords) => call("POST", `${admin}/watch-lists/${list.id}/entries/removal`, { body: { passwords } }), "passwords", "Remove exact passwords", "", "removed"),
    makeForm("Terms to add (one per line)", (terms) => call("POST", `${admin}/watch-lists/${list.id}/terms`, { body: { terms } }), "terms", "Add terms", "examplecorp", "added"),
    makeForm("Terms to remove", (terms) => call("POST", `${admin}/watch-lists/${list.id}/terms/removal`, { body: { terms } }), "terms", "Remove terms", "", "removed"),
  );
}

async function manageList(admin, id, area, reload) {
  const answer = await call("GET", `${admin}/watch-lists/${id}`);
  if (!answer.ok) {
    area.replaceChildren(outcome(answer));
    return;
  }
  const list = answer.data.watch_list;
  const policies = await listPolicies(admin);
  const out = h("div", {});
  const again = async () => {
    await reload();
    await manageList(admin, id, area, reload);
  };
  area.replaceChildren(
    card(
      `Manage ${list.name}`,
      h("p", { class: "muted" }, `${list.kind} list: ${list.entry_count} exact passwords, ${list.term_count} terms${list.import_threshold ? `, threshold ${list.import_threshold}` : ""}${list.last_imported_at ? `, last imported ${when(list.last_imported_at)}` : ""}.`),
      form(
        "inline",
        [
          field("Name", input("name", { value: list.name, maxlength: 64, required: true })),
          field("Reason shown to a user whose password matches", input("reason", { value: list.reason, maxlength: 200, required: true })),
          h("button", { class: "quiet" }, "Save"),
        ],
        async (values) => {
          const saved = await call("PUT", `${admin}/watch-lists/${id}`, { body: values });
          if (saved.ok) await again();
          return result(saved, "watch list saved");
        },
      ),
      list.kind === "manual"
        ? termsAndEntries(admin, list, out, again)
        : h(
            "div",
            {},
            h("p", { class: "muted" }, "An imported list is replaced from a file in the Pwned Passwords downloader format (HASH:count per line). warden imports with its command line: warden --config <console.yaml> passwords import --list NAME --file FILE [--threshold N]. For the walk, this button imports the small synthetic file that ships with the sample (examples/console/data/synthetic-pwned.txt)."),
            action("Import the sample file", async () => {
              const imported = await call("POST", `/api/watch-lists/${id}/import-sample`);
              if (imported.ok) await again();
              return imported.ok ? status("ok", `${imported.status}: ${imported.data.imported} hashes imported`) : refused(imported);
            }, out),
          ),
      h(
        "fieldset",
        {},
        h("legend", {}, "Attached to these policies"),
        policies.map((p) => {
          const attached = list.policy_ids.includes(p.id);
          return h(
            "div",
            { class: "inline-actions" },
            h("span", {}, `${p.name}: ${attached ? "attached" : "not attached"}`),
            action(
              attached ? "Detach" : "Attach",
              async () => {
                const toggled = await call(attached ? "DELETE" : "PUT", `${admin}/password-policies/${p.id}/watch-lists/${id}`);
                await again();
                return result(toggled, attached ? "detached" : "attached");
              },
              out,
              "quiet",
            ),
          );
        }),
      ),
      out,
    ),
  );
}

export async function watchListsScreen(main) {
  const { admin } = await prefixes();
  const listArea = h("div", {});
  const detail = h("div", {});
  const out = h("div", {});

  const draw = async () => {
    const [lists, policies] = await Promise.all([listWatchLists(admin), listPolicies(admin)]);
    const names = new Map(policies.map((p) => [p.id, p.name]));
    listArea.replaceChildren(
      lists.length === 0
        ? status("info", "No watch lists yet. warden's built-in common-password list is still checked wherever a policy includes it.")
        : table(
            ["Name", "Kind", "Reason", "Passwords", "Terms", "Policies", ""],
            lists.map((l) =>
              h(
                "tr",
                {},
                h("td", {}, l.name),
                h("td", {}, l.kind),
                h("td", {}, l.reason),
                h("td", {}, String(l.entry_count)),
                h("td", {}, String(l.term_count)),
                h("td", {}, l.policy_ids.map((id) => names.get(id) ?? id).join(", ") || "none"),
                h(
                  "td",
                  { class: "actions" },
                  h("button", { type: "button", class: "quiet", onclick: () => manageList(admin, l.id, detail, draw) }, "Manage"),
                  action("Delete", async () => {
                    const answer = await call("DELETE", `${admin}/watch-lists/${l.id}`);
                    await draw();
                    detail.replaceChildren();
                    return answer.ok ? status("ok", "deleted") : answer.status === 409 ? status("error", "Not deleted: detach it from its policies first.") : refused(answer);
                  }, out, "danger"),
                ),
              ),
            ),
          ),
    );
  };

  main.replaceChildren(
    h("h2", {}, "Watch lists"),
    h("p", { class: "muted" }, "Passwords that are refused with a reason. A manual list holds exact passwords and terms you type in; an imported list is filled from a Pwned Passwords downloader file."),
    card("Lists", listArea, out),
    card(
      "New watch list",
      form(
        "inline",
        [
          field("Name", input("name", { maxlength: 64, required: true })),
          field("Reason shown to a user whose password matches", input("reason", { maxlength: 200, required: true })),
          field("Kind", select("kind", [["manual", "manual (exact passwords and terms)"], ["imported", "imported (HIBP-format file)"]])),
          h("button", {}, "Create"),
        ],
        async (values) => {
          const answer = await call("POST", `${admin}/watch-lists`, { body: values });
          if (answer.ok) {
            await draw();
            manageList(admin, answer.data.watch_list.id, detail, draw);
          }
          return result(answer, "watch list created");
        },
      ),
    ),
    detail,
  );
  await draw();
}

// The exposure report

export async function exposureScreen(main) {
  const { admin } = await prefixes();
  const [policies, lists] = await Promise.all([listPolicies(admin), listWatchLists(admin)]);
  const policyName = new Map(policies.map((p) => [p.id, p.name]));
  const listName = new Map(lists.map((l) => [l.id, l.name]));
  const people = new Map();
  const everyone = await call("GET", `${admin}/users`);
  if (everyone.ok) for (const u of everyone.data.users) people.set(u.id, u.email);
  const area = h("div", {});

  const page = async (after) => {
    const query = after ? `?limit=50&after=${encodeURIComponent(after)}` : "?limit=50";
    const answer = await call("GET", `${admin}/password-exposures${query}`);
    if (!answer.ok) return outcome(answer);
    const report = answer.data;
    const source = (s, id) => (id ? `${s}: ${listName.get(id) ?? id}` : s);
    return h(
      "div",
      {},
      h("p", {}, `${report.total} user${report.total === 1 ? "" : "s"} with a password found on a list.`),
      report.by_list.length
        ? table(["By list", "Users"], report.by_list.map((r) => h("tr", {}, h("td", {}, source(r.source, r.watch_list_id)), h("td", {}, String(r.users)))))
        : null,
      report.by_policy.length
        ? table(["By policy", "Users"], report.by_policy.map((r) => h("tr", {}, h("td", {}, r.policy_id ? policyName.get(r.policy_id) ?? r.policy_id : "(no policy)"), h("td", {}, String(r.users)))))
        : null,
      report.users.length
        ? table(
            ["User", "Found on", "Policy"],
            report.users.map((u) => h("tr", {}, h("td", {}, people.get(u.user_id) ?? u.user_id), h("td", {}, source(u.source, u.watch_list_id)), h("td", {}, u.policy_id ? policyName.get(u.policy_id) ?? u.policy_id : ""))),
          )
        : status("info", "Nobody. Run a recheck (Development screen) after adding to a list that a fingerprinted policy uses."),
      report.next ? action("Next page", async () => { area.replaceChildren(await page(report.next)); return null; }, h("div", {}), "quiet") : null,
    );
  };

  main.replaceChildren(
    h("h2", {}, "Exposure report"),
    h("p", { class: "muted" }, "Users whose password was found on a watch list when they set it, signed in, or were rechecked, and who have not yet changed it. Counts and identifiers only."),
    area,
  );
  area.replaceChildren(await page(null));
}
