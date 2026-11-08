// Administration: users and roles, invitations, API keys, the session policy and
// single sign-on, all through warden's administration routes except the policy.

import { call, prefixes } from "./api.js";
import { action, card, field, form, h, input, json, outcome, select, status, table, when, zoned } from "./dom.js";
import { gap } from "./gaps.js";

const STATUSES = ["active", "suspended", "deactivated", "invited"];
const METHODS = ["password_and_sso", "sso_only", "passkey_only"];

function chosen(el, value) {
  el.value = value;
  return el;
}

// What warden says this deployment can do (GET <admin>/capabilities), so the
// screens disable what cannot work and say why. If the answer is missing, every
// action stays enabled and warden's own refusal (its 503) says what is wrong.
async function capabilities(admin) {
  const answer = await call("GET", `${admin}/capabilities`);
  if (answer.ok) return answer.data;
  return { mail_sender: true, invitations: true, password_reset: true, passkey_registration_link: true, single_sign_on: true, webauthn: true };
}

// Why an action that mails cannot be used, from the booleans alone.
function why(can, field) {
  if (!can.mail_sender) return "Unavailable: mail is not configured (the product installed no mail sender).";
  if (field === "invitations") return "Unavailable: the link setting http.accept_invitation_link is missing.";
  if (field === "password_reset") return "Unavailable: the link setting http.reset_password_link is missing.";
  if (!can.webauthn) return "Unavailable: WebAuthn is not configured (no relying party for this address).";
  return "Unavailable: the link setting http.passkey_registration_link is missing.";
}

// A button or form that cannot work here: disabled, with a short notice beside it.
function unavailable(control, allowed, reason) {
  if (allowed) return control;
  const parts = control.matches("button") ? [control] : control.querySelectorAll("button, input, select");
  for (const part of parts) part.disabled = true;
  return h("span", {}, control, " ", reason ? h("span", { class: "muted" }, reason) : null);
}

async function roleNames(admin) {
  const answer = await call("GET", `${admin}/roles`);
  return answer.ok ? answer.data : { roles: [], permissions: {} };
}

// Users and their roles

export async function usersScreen(main) {
  const { admin } = await prefixes();
  const registry = await roleNames(admin);
  const can = await capabilities(admin);
  const listArea = h("div", {});
  const detail = h("div", {});
  let filter = "";

  const load = async () => {
    const query = filter ? `?status=${encodeURIComponent(filter)}` : "";
    const answer = await call("GET", `${admin}/users${query}`);
    if (!answer.ok) return outcome(answer);
    return table(
      ["Email", "Name", "Status", "Sign-in method", "Password", "Created", ""],
      answer.data.users.map((u) =>
        h(
          "tr",
          {},
          h("td", {}, u.email),
          h("td", {}, u.display_name ?? ""),
          h("td", {}, u.status),
          h("td", {}, u.sign_in_method),
          h("td", {}, u.has_password ? "set" : "none"),
          h("td", {}, when(u.created_at)),
          h("td", { class: "actions" }, h("button", { type: "button", class: "quiet", onclick: () => show(u.id) }, "Manage")),
        ),
      ),
    );
  };

  const show = async (id) => {
    const answer = await call("GET", `${admin}/users/${id}`);
    if (!answer.ok) {
      detail.replaceChildren(outcome(answer));
      return;
    }
    const { user, roles, webauthn_credentials: keys } = answer.data;
    const out = h("div", {});
    const after = async (result, message) => {
      out.replaceChildren(outcome(result, message));
      listArea.replaceChildren(await load());
    };
    detail.replaceChildren(
      card(
        `Manage ${user.email}`,
        form(
          "inline",
          [field("Status", chosen(select("status", STATUSES.map((s) => [s])), user.status)), h("button", {}, "Set status")],
          async ({ status: value }) => after(await call("POST", `${admin}/users/${id}/status`, { body: { status: value } }), "status set"),
        ),
        form(
          "inline",
          [field("Sign-in method", chosen(select("sign_in_method", METHODS.map((m) => [m])), user.sign_in_method)), h("button", {}, "Set method")],
          async (values) => {
            const result = await call("POST", `${admin}/users/${id}/sign-in-method`, { body: values });
            await after(result, "method set");
            if (result.ok && result.data.has_passkey === false) {
              out.prepend(status("info", "This user holds no passkey, so they cannot sign in yet: send them a passkey registration link."));
            }
            return null;
          },
        ),
        h("p", { class: "muted" }, `Security keys and passkeys held: ${keys}.`),
        h(
          "p",
          {},
          unavailable(
            action("Send a password reset link", async () => outcome(await call("POST", `${admin}/users/${id}/password-reset`), "sent; see the outbox"), out, "quiet"),
            can.password_reset,
            why(can, "password_reset"),
          ),
          " ",
          unavailable(
            action("Send a passkey registration link", async () => outcome(await call("POST", `${admin}/users/${id}/passkey-registration`), "sent; see the outbox"), out, "quiet"),
            can.passkey_registration_link,
            why(can, "passkey_registration_link"),
          ),
        ),
        h(
          "p",
          {},
          action(
            "Reset second factors",
            async () => {
              const result = await call("DELETE", `${admin}/users/${id}/mfa`);
              await show(id);
              detail.prepend(outcome(result, "every second factor removed; the user's sessions have ended"));
              return null;
            },
            out,
            "danger",
          ),
          " ",
          h("span", { class: "muted" }, "Removes the authenticator, every security key and passkey and every recovery code, and ends the user's sessions. A passkey-only user then needs a registration link."),
        ),
        h(
          "p",
          {},
          action("Reset TOTP", async () => outcome(await call("DELETE", `${admin}/users/${id}/totp`), "TOTP reset; the user enrols again at their next sign-in"), out, "danger"),
          " ",
          h("span", { class: "muted" }, "For a user who has lost their authenticator and their recovery codes: removes both and ends the user's sessions. Security keys and passkeys stay."),
        ),
        h("h4", {}, "Roles"),
        roles.length === 0
          ? status("info", "No roles.")
          : table(
              ["Role", "Granted", "By", "Expires", ""],
              roles.map((r) =>
                h(
                  "tr",
                  {},
                  h("td", {}, r.role),
                  h("td", {}, when(r.granted_at)),
                  h("td", {}, r.granted_by ?? ""),
                  h("td", {}, when(r.expires_at)),
                  h(
                    "td",
                    { class: "actions" },
                    h(
                      "button",
                      {
                        type: "button",
                        class: "danger",
                        onclick: async () => {
                          const result = await call("DELETE", `${admin}/users/${id}/roles/${encodeURIComponent(r.role)}`);
                          await show(id);
                          detail.prepend(outcome(result, "role removed"));
                        },
                      },
                      "Remove",
                    ),
                  ),
                ),
              ),
            ),
        form(
          "inline",
          [
            field("Role", select("role", registry.roles.map((r) => [r.name]))),
            field("Expires (optional)", input("expires_at", { type: "datetime-local" })),
            h("button", {}, "Assign"),
          ],
          async ({ role, expires_at }) => {
            const result = await call("PUT", `${admin}/users/${id}/roles/${encodeURIComponent(role)}`, { body: { expires_at: zoned(expires_at) ?? null } });
            await show(id);
            detail.prepend(outcome(result, "role assigned"));
            return null;
          },
        ),
        h("p", { class: "muted" }, "Removing the last active administrator's role, or suspending them, is refused with 409. So is moving a user who holds security keys or passkeys to sso_only: reset their second factors first."),
        out,
      ),
    );
  };

  const filterForm = form(
    "inline",
    [field("Status", select("status", [["", "any"], ...STATUSES.map((s) => [s])])), h("button", { class: "quiet" }, "Filter")],
    async ({ status: value }) => {
      filter = value;
      listArea.replaceChildren(await load());
      return null;
    },
  );

  main.replaceChildren(
    h("h2", {}, "Users and roles"),
    card("Users", filterForm, listArea),
    detail,
    card("Roles the product defines", table(["Role", "Permissions", "Administrator"], registry.roles.map((r) => h("tr", {}, h("td", {}, r.name), h("td", {}, r.permissions.join(", ")), h("td", {}, r.administrator ? "yes" : ""))))),
  );
  listArea.replaceChildren(await load());
}

// Invitations

export async function invitationsScreen(main) {
  const { admin } = await prefixes();
  const registry = await roleNames(admin);
  const can = await capabilities(admin);
  const listArea = h("div", {});
  const out = h("div", {});

  const load = async () => {
    const answer = await call("GET", `${admin}/invitations`);
    if (!answer.ok) return outcome(answer);
    if (answer.data.invitations.length === 0) return status("info", "No pending invitations.");
    return table(
      ["Email", "Method", "Roles", "Expires", ""],
      answer.data.invitations.map((i) =>
        h(
          "tr",
          {},
          h("td", {}, i.user.email),
          h("td", {}, i.user.sign_in_method),
          h("td", {}, i.roles.map((r) => r.role).join(", ")),
          h("td", {}, when(i.expires_at)),
          h(
            "td",
            { class: "actions" },
            unavailable(
              action("Resend", async () => {
                const result = await call("POST", `${admin}/invitations/${i.user.id}/resend`);
                listArea.replaceChildren(await load());
                return outcome(result, "resent; see the outbox");
              }, out, "quiet"),
              can.invitations,
              "",
            ),
            action("Revoke", async () => {
              const result = await call("DELETE", `${admin}/invitations/${i.user.id}`);
              listArea.replaceChildren(await load());
              return outcome(result, "revoked");
            }, out, "danger"),
          ),
        ),
      ),
    );
  };

  const invite = form(
    "stack",
    [
      field("Email", input("email", { type: "email", required: true })),
      field("Display name (optional)", input("display_name")),
      field("Sign-in method", select("sign_in_method", METHODS.map((m) => [m]))),
      h("fieldset", {}, h("legend", {}, "Roles"), registry.roles.map((r) => h("label", { class: "check" }, h("input", { type: "checkbox", name: `role:${r.name}` }), r.name))),
      h("button", {}, "Invite"),
    ],
    async (values) => {
      const roles = Object.keys(values).filter((k) => k.startsWith("role:")).map((k) => ({ role: k.slice(5) }));
      const body = { email: values.email, sign_in_method: values.sign_in_method, roles };
      if (values.display_name) body.display_name = values.display_name;
      const result = await call("POST", `${admin}/invitations`, { body });
      listArea.replaceChildren(await load());
      return outcome(result, "invited; the link is in the outbox");
    },
  );

  main.replaceChildren(
    h("h2", {}, "Invitations"),
    card(
      "Invite someone",
      can.invitations ? null : status("info", `${why(can, "invitations")} Invitations cannot be sent or resent until it is set up.`),
      unavailable(invite, can.invitations, ""),
      h("p", { class: "muted" }, "Choose sso_only to make the invitee accept through single sign-on, or passkey_only to make them accept by registering a passkey (the link opens /accept, where they choose With a passkey)."),
    ),
    card("Pending", listArea, out),
  );
  listArea.replaceChildren(await load());
}

// API keys

export async function apiKeysScreen(main) {
  const { admin } = await prefixes();
  const registry = await roleNames(admin);
  const users = await call("GET", `${admin}/users?status=active`);
  const people = users.ok ? users.data.users : [];
  const listArea = h("div", {});
  const out = h("div", {});
  const tryArea = h("div", {});

  const load = async () => {
    const answer = await call("GET", `${admin}/api-keys`);
    if (!answer.ok) return outcome(answer);
    if (answer.data.api_keys.length === 0) return status("info", "No API keys.");
    return table(
      ["Name", "Hint", "User", "Scopes", "Expires", "Last used", "Revoked", ""],
      answer.data.api_keys.map((k) =>
        h(
          "tr",
          {},
          h("td", {}, k.name),
          h("td", {}, k.hint),
          h("td", {}, people.find((p) => p.id === k.user_id)?.email ?? k.user_id),
          h("td", {}, k.scopes.join(", ")),
          h("td", {}, when(k.expires_at)),
          h("td", {}, when(k.last_used_at)),
          h("td", {}, when(k.revoked_at)),
          h(
            "td",
            { class: "actions" },
            k.revoked_at
              ? null
              : action("Revoke", async () => {
                  const result = await call("DELETE", `${admin}/api-keys/${k.id}`);
                  listArea.replaceChildren(await load());
                  return outcome(result, "revoked");
                }, out, "danger"),
          ),
        ),
      ),
    );
  };

  const create = form(
    "stack",
    [
      field("User", select("user_id", people.map((p) => [p.id, p.email]))),
      field("Name", input("name", { required: true })),
      h("fieldset", {}, h("legend", {}, "Scopes"), Object.keys(registry.permissions).map((p) => h("label", { class: "check" }, h("input", { type: "checkbox", name: `scope:${p}` }), p))),
      field("Expires (optional)", input("expires_at", { type: "datetime-local" })),
      h("button", {}, "Create key"),
    ],
    async (values) => {
      const scopes = Object.keys(values).filter((k) => k.startsWith("scope:")).map((k) => k.slice(6));
      const body = { user_id: values.user_id, name: values.name, scopes };
      const expires = zoned(values.expires_at);
      if (expires) body.expires_at = expires;
      const result = await call("POST", `${admin}/api-keys`, { body });
      listArea.replaceChildren(await load());
      if (!result.ok) return outcome(result);
      return h("div", {}, status("ok", "Created. The key is shown once, never again:"), h("pre", {}, result.data.key), json(result.data.api_key));
    },
  );

  const tryKey = form(
    "stack",
    [
      field("API key", input("key", { autocomplete: "off", required: true })),
      field("Call", select("path", [["/api/me"], ["/api/notes"]])),
      h("button", {}, "Call with the key"),
    ],
    async ({ key, path }) => outcome(await call("GET", path, { key }), "answered with the key's permissions (its scopes intersected with the user's)"),
  );

  main.replaceChildren(
    h("h2", {}, "API keys"),
    card("Create", create),
    card("Keys", listArea, out),
    card("Make a call with a key", h("p", { class: "muted" }, "Sent as Authorization: Bearer <key>, not with your session."), tryKey, tryArea),
  );
  listArea.replaceChildren(await load());
}

// Session policy (the sample's own routes over Identity.policy)

const POLICY_FIELDS = [
  ["access_token_ttl_seconds", "number"],
  ["refresh_token_ttl_seconds", "number"],
  ["session_lifespan_seconds", "number"],
  ["refresh_reuse_grace_seconds", "number"],
  ["require_mfa", "checkbox"],
];

export async function policyScreen(main) {
  const area = h("div", {});
  const render = (answer) => {
    if (!answer.ok) return outcome(answer);
    const { policy, defaults } = answer.data;
    return h(
      "div",
      {},
      form(
        "stack",
        [
          POLICY_FIELDS.map(([name, type]) =>
            field(
              `${name} (configured ${defaults ? defaults[name] : "?"})`,
              type === "checkbox"
                ? h("input", { type: "checkbox", name, checked: policy[name] })
                : input(name, { type: "number", value: policy[name], min: 0 }),
            ),
          ),
          h("button", {}, "Save policy"),
        ],
        async (values) => {
          const body = {};
          for (const [name, type] of POLICY_FIELDS) {
            body[name] = type === "checkbox" ? name in values : Number(values[name]);
          }
          const result = await call("PUT", "/api/policy", { body });
          return outcome(result, "saved; shortening the lifespan cuts existing sessions off");
        },
      ),
      h("div", {}, action("Return to the configuration", async () => outcome(await call("POST", "/api/policy/reset"), "reset"), area, "quiet")),
    );
  };
  main.replaceChildren(h("h2", {}, "Session policy"), gap("policyRoute"), card("Policy", area));
  area.replaceChildren(render(await call("GET", "/api/policy")));
}

// Single sign-on settings and the configuration test

export async function ssoScreen(main) {
  const { admin } = await prefixes();
  const area = h("div", {});
  const out = h("div", {});
  const load = async () => {
    const answer = await call("GET", `${admin}/sso/settings`);
    if (!answer.ok) return outcome(answer);
    const s = answer.data;
    return h(
      "div",
      {},
      h("p", {}, "Callback URI to allow at the provider: ", h("code", {}, s.callback_url)),
      h("p", {}, `Client secret ${s.client_secret_set ? "is set" : "is not set"}.`),
      form(
        "stack",
        [
          h("label", { class: "check" }, h("input", { type: "checkbox", name: "enabled", checked: s.enabled }), "Enabled"),
          field("Issuer URL", input("issuer_url", { value: s.issuer_url ?? "" })),
          field("Client id", input("client_id", { value: s.client_id ?? "" })),
          field("Scopes (space separated)", input("scopes", { value: s.scopes.join(" ") })),
          field("Allowed email domains (comma separated)", input("allowed_email_domains", { value: s.allowed_email_domains.join(",") })),
          field("Provider preset (a label for setup guidance)", chosen(select("provider_preset", s.presets.map((p) => [p.preset, p.label])), s.provider_preset)),
          h("button", {}, "Save settings"),
        ],
        async (values) => {
          const body = {
            enabled: "enabled" in values,
            issuer_url: values.issuer_url || null,
            client_id: values.client_id || null,
            scopes: values.scopes.split(/\s+/).filter(Boolean),
            allowed_email_domains: values.allowed_email_domains.split(",").map((d) => d.trim()).filter(Boolean),
            provider_preset: values.provider_preset,
          };
          const result = await call("PUT", `${admin}/sso/settings`, { body });
          return outcome(result, "saved; turning single sign-on off ends every session it issued");
        },
      ),
      h("details", {}, h("summary", {}, "Presets"), json(s.presets)),
    );
  };
  const secret = form(
    "inline",
    [field("Client secret", input("client_secret", { type: "password", autocomplete: "off", required: true })), h("button", {}, "Store secret")],
    async (values) => outcome(await call("PUT", `${admin}/sso/client-secret`, { body: values }), "stored; it is never shown again"),
  );
  const unpin = form(
    "inline",
    [field("User id", input("user_id", { required: true })), h("button", { class: "quiet" }, "Remove subject pin")],
    async ({ user_id }) => outcome(await call("DELETE", `${admin}/sso/users/${encodeURIComponent(user_id)}/pin`), "pin removed"),
  );
  main.replaceChildren(
    h("h2", {}, "Single sign-on"),
    card("Settings", area),
    card(
      "Configuration test",
      h("p", { class: "muted" }, "Runs discovery, fetches the provider's keys and checks the client secret; nobody is signed in."),
      action("Test the configuration", async () => outcome(await call("POST", `${admin}/sso/test`), "report"), out),
      " ",
      action("Return to the configuration file's settings", async () => outcome(await call("POST", `${admin}/sso/settings/reset`), "reset"), out, "quiet"),
      out,
    ),
    card("Client secret", secret),
    card("Subject pins", unpin),
    gap("providerCa"),
  );
  area.replaceChildren(await load());
}
