// The sample product's notes: permission-gated, owner-scoped and audited.

import { call, me } from "./api.js";
import { card, field, form, h, input, outcome, status, table, when } from "./dom.js";

export async function notesScreen(main) {
  const who = await me();
  const listArea = h("div", {});
  const editArea = h("div", {});

  const load = async () => {
    const answer = await call("GET", "/api/notes");
    if (!answer.ok) return outcome(answer);
    const notes = answer.data.notes;
    if (notes.length === 0) return status("info", "No notes yet.");
    return table(
      ["Title", "Owner", "Created", ""],
      notes.map((n) =>
        h(
          "tr",
          {},
          h("td", {}, n.title),
          h("td", {}, n.owner === who?.user_id ? "you" : n.owner),
          h("td", {}, when(n.created_at)),
          h(
            "td",
            { class: "actions" },
            h("button", { type: "button", class: "quiet", onclick: () => edit(n) }, "Edit"),
            h(
              "button",
              {
                type: "button",
                class: "danger",
                onclick: async () => {
                  const answer = await call("DELETE", `/api/notes/${n.id}`);
                  editArea.replaceChildren(outcome(answer, "deleted"));
                  listArea.replaceChildren(await load());
                },
              },
              "Delete",
            ),
          ),
        ),
      ),
    );
  };

  const edit = (note) => {
    editArea.replaceChildren(
      card(
        `Edit "${note.title}"`,
        form(
          "stack",
          [
            field("Title", input("title", { value: note.title, required: true })),
            field("Body", h("textarea", { name: "body" }, note.body)),
            h("button", {}, "Save"),
          ],
          async (values) => {
            const answer = await call("PUT", `/api/notes/${note.id}`, { body: values });
            listArea.replaceChildren(await load());
            return outcome(answer, "saved");
          },
        ),
        h("p", { class: "muted" }, "Editing someone else's note needs notes.admin: the product's resource-scope hook refuses it with 403 otherwise."),
      ),
    );
  };

  const create = form(
    "stack",
    [field("Title", input("title", { required: true })), field("Body", h("textarea", { name: "body" })), h("button", {}, "Add note")],
    async (values) => {
      const answer = await call("POST", "/api/notes", { body: values });
      listArea.replaceChildren(await load());
      return outcome(answer, "created");
    },
  );

  main.replaceChildren(
    h("h2", {}, "Notes"),
    h(
      "p",
      { class: "muted" },
      "The sample product's own resource. Reading needs notes.read; writing needs notes.write; " +
        "changing a note you do not own also needs notes.admin. Every change is a product audit event (console.note.*).",
    ),
    card("Notes", listArea),
    editArea,
    card("New note", create),
  );
  listArea.replaceChildren(await load());
}
