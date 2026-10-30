// Building the page without innerHTML: every value is set as text, so nothing
// a server or user supplies can become markup or script.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (name === "class") el.className = value;
    else if (name.startsWith("on")) el.addEventListener(name.slice(2), value);
    else if (value === true) el.setAttribute(name, "");
    else el.setAttribute(name, String(value));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function card(title, ...children) {
  return h("section", { class: "card" }, h("h3", {}, title), ...children);
}

export function status(kind, text) {
  return h("div", { class: `status ${kind}`, role: kind === "error" ? "alert" : "status" }, text);
}

export function json(value) {
  return h("pre", {}, JSON.stringify(value, null, 2));
}

export function field(label, input) {
  return h("label", {}, label, input);
}

export function input(name, attrs = {}) {
  return h("input", { name, ...attrs });
}

export function select(name, options, attrs = {}) {
  return h(
    "select",
    { name, ...attrs },
    options.map(([value, text]) => h("option", { value }, text ?? value)),
  );
}

// A form whose submit handler receives its values; the result area below it
// shows whatever the handler returns (a node, or nothing).
export function form(className, children, onsubmit) {
  const result = h("div", { class: "result" });
  const el = h("form", { class: className }, children, h("div", {}, result));
  el.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(el).entries());
    result.replaceChildren(status("info", "Working."));
    try {
      const shown = await onsubmit(values, el);
      result.replaceChildren(...(shown ? [shown] : []));
    } catch (error) {
      result.replaceChildren(status("error", String(error.message || error)));
    }
  });
  return el;
}

// A button that runs an action and shows its result in ``target``.
export function action(label, run, target, className = "") {
  return h(
    "button",
    {
      type: "button",
      class: className,
      onclick: async () => {
        target.replaceChildren(status("info", "Working."));
        try {
          const shown = await run();
          target.replaceChildren(...(shown ? [shown] : []));
        } catch (error) {
          target.replaceChildren(status("error", String(error.message || error)));
        }
      },
    },
    label,
  );
}

// The outcome of an API call: a status line with the HTTP status, then the body.
export function outcome(answer, success = "Done.") {
  if (answer.ok) {
    return h("div", {}, status("ok", `${answer.status}: ${success}`), answer.data ? json(answer.data) : null);
  }
  return h("div", {}, status("error", `${answer.status}: refused`), answer.data ? json(answer.data) : null);
}

export function table(headings, rows) {
  return h(
    "table",
    {},
    h("thead", {}, h("tr", {}, headings.map((text) => h("th", {}, text)))),
    h("tbody", {}, rows),
  );
}

export function when(iso) {
  return iso ? new Date(iso).toLocaleString("en-AU") : "";
}

// A zoned ISO 8601 time from a datetime-local input, or undefined when empty.
export function zoned(local) {
  return local ? new Date(local).toISOString() : undefined;
}
