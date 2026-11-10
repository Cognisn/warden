// Talking to the app: warden's routes and the sample's own, with fetch.
//
// The session follows warden's client rules:
// - the access and refresh tokens live only in this module's memory, never in
//   localStorage, sessionStorage or a cookie the page can read, so a reload
//   signs the user out;
// - a refresh token is used once: each refresh returns a new pair, and the old
//   refresh token must never be sent again (warden treats reuse as theft and
//   ends the whole session family);
// - only one refresh runs at a time; every caller that needs one waits for it;
// - the access token is renewed shortly before it expires, and a request
//   refused with 401 is retried once after a refresh;
// - a refused refresh ends the session in the page.

const session = {
  access: null,
  refresh: null,
  accessExpiresAt: 0,
  refreshExpiresAt: 0,
  timer: null,
};
const listeners = new Set();
let refreshing = null;
let settings = null;

export async function prefixes() {
  if (!settings) {
    const answer = await fetch("/api/console", { headers: { accept: "application/json" } });
    settings = await answer.json();
  }
  return settings.prefixes;
}

export async function syslogConfigured() {
  await prefixes();
  return settings.syslog;
}

// The console's own settings (GET /api/console): prefixes, and which optional
// features this run has.
export async function consoleSettings() {
  await prefixes();
  return settings;
}

export function onSessionChange(listener) {
  listeners.add(listener);
}

function changed() {
  for (const listener of listeners) listener(signedIn());
}

export function signedIn() {
  return session.access !== null;
}

export function sessionTimes() {
  return { accessExpiresAt: session.accessExpiresAt, refreshExpiresAt: session.refreshExpiresAt };
}

// Keep the token pair from a signed-in body (sign-in, MFA, refresh, handoff).
export function adopt(body) {
  const now = Date.now();
  session.access = body.access_token;
  session.refresh = body.refresh_token;
  session.accessExpiresAt = now + body.expires_in * 1000;
  session.refreshExpiresAt = now + body.refresh_expires_in * 1000;
  clearTimeout(session.timer);
  // Renew a little before expiry, but not in a tight loop for short lifetimes.
  const lead = Math.min(60, Math.max(5, body.expires_in / 5));
  session.timer = setTimeout(() => refresh(), Math.max(5, body.expires_in - lead) * 1000);
  changed();
}

export function forget() {
  clearTimeout(session.timer);
  session.access = null;
  session.refresh = null;
  session.accessExpiresAt = 0;
  session.refreshExpiresAt = 0;
  changed();
}

// One refresh at a time; the refresh token is cleared as soon as it is sent,
// so nothing can send it twice.
export function refresh() {
  if (refreshing) return refreshing;
  const token = session.refresh;
  if (!token) return Promise.resolve(false);
  session.refresh = null;
  refreshing = (async () => {
    try {
      const { auth } = await prefixes();
      const answer = await fetch(`${auth}/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ refresh_token: token }),
      });
      if (!answer.ok) {
        forget();
        return false;
      }
      adopt(await answer.json());
      return true;
    } catch {
      forget();
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

async function send(method, path, { body, form, bearer, raw } = {}) {
  const headers = { accept: "application/json" };
  let payload;
  if (form !== undefined) {
    payload = form;
  } else if (typeof body === "string") {
    headers["content-type"] = "text/plain; charset=utf-8";
    payload = body;
  } else if (body !== undefined) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  const response = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  if (raw) return { ok: response.ok, status: response.status, response };
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { text };
    }
  }
  return { ok: response.ok, status: response.status, data, response };
}

// A call with the session's access token, retried once after a refresh if the
// token was refused. ``key`` sends an API key instead, with no retry.
export async function call(method, path, options = {}) {
  if (options.key) return send(method, path, { ...options, bearer: options.key });
  if (options.anonymous || !signedIn()) return send(method, path, options);
  let answer = await send(method, path, { ...options, bearer: session.access });
  if (answer.status === 401 && (await refresh())) {
    answer = await send(method, path, { ...options, bearer: session.access });
  }
  return answer;
}

export async function signOut() {
  const { auth } = await prefixes();
  const answer = signedIn() ? await send("POST", `${auth}/sign-out`, { bearer: session.access }) : null;
  forget();
  return answer;
}

export async function me() {
  if (!signedIn()) return null;
  const answer = await call("GET", "/api/me");
  return answer.ok ? answer.data : null;
}
