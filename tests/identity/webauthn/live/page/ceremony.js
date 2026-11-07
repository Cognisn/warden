// The live check's page: a front end for warden's WebAuthn routes, written as
// the client guide describes, with the WebAuthn Level 3 JSON helpers.
//
// Each button runs one flow and writes what the page saw into #outcome as
// JSON: every call to warden (its path, the body's field names, the status
// and the answer) and the browser's error name if a ceremony failed.

const state = { access: null, challenge: null };
const token = new URLSearchParams(window.location.search).get("t");
const outcome = document.getElementById("outcome");
let seq = 0;

function field(id) {
  return document.getElementById(id).value;
}

async function call(steps, path, body, bearer) {
  const headers = { "content-type": "application/json" };
  if (bearer) {
    headers.authorization = `Bearer ${bearer}`;
  }
  const response = await fetch(`/auth${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let answer = null;
  try {
    answer = JSON.parse(text);
  } catch {
    answer = text;
  }
  const step = { path, sent: Object.keys(body), status: response.status, body: answer };
  steps.push(step);
  return step;
}

async function create(publicKey) {
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(publicKey);
  const credential = await navigator.credentials.create({ publicKey: options });
  return credential.toJSON();
}

async function get(publicKey) {
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(publicKey);
  const credential = await navigator.credentials.get({ publicKey: options });
  return credential.toJSON();
}

function keep(step) {
  if (step.body && typeof step.body === "object") {
    if (step.body.access_token) {
      state.access = step.body.access_token;
    }
    if (step.body.challenge) {
      state.challenge = step.body.challenge;
    }
  }
}

function withNickname(body) {
  const nickname = field("nickname");
  return nickname ? { ...body, nickname } : body;
}

// Register through an options route and a confirming route that share a body.
async function register(steps, optionsPath, confirmPath, body, bearer) {
  const options = await call(steps, optionsPath, body, bearer);
  if (options.status !== 200) {
    return;
  }
  const credential = await create(options.body.public_key);
  keep(await call(steps, confirmPath, withNickname({ ...body, credential }), bearer));
}

const flows = {
  "sign-in": async (steps) => {
    keep(await call(steps, "/sign-in", { email: field("email"), password: field("password") }));
  },
  "verify-key": async (steps) => {
    const body = { challenge: state.challenge };
    const options = await call(steps, "/webauthn/verify/options", body);
    if (options.status !== 200) {
      return;
    }
    const credential = await get(options.body.public_key);
    keep(await call(steps, "/webauthn/verify", { ...body, credential }));
  },
  "register-key": async (steps) => {
    await register(steps, "/webauthn/registration", "/webauthn/registration/confirm", {}, state.access);
  },
  "passkey-sign-in": async (steps) => {
    const options = await call(steps, "/passkey/options", {});
    if (options.status !== 200) {
      return;
    }
    const credential = await get(options.body.public_key);
    keep(await call(steps, "/passkey/sign-in", { credential }));
  },
  "accept-invitation": async (steps) => {
    await register(steps, "/invitations/accept/passkey/options", "/invitations/accept/passkey", { token });
  },
  "register-from-link": async (steps) => {
    await register(steps, "/passkey-registration/options", "/passkey-registration", { token });
  },
};

for (const [action, flow] of Object.entries(flows)) {
  document.getElementById(action).addEventListener("click", async () => {
    const steps = [];
    let error = null;
    try {
      await flow(steps);
    } catch (exc) {
      error = exc && exc.name ? exc.name : String(exc);
    }
    seq += 1;
    outcome.textContent = JSON.stringify({ action, steps, error });
    outcome.dataset.seq = String(seq);
  });
}

outcome.dataset.ready = "yes";
