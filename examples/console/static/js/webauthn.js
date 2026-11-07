// The browser side of passkeys and security keys (WebAuthn).
//
// warden sends ceremony options as WebAuthn's JSON form (binary values in
// base64url) and takes the browser's answer the same way. Browsers with the
// Level 3 helpers convert both directions themselves
// (PublicKeyCredential.parseCreationOptionsFromJSON,
// parseRequestOptionsFromJSON and the credential's toJSON); for a browser
// without them, this module converts by hand.
//
// Nothing here keeps or logs a credential, a challenge or a signature: each
// answer goes straight to warden and is forgotten.

function fromBase64url(text) {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function toBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function descriptors(list) {
  return (list || []).map((d) => ({ ...d, id: fromBase64url(d.id) }));
}

export function supported() {
  return typeof window.PublicKeyCredential === "function" && Boolean(navigator.credentials);
}

// Whether the browser can offer passkeys in the username field's autofill.
export async function conditionalAvailable() {
  if (!supported() || typeof PublicKeyCredential.isConditionalMediationAvailable !== "function") return false;
  try {
    return await PublicKeyCredential.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

function creationOptions(json) {
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
    return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  }
  return {
    ...json,
    challenge: fromBase64url(json.challenge),
    user: { ...json.user, id: fromBase64url(json.user.id) },
    excludeCredentials: descriptors(json.excludeCredentials),
  };
}

function requestOptions(json) {
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
    return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  }
  return { ...json, challenge: fromBase64url(json.challenge), allowCredentials: descriptors(json.allowCredentials) };
}

function answerJSON(credential) {
  if (typeof credential.toJSON === "function") return credential.toJSON();
  const r = credential.response;
  const response = { clientDataJSON: toBase64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = toBase64url(r.attestationObject);
    if (typeof r.getTransports === "function") response.transports = r.getTransports();
  } else {
    response.authenticatorData = toBase64url(r.authenticatorData);
    response.signature = toBase64url(r.signature);
    if (r.userHandle) response.userHandle = toBase64url(r.userHandle);
  }
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function unsupported() {
  return new Error("This browser does not support passkeys or security keys.");
}

// Words for the errors a browser raises, so a cancelled prompt reads plainly.
export function described(error) {
  if (error && error.name === "NotAllowedError") return "The browser's prompt was cancelled or timed out.";
  if (error && error.name === "InvalidStateError") return "This key is already registered for this account.";
  if (error && error.name === "SecurityError") return "The browser refused this site as the relying party (use http://localhost, not 127.0.0.1).";
  return String((error && error.message) || error);
}

// navigator.credentials.create() for warden's registration options; the answer as JSON.
export async function create(publicKey) {
  if (!supported()) throw unsupported();
  const credential = await navigator.credentials.create({ publicKey: creationOptions(publicKey) });
  return answerJSON(credential);
}

// navigator.credentials.get() for warden's sign-in options; the answer as JSON.
// ``mediation: "conditional"`` waits for the user to pick a passkey from the
// username field's autofill; ``signal`` aborts the wait.
export async function get(publicKey, { mediation, signal } = {}) {
  if (!supported()) throw unsupported();
  const request = { publicKey: requestOptions(publicKey) };
  if (mediation) request.mediation = mediation;
  if (signal) request.signal = signal;
  const credential = await navigator.credentials.get(request);
  return answerJSON(credential);
}
