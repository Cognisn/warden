// Runs every case in docs/contract/password-rule-vectors.json through the
// packaged browser rules (src/warden/static/passwordrules.js) and exits
// non-zero on any disagreement. Standard library only: no npm packages.
//
// The script is run the way a browser runs a classic script: as source text in
// a fresh context holding nothing but a bare global object, so a missing global
// or a reach for the DOM fails here as it would in a page.
//
//   node tests/static/run_vectors.mjs [vectors.json [passwordrules.js]]

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..");
const vectorsPath = process.argv[2] ?? resolve(root, "docs", "contract", "password-rule-vectors.json");
const scriptPath = process.argv[3] ?? resolve(root, "src", "warden", "static", "passwordrules.js");

const context = vm.createContext({});
vm.runInContext(readFileSync(scriptPath, "utf8"), context, { filename: scriptPath });
const api = vm.runInContext("globalThis.WardenPasswordRules", context);
if (!api || typeof api.evaluate !== "function") {
  console.error("the script did not define WardenPasswordRules.evaluate");
  process.exit(1);
}

const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
const fields = ["code_points", "ok", "passphrase", "tier", "results"];
const failures = [];
const seen = new Set();
for (const c of vectors.cases) {
  if (seen.has(c.name)) failures.push(`${c.name}: duplicate case name`);
  seen.add(c.name);
  let got;
  try {
    // A JSON round trip: the answer comes from another realm, and only its data matters.
    got = JSON.parse(JSON.stringify(api.evaluate(c.password, vectors.policies[c.policy], c.user)));
  } catch (error) {
    failures.push(`${c.name}: threw ${error}`);
    continue;
  }
  for (const field of fields) {
    if (!isDeepStrictEqual(got[field], c.expected[field])) {
      failures.push(`${c.name}: ${field} is ${JSON.stringify(got[field])}, expected ${JSON.stringify(c.expected[field])}`);
    }
  }
}

const total = vectors.cases.length;
const failed = new Set(failures.map((line) => line.split(":")[0])).size;
if (total < 50) failures.push(`only ${total} cases in the vectors file, expected at least 50`);
if (failures.length > 0) {
  for (const line of failures) console.error(`FAIL ${line}`);
  console.error(`${failed} of ${total} cases disagree`);
  process.exit(1);
}
console.log(`${total} of ${total} cases agree`);
