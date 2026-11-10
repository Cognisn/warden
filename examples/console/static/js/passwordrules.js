// warden's password rules, evaluated in the browser from a policy description.
//
// The description is the ``rules`` object the policy routes return (and
// docs/contract/password-rule-vectors.json holds test cases for): a versioned
// shape that carries everything needed, so nothing here is a copy of any
// product's policy. This module has no DOM and no network, so it runs the same
// in a browser and under Node, where tests/examples runs every case in the
// vectors file through it.
//
// Counting is by Unicode code point after NFC, as the server counts; a browser's
// String.length counts an emoji twice, so this never uses it for the rules.

const SUPPORTED_VERSION = 1;

export function normalise(text) {
  return text.normalize("NFC");
}

function codePoints(text) {
  return [...text];
}

// One regular expression per class, built from the Unicode general categories
// the description names (for example lowercase: ["Ll"]).
function classMatchers(classes) {
  return Object.entries(classes).map(([name, categories]) => [
    name,
    new RegExp(categories.map((category) => `\\p{${category}}`).join("|"), "u"),
  ]);
}

function countClasses(points, matchers) {
  const found = new Set();
  for (const ch of points) {
    for (const [name, matcher] of matchers) {
      if (matcher.test(ch)) {
        found.add(name);
        break;
      }
    }
  }
  return found.size;
}

function longestRun(points) {
  let longest = 0;
  let run = 0;
  let previous = null;
  for (const ch of points) {
    run = ch === previous ? run + 1 : 1;
    previous = ch;
    longest = Math.max(longest, run);
  }
  return longest;
}

// Words are the non-empty pieces left by splitting on the separators.
export function countWords(text, separators) {
  let count = 0;
  let inWord = false;
  for (const ch of text) {
    if (separators.includes(ch)) {
      inWord = false;
    } else if (!inWord) {
      inWord = true;
      count += 1;
    }
  }
  return count;
}

// Runs of letters and digits.
function pieces(text) {
  return text.match(/[\p{L}\p{N}]+/gu) ?? [];
}

function detailTokens(text, whole, minimum) {
  if (!text) return [];
  const lowered = normalise(text).toLowerCase();
  const tokens = new Set(pieces(lowered));
  if (whole) tokens.add(lowered);
  return [...tokens].filter((token) => codePoints(token).length >= minimum);
}

function localPart(email) {
  if (!email || !email.includes("@")) return email;
  return email.slice(0, email.lastIndexOf("@"));
}

function meets(tier, length, classes, passphrase) {
  if (tier.passphrase) return passphrase;
  return length >= tier.min_length && classes >= tier.min_classes;
}

// Each configured rule's result, whether the password is a passphrase, and the
// first tier it meets. ``user`` is {email, display_name}, both optional.
export function evaluate(password, rules, user = null) {
  if (rules.version !== SUPPORTED_VERSION) throw new Error(`password rules version ${rules.version} is not supported`);
  const text = normalise(password);
  const points = codePoints(text);
  const length = points.length;
  const classes = countClasses(points, classMatchers(rules.classes));
  const phrase = rules.passphrase;
  const words = phrase ? countWords(text, phrase.separators) : 0;
  const passphrase = phrase !== null && length >= phrase.min_length && words >= phrase.min_words;
  const results = [
    { code: "min_length", passed: length >= rules.min_length, waived: false },
    { code: "max_length", passed: length <= rules.max_length, waived: false },
  ];
  if (rules.min_classes > 0) {
    const enough = classes >= rules.min_classes;
    const waived = !enough && passphrase && phrase !== null && phrase.relaxes_classes;
    results.push({ code: "min_classes", passed: enough || waived, waived });
  }
  if (rules.max_repeat !== null) {
    results.push({ code: "max_repeat", passed: longestRun(points) <= rules.max_repeat, waived: false });
  }
  if (rules.forbid_user_details) {
    const lowered = text.toLowerCase();
    const minimum = rules.user_detail_min_length;
    const email = detailTokens(localPart(user?.email), true, minimum);
    const name = detailTokens(user?.display_name, false, minimum);
    results.push({ code: "no_email", passed: !email.some((token) => lowered.includes(token)), waived: false });
    results.push({ code: "no_display_name", passed: !name.some((token) => lowered.includes(token)), waived: false });
  }
  const tier = rules.tiers.find((candidate) => meets(candidate, length, classes, passphrase));
  return {
    code_points: length,
    ok: results.every((result) => result.passed),
    passphrase,
    tier: tier ? tier.name : null,
    words,
    classes,
    results,
  };
}

function plural(count, one, many) {
  return `${count} ${count === 1 ? one : many}`;
}

// The checklist's wording for a rule, from the description alone.
export function ruleLabel(code, rules) {
  switch (code) {
    case "min_length":
      return `At least ${plural(rules.min_length, "character", "characters")}`;
    case "max_length":
      return `At most ${plural(rules.max_length, "character", "characters")}`;
    case "min_classes":
      return `Uses at least ${rules.min_classes} of the 5 kinds of character (lower case, upper case, digit, other letter, symbol or space)`;
    case "max_repeat":
      return `No character repeated more than ${plural(rules.max_repeat, "time", "times")} in a row`;
    case "no_email":
      return "Does not contain part of your email address";
    case "no_display_name":
      return "Does not contain part of your name";
    default:
      return code;
  }
}

// The passphrase path: "Passphrase: 3 of 4 words" and the length it also needs.
export function passphraseLine(rules, evaluation) {
  const phrase = rules.passphrase;
  if (!phrase) return null;
  const words = `${Math.min(evaluation.words, phrase.min_words)} of ${phrase.min_words} words`;
  const length = `${Math.min(evaluation.code_points, phrase.min_length)} of ${phrase.min_length} characters`;
  const relaxed = phrase.relaxes_classes ? " A passphrase is excused the character kinds rule." : "";
  const prefix = evaluation.passphrase ? "Passphrase met" : "Passphrase";
  return `${prefix}: ${words}, ${length}.${relaxed}`;
}

// How long a tier lasts, in plain words.
export function periodText(tier) {
  if (!tier) return "";
  return tier.max_age_days === null ? "no change period" : `change every ${plural(tier.max_age_days, "day", "days")}`;
}

export function tierLine(rules, evaluation) {
  if (rules.tiers.length === 0) return null;
  if (evaluation.tier === null) return "Tier: none yet. Meet the rules above to reach a tier.";
  const tier = rules.tiers.find((candidate) => candidate.name === evaluation.tier);
  return `Tier: ${evaluation.tier} (${periodText(tier)})`;
}
