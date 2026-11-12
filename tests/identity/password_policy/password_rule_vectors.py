"""The rule test cases behind ``docs/contract/password-rule-vectors.json``.

The file is generated from the engine by running this module::

    python tests/identity/password_policy/password_rule_vectors.py

and ``test_password_rule_vectors.py`` fails whenever the file and the engine
disagree. A product's browser checks evaluate each case's ``policy`` (the
shape ``PasswordRules.describe()`` returns) against ``password`` and
``user``, and must reach ``expected``. Every password here is synthetic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / "src") not in sys.path:  # run as a script from a checkout
    sys.path.insert(0, str(ROOT / "src"))

from warden.identity.password_policy import (  # noqa: E402
    PassphraseRule,
    PasswordRules,
    Tier,
    UserContext,
    evaluate,
)
from warden.identity.password_policy.rules import normalise  # noqa: E402

VECTORS = ROOT / "docs" / "contract" / "password-rule-vectors.json"

POLICIES: dict[str, PasswordRules] = {
    "seeded": PasswordRules(min_length=12),
    "bounded": PasswordRules(min_length=8, max_length=16),
    "classes": PasswordRules(min_length=8, min_classes=3),
    "five_classes": PasswordRules(min_length=8, min_classes=5),
    "repeat": PasswordRules(min_length=8, max_repeat=2),
    "details": PasswordRules(min_length=8, forbid_user_details=True),
    "passphrase": PasswordRules(
        min_length=12,
        min_classes=3,
        passphrase=PassphraseRule(min_length=20, min_words=4, relaxes_classes=True),
    ),
    "strict_passphrase": PasswordRules(
        min_length=12,
        min_classes=3,
        passphrase=PassphraseRule(min_length=20, min_words=4, relaxes_classes=False),
    ),
    "tiers": PasswordRules(
        min_length=12,
        passphrase=PassphraseRule(min_length=24, min_words=5, relaxes_classes=True),
        tiers=(
            Tier(name="passphrase", passphrase=True, max_age_days=None),
            Tier(name="strong", min_length=16, min_classes=4, max_age_days=365),
            Tier(name="good", min_length=14, min_classes=3, max_age_days=180),
            Tier(name="standard", min_length=12, min_classes=0, max_age_days=90),
        ),
        warning_days=14,
    ),
    "everything": PasswordRules(
        min_length=10,
        max_length=64,
        min_classes=2,
        max_repeat=3,
        forbid_user_details=True,
        passphrase=PassphraseRule(min_length=20, min_words=4, relaxes_classes=True),
        tiers=(
            Tier(name="passphrase", passphrase=True, max_age_days=None),
            Tier(name="other", min_length=10, min_classes=0, max_age_days=180),
        ),
        warning_days=7,
    ),
}

JANE = {"email": "jane.citizen@example.com", "display_name": "Jane Q Citizen"}
RENEE = {"email": "zoe@example.org", "display_name": "Ren\u00e9e Okafor"}
# A digit inside a piece: a client whose pieces are letters only drops these.
SAM = {"email": "sam.x7k2@example.com", "display_name": "Sam Citizen"}
ROBO = {"email": "unit@example.net", "display_name": "Robo r2d2x Unit"}

# (name, policy, password, user)
CASES: list[tuple[str, str, str, dict[str, str] | None]] = [
    ("seeded: one short", "seeded", "abcdefghijk", None),
    ("seeded: exactly the minimum", "seeded", "abcdefghijkl", None),
    ("seeded: digits only", "seeded", "123456789012", None),
    ("seeded: the maximum length", "seeded", "x" * 1024, None),
    ("seeded: one over the maximum", "seeded", "x" * 1025, None),
    ("bounded: below", "bounded", "abcdefg", None),
    ("bounded: lower edge", "bounded", "abcdefgh", None),
    ("bounded: upper edge", "bounded", "abcdefghijklmnop", None),
    ("bounded: above", "bounded", "abcdefghijklmnopq", None),
    ("nfc: precomposed accent", "bounded", "caf\u00e9abcd", None),
    ("nfc: decomposed accent counts once", "bounded", "cafe\u0301abcd", None),
    ("nfc: decomposed at the upper edge", "bounded", "e\u0301" * 16, None),
    ("nfc: decomposed one over", "bounded", "e\u0301" * 17, None),
    ("combining mark with no composed form", "bounded", "x\u0301" * 4, None),
    ("surrogate pair: emoji counts once", "bounded", "\U0001f600" * 8, None),
    ("surrogate pair: seven emoji", "bounded", "\U0001f600" * 7, None),
    ("surrogate pair: sixteen emoji", "bounded", "\U0001f510" * 16, None),
    ("classes: lowercase only", "classes", "abcdefghij", None),
    ("classes: two", "classes", "abcdeFGHIJ", None),
    ("classes: three", "classes", "abcdeFGH12", None),
    ("classes: symbol from a space", "classes", "abcd EFGH 1", None),
    ("classes: other letters", "classes", "\u5bc6\u7801abcdEFGH", None),
    ("classes: titlecase is uppercase", "classes", "\u01c5abcdefg1!", None),
    ("classes: astral uppercase", "classes", "\U0001d49cbcdefg1", None),
    ("classes: astral symbol", "classes", "\U0001f600abcdefgH", None),
    ("classes: marks belong to no class", "classes", "abcdefgh\u0301\u0302", None),
    ("classes: all five", "five_classes", "aB3!\u5bc6xyz", None),
    ("classes: four of five", "five_classes", "aB3!xyzw", None),
    ("repeat: two allowed", "repeat", "aabbccdd", None),
    ("repeat: three refused", "repeat", "aaabbccd", None),
    ("repeat: decomposed run after nfc", "repeat", "xy" + "e\u0301" * 3 + "zzw", None),
    ("repeat: emoji run", "repeat", "abcdef" + "\U0001f600" * 3, None),
    ("details: unrelated", "details", "correct horse battery", JANE),
    ("details: whole local part", "details", "xxjane.citizenxx", JANE),
    ("details: a piece of the local part", "details", "citizenkane-2026", JANE),
    ("details: case ignored", "details", "MY JANE PASSWORD", JANE),
    ("details: short words ignored", "details", "q is not a token", JANE),
    ("details: the domain is not checked", "details", "example.com rocks", JANE),
    ("details: accent normalised", "details", "hi rene\u0301e okay", RENEE),
    ("details: no user details given", "details", "jane.citizen", None),
    ("details: a digit inside an email piece, refused", "details", "my x7k2 secret", SAM),
    ("details: a digit inside an email piece, allowed", "details", "my x7 k2 secret", SAM),
    ("details: a digit inside a name word, refused", "details", "plan r2d2x now", ROBO),
    ("details: a digit inside a name word, allowed", "details", "plan r2 d2x now", ROBO),
    ("passphrase: four words, long enough", "passphrase", "correct horse battery staple", None),
    ("passphrase: separators mix", "passphrase", "correct-horse.battery_staple", None),
    ("passphrase: three words", "passphrase", "correct horse batterystaple", None),
    ("passphrase: 19 code points", "passphrase", "abcd efgh ijkl mnop", None),
    ("passphrase: 20 code points", "passphrase", "abcd efgh ijkl mnopq", None),
    ("passphrase: runs of separators", "passphrase", "abcd  efgh   ijkl  mnop", None),
    ("passphrase: separators at the ends", "passphrase", "  leading and trailing  ", None),
    ("passphrase: emoji words", "passphrase", "\U0001f600\U0001f600 b c d efghijklmnopqrst", None),
    ("passphrase: not relaxed", "strict_passphrase", "correct horse battery staple", None),
    ("passphrase: classes met anyway", "strict_passphrase", "Correct horse battery 5taple", None),
    ("tiers: passphrase tier", "tiers", "the quick brown fox jumps over", None),
    ("tiers: strong", "tiers", "Abcdefghij12345!", None),
    ("tiers: good", "tiers", "Abcdefghij1234", None),
    ("tiers: standard", "tiers", "abcdefghijkl", None),
    ("tiers: below the rules", "tiers", "abcdefghijk", None),
    ("everything: passes", "everything", "Tiger lily 77", JANE),
    ("everything: every rule fails", "everything", "jjjjane", JANE),
    ("everything: passphrase relaxed", "everything", "lots of words here now", JANE),
    ("everything: passphrase with a name", "everything", "my name is jane citizen", JANE),
]


def _case(name: str, policy: str, password: str, user: dict[str, str] | None) -> dict[str, Any]:
    context = UserContext(**user) if user else UserContext()
    result = evaluate(password, POLICIES[policy], context)
    return {
        "name": name,
        "policy": policy,
        "password": password,
        "user": user,
        "expected": {
            "code_points": len(normalise(password)),
            "ok": result.ok,
            "passphrase": result.passphrase,
            "tier": result.tier,
            "results": [
                {"code": str(r.code), "passed": r.passed, "waived": r.waived}
                for r in result.results
            ],
        },
    }


def build() -> dict[str, Any]:
    for rules in POLICIES.values():
        rules.validate()
    return {
        "about": (
            "Password rule test cases for warden's password policies. Evaluate each case's"
            " password against its policy (the shape of the policy description routes) and"
            " user, and compare with expected. Generated from warden's rule engine; the engine"
            " and this file never disagree."
        ),
        "version": 1,
        "policies": {name: rules.describe() for name, rules in POLICIES.items()},
        "cases": [_case(*case) for case in CASES],
    }


def render() -> str:
    return json.dumps(build(), ensure_ascii=False, indent=2) + "\n"


if __name__ == "__main__":
    VECTORS.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {len(CASES)} cases to {VECTORS.relative_to(ROOT)}")
