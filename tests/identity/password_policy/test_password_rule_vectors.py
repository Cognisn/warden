"""The rule test-case file and the engine never disagree (ruling PW10).

``docs/contract/password-rule-vectors.json`` ships in the contract so a
product can prove its browser checks agree with the server. Regenerate it
with ``python tests/identity/password_policy/password_rule_vectors.py``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from password_rule_vectors import CASES, POLICIES, VECTORS, render

from warden.identity.password_policy import PasswordRules, RuleCode, UserContext, evaluate
from warden.identity.password_policy.rules import normalise


def _file() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(VECTORS.read_text(encoding="utf-8"))
    return data


def test_the_file_is_exactly_what_the_engine_generates() -> None:
    raw = VECTORS.read_bytes()
    assert b"\r\n" not in raw
    assert raw.decode("utf-8") == render(), (
        "the rule engine and docs/contract/password-rule-vectors.json disagree; regenerate"
        " the file and check the change is intended"
    )


@pytest.mark.parametrize("case", _file()["cases"], ids=lambda c: c["name"])
def test_each_case_holds_against_the_engine_from_the_files_own_policy(
    case: dict[str, Any],
) -> None:
    # Read only from the file, as a browser would: the description, not POLICIES.
    rules = PasswordRules.from_description(_file()["policies"][case["policy"]])
    user = case["user"] or {}
    result = evaluate(case["password"], rules, UserContext(**user))
    expected = case["expected"]
    assert len(normalise(case["password"])) == expected["code_points"]
    assert result.ok is expected["ok"]
    assert result.passphrase is expected["passphrase"]
    assert result.tier == expected["tier"]
    assert [
        {"code": str(r.code), "passed": r.passed, "waived": r.waived} for r in result.results
    ] == expected["results"]


def test_the_cases_cover_every_rule_both_ways() -> None:
    seen: set[tuple[str, bool]] = set()
    waived = False
    for case in _file()["cases"]:
        for result in case["expected"]["results"]:
            seen.add((result["code"], result["passed"]))
            waived = waived or result["waived"]
    for code in RuleCode:
        assert (str(code), True) in seen, code
        assert (str(code), False) in seen, code
    assert waived


def test_the_cases_cover_passphrases_tiers_and_unicode() -> None:
    cases = _file()["cases"]
    assert {c["expected"]["passphrase"] for c in cases} == {True, False}
    tiers = {c["expected"]["tier"] for c in cases if c["policy"] == "tiers"} - {None}
    assert tiers == {"passphrase", "strong", "good", "standard"}
    passwords = [c["password"] for c in cases]
    assert any("\u0301" in p for p in passwords), "combining marks"
    assert any(any(ord(ch) > 0xFFFF for ch in p) for p in passwords), "surrogate pairs"
    assert any(len(p) != len(normalise(p)) for p in passwords), "NFC changes the count"


def test_every_policy_in_the_file_is_one_the_engine_accepts() -> None:
    for name, description in _file()["policies"].items():
        assert PasswordRules.from_description(description) == POLICIES[name]
    assert len(_file()["cases"]) == len(CASES)
