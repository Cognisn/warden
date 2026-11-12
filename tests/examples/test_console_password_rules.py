"""The browser's password rules against warden's test vectors.

The checklist in the sample console evaluates a policy description in the
browser (``examples/console/static/js/passwordrules.js``). Every case in
``docs/contract/password-rule-vectors.json`` is run through that very file
under Node, and the answer compared with the expected one, so the sample's
JavaScript and warden's rule engine cannot drift apart.

Node is the documented way to run browser JavaScript in a test here: it ships
on GitHub's hosted runners and needs no package. Where Node is missing a
developer's run skips the check with a reason; in CI (the ``CI`` variable is
set) a missing Node fails, so the check can never be silently skipped there.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "docs" / "contract" / "password-rule-vectors.json"
RULES = ROOT / "examples" / "console" / "static" / "js" / "passwordrules.js"

# Node treats a .js file as CommonJS unless told otherwise, so the module is
# copied to a .mjs file beside this runner; the module itself stays a plain
# browser module.
RUNNER = """
import { readFileSync, writeFileSync } from "node:fs";
import { evaluate } from "./passwordrules.mjs";

const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));
const answers = vectors.cases.map((c) => {
  const got = evaluate(c.password, vectors.policies[c.policy], c.user);
  return { name: c.name, got };
});
writeFileSync(process.argv[3], JSON.stringify(answers), "utf8");
"""


def node() -> str:
    found = shutil.which("node")
    if found is None:
        if os.environ.get("CI"):
            pytest.fail("Node is required in CI to run the browser rules against the vectors")
        pytest.skip("Node is not installed: the browser rules are not run against the vectors")
    return found


@pytest.fixture(scope="module")
def answers(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    work = tmp_path_factory.mktemp("rules")
    (work / "passwordrules.mjs").write_text(
        RULES.read_text(encoding="utf-8"), encoding="utf-8", newline="\n"
    )
    (work / "run.mjs").write_text(RUNNER, encoding="utf-8", newline="\n")
    out = work / "answers.json"
    subprocess.run(
        [node(), str(work / "run.mjs"), str(VECTORS), str(out)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    found = json.loads(out.read_text(encoding="utf-8"))
    return {item["name"]: item["got"] for item in found}


def cases() -> list[dict[str, Any]]:
    loaded = json.loads(VECTORS.read_text(encoding="utf-8"))
    found: list[dict[str, Any]] = loaded["cases"]
    return found


def test_the_vectors_file_has_cases() -> None:
    assert len(cases()) >= 50


@pytest.mark.parametrize("case", cases(), ids=lambda c: str(c["name"]))
def test_the_browser_rules_agree_with_the_vector(
    case: dict[str, Any], answers: dict[str, dict[str, Any]]
) -> None:
    got = answers[case["name"]]
    expected = case["expected"]
    assert got["code_points"] == expected["code_points"]
    assert got["ok"] == expected["ok"]
    assert got["passphrase"] == expected["passphrase"]
    assert got["tier"] == expected["tier"]
    assert got["results"] == expected["results"]


def test_every_case_is_answered_once(answers: dict[str, dict[str, Any]]) -> None:
    names = [case["name"] for case in cases()]
    assert len(names) == len(set(names)), "case names must be unique for this check"
    assert set(answers) == set(names)
