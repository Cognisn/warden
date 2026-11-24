"""The packaged browser rules against warden's test vectors.

``src/warden/static/passwordrules.js`` ships in the wheel so a product can serve
it. Every case in ``docs/contract/password-rule-vectors.json`` is run through
that very file under Node by ``tests/static/run_vectors.mjs`` (the same runner the
CI ``browser-rules`` job runs), so the script and warden's rule engine cannot
drift apart. ``tests/identity/password_policy/test_password_rule_vectors.py``
holds the other half: the engine against the same file.

Where Node is missing a developer's run skips the check with a reason; in CI
(the ``CI`` variable is set) a missing Node fails, so it can never be silently
skipped there.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import warden.static

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "docs" / "contract" / "password-rule-vectors.json"
RUNNER = ROOT / "tests" / "static" / "run_vectors.mjs"


def node() -> str:
    found = shutil.which("node")
    if found is None:
        if os.environ.get("CI"):
            pytest.fail("Node is required in CI to run the browser rules against the vectors")
        pytest.skip("Node is not installed: the browser rules are not run against the vectors")
    return found


def run(script: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [node(), str(RUNNER), str(VECTORS), str(script)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_the_vectors_file_has_cases() -> None:
    cases = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]
    assert len(cases) >= 50


def test_every_vector_agrees_with_the_packaged_script() -> None:
    done = run(warden.static.path("passwordrules.js"))
    assert done.returncode == 0, done.stderr
    total = len(json.loads(VECTORS.read_text(encoding="utf-8"))["cases"])
    assert done.stdout.strip() == f"{total} of {total} cases agree"


def test_the_runner_fails_when_a_rule_is_altered(tmp_path: Path) -> None:
    # Mutation check: the runner is a guard only if it fails when a rule changes.
    source = warden.static.path("passwordrules.js").read_text(encoding="utf-8")
    needle = "length >= rules.min_length"
    assert source.count(needle) == 1
    mutated = tmp_path / "passwordrules.js"
    mutated.write_text(source.replace(needle, "length > rules.min_length"), "utf-8", newline="\n")
    done = run(mutated)
    assert done.returncode == 1
    assert "FAIL" in done.stderr and "cases disagree" in done.stderr


def test_the_runner_fails_when_the_script_defines_nothing(tmp_path: Path) -> None:
    empty = tmp_path / "passwordrules.js"
    empty.write_text("// nothing\n", "utf-8", newline="\n")
    assert run(empty).returncode == 1


def test_the_script_has_no_dom_or_network() -> None:
    source = warden.static.path("passwordrules.js").read_text(encoding="utf-8")
    for forbidden in ("document", "window", "fetch(", "XMLHttpRequest", "localStorage"):
        assert forbidden not in source, forbidden
    # A classic script: no module statements (the header's examples are comments).
    assert not re.search(r"^(export|import)\s", source, re.MULTILINE)
