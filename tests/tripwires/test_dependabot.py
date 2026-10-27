"""Dependabot keeps the pinned GitHub Actions current.

Pinning every action to a commit SHA (``test_pinned_actions``) stops a moved
tag from changing what CI runs, but a pin never updates itself. Dependabot
proposes new SHAs weekly, in the same pinned form, so the tripwire keeps
passing on its pull requests.
"""

from __future__ import annotations

import re
from pathlib import Path

from tripwires.test_pinned_actions import _PINNED, _USES

DEPENDABOT = Path(__file__).resolve().parents[2] / ".github" / "dependabot.yml"

# A line as Dependabot rewrites it when it bumps a SHA-pinned action: the new
# commit SHA, with the release it corresponds to kept as a trailing comment.
DEPENDABOT_BUMP = (
    "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v5.2.0\n"
)


def _blocks() -> list[str]:
    text = DEPENDABOT.read_text(encoding="utf-8")
    return re.split(r"\n\s*- package-ecosystem:", text)[1:]


def test_dependabot_watches_github_actions_weekly() -> None:
    text = DEPENDABOT.read_text(encoding="utf-8")
    assert re.search(r"^version:\s*2\s*$", text, re.MULTILINE)
    ecosystem = re.compile(r"\s*[\"']?github-actions[\"']?\s*")
    actions = [b for b in _blocks() if ecosystem.fullmatch(b.split("\n")[0])]
    assert len(actions) == 1, "exactly one github-actions entry"
    block = actions[0]
    assert re.search(r"^\s*directory:\s*[\"']?/[\"']?\s*$", block, re.MULTILINE)
    assert re.search(r"^\s*interval:\s*[\"']?weekly[\"']?\s*$", block, re.MULTILINE)


def test_the_pinned_actions_tripwire_accepts_dependabots_sha_form() -> None:
    refs = [m.group("ref").strip("'\"") for m in _USES.finditer(DEPENDABOT_BUMP)]
    assert refs == ["actions/checkout@0123456789abcdef0123456789abcdef01234567"]
    assert _PINNED.fullmatch(refs[0]) is not None


def test_the_pinned_actions_tripwire_still_refuses_a_tag() -> None:
    line = DEPENDABOT_BUMP.replace("0123456789abcdef0123456789abcdef01234567", "v5")
    refs = [m.group("ref").strip("'\"") for m in _USES.finditer(line)]
    assert _PINNED.fullmatch(refs[0]) is None
