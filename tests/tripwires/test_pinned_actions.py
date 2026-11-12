"""Tripwire: every GitHub Action is pinned to a full commit SHA.

A tag such as ``@v5`` can be moved to different code by whoever controls the
action's repository; a commit SHA cannot. Local actions (``./...``) are
exempt because they are part of this repository.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"

_USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)", re.MULTILINE)
_PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")


def _references() -> list[tuple[str, str]]:
    found = []
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        found += [(path.name, m.group("ref").strip("'\"")) for m in _USES.finditer(text)]
    return found


def test_workflows_reference_actions() -> None:
    # Guards against the scan silently matching nothing.
    assert _references()


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    unpinned = [
        (name, ref)
        for name, ref in _references()
        if not ref.startswith("./") and _PINNED.fullmatch(ref) is None
    ]
    assert unpinned == []
