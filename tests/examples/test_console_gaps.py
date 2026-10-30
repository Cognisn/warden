"""Every gap the console shows names the question that records it."""

from __future__ import annotations

import re
from pathlib import Path

GAPS = Path(__file__).resolve().parents[2] / "examples" / "console" / "static" / "js" / "gaps.js"


def test_every_gap_names_its_question() -> None:
    source = GAPS.read_text(encoding="utf-8")
    entries = re.findall(r"^  (\w+): \{\n    question: \"([^\"]*)\"", source, re.MULTILINE)
    assert len(entries) >= 6
    for name, question in entries:
        assert re.fullmatch(r"Q[1-9][0-9]*", question), (name, question)


def test_every_gap_the_screens_use_is_defined() -> None:
    source = GAPS.read_text(encoding="utf-8")
    defined = set(re.findall(r"^  (\w+): \{", source, re.MULTILINE))
    used: set[str] = set()
    for script in GAPS.parent.glob("*.js"):
        used |= set(re.findall(r"gap\(\"(\w+)\"\)", script.read_text(encoding="utf-8")))
    assert used, "no screen shows a gap"
    assert used <= defined, sorted(used - defined)
