"""README.md is the PyPI project description, so it must render there without broken links."""

from __future__ import annotations

import re
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"

# Markdown links and images: [text](target) and ![alt](target).
_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)[^)]*\)")


def _targets(text: str) -> list[str]:
    return _LINK.findall(text)


def test_readme_has_links() -> None:
    assert _targets(README.read_text(encoding="utf-8"))


def test_every_link_is_absolute() -> None:
    relative = [
        target
        for target in _targets(README.read_text(encoding="utf-8"))
        if not re.fullmatch(r"https://\S+", target)
    ]
    assert relative == [], f"relative links break on pypi.org: {relative}"


def test_link_check_refuses_relative_link_and_image() -> None:
    sample = "See [the guide](docs/guide/clients.md) and ![logo](img/logo.png)."
    assert _targets(sample) == ["docs/guide/clients.md", "img/logo.png"]


def test_no_pre_release_wording() -> None:
    text = README.read_text(encoding="utf-8").lower()
    for phrase in ("pre-alpha", "nothing here is usable", "(planned)", "what it will provide"):
        assert phrase not in text, phrase
