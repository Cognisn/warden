"""Every gap the console shows names the question that records it."""

from __future__ import annotations

import re
from pathlib import Path

GAPS = Path(__file__).resolve().parents[2] / "examples" / "console" / "static" / "js" / "gaps.js"


def test_every_gap_names_its_question() -> None:
    source = GAPS.read_text(encoding="utf-8")
    entries = re.findall(r"^  (\w+): \{\n    question: \"([^\"]*)\"", source, re.MULTILINE)
    assert len(entries) >= 5
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


STATIC = GAPS.parent.parent
README = STATIC.parent / "README.md"


def test_the_totp_reset_is_no_longer_a_gap() -> None:
    """Question 6 was ruled an administrator's reset in warden 0.1.0."""
    source = GAPS.read_text(encoding="utf-8")
    assert '"Q6"' not in source
    assert "mfaReset" not in source
    readme = README.read_text(encoding="utf-8")
    gaps = readme.split("## Gaps", 1)[1].split("\n## ", 1)[0]
    assert "question 6" not in gaps


def test_the_passkey_flag_is_no_longer_a_gap() -> None:
    """Question 29 was answered with a field: the console labels keys from it."""
    source = GAPS.read_text(encoding="utf-8")
    assert '"Q29"' not in source
    assert "passkeyKind" not in source
    readme = README.read_text(encoding="utf-8")
    gaps = readme.split("## Gaps", 1)[1].split("\n## ", 1)[0]
    assert "question 29" not in gaps
    signin = (GAPS.parent / "signin.js").read_text(encoding="utf-8")
    assert "key.passkey" in signin
    assert "key.discoverable" not in signin


def test_forbid_user_details_is_no_longer_a_gap() -> None:
    """Question 39 was a defect in the admin route, fixed in warden 0.1.0."""
    source = GAPS.read_text(encoding="utf-8")
    assert '"Q39"' not in source
    assert "forbidUserDetails" not in source
    readme = README.read_text(encoding="utf-8")
    gaps = readme.split("## Gaps", 1)[1].split("\n## ", 1)[0]
    assert "question 39" not in gaps
    assert "question 39" not in readme
    passwords = (GAPS.parent / "passwords.js").read_text(encoding="utf-8")
    assert "forbidUserDetails" not in passwords


def test_the_users_screen_resets_totp_through_wardens_route() -> None:
    admin = (GAPS.parent / "admin.js").read_text(encoding="utf-8")
    assert 'call("DELETE", `${admin}/users/${id}/totp`)' in admin
