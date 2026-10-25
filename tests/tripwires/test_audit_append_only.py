"""Tripwire: nothing in warden edits audit rows, and only the retention purge deletes them.

A module refers to the audit table if it names it in a string or uses the
``AUDIT_EVENTS`` constant. No such module may carry ``UPDATE ... SET`` or
``TRUNCATE``, and only the retention module may carry ``DELETE FROM``. A
companion test asserts the retention module still holds its delete, so the
guard cannot pass vacuously if the purge moves.
"""

from __future__ import annotations

import re

from tripwires.source import identifiers, modules, string_literals

ALLOWED_DELETER = "warden/audit/retention.py"

_DELETE = re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE)
_EDIT = re.compile(r"\bUPDATE\s+\S+.*\bSET\b|\bTRUNCATE\b", re.IGNORECASE | re.DOTALL)
_TABLE = re.compile(r"\baudit_events\b")


def _matching(pattern: re.Pattern[str]) -> set[str]:
    found: set[str] = set()
    for module in modules():
        literals = list(string_literals(module.tree))
        refers = "AUDIT_EVENTS" in set(identifiers(module.tree)) or any(
            _TABLE.search(s) for s in literals
        )
        if refers and any(pattern.search(s) for s in literals):
            found.add(module.rel)
    return found


def test_no_module_edits_audit_rows() -> None:
    assert _matching(_EDIT) == set()


def test_only_the_retention_purge_deletes_audit_rows() -> None:
    assert _matching(_DELETE) == {ALLOWED_DELETER}


def test_the_retention_purge_still_holds_its_delete() -> None:
    (retention,) = [m for m in modules() if m.rel == ALLOWED_DELETER]
    assert any(_DELETE.search(s) for s in string_literals(retention.tree))
    assert "AUDIT_EVENTS" in set(identifiers(retention.tree))
