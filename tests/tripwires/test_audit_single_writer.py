"""Tripwire: only the audit recorder writes to the audit table.

A module is a writer if it refers to the audit table (by name or through the
``AUDIT_EVENTS`` constant) and its code carries a row-writing statement
(``INSERT INTO``, ``COPY ... FROM``, ``MERGE INTO``) or a SQLAlchemy insert.
Exactly one module may be a writer, and it must be the recorder. A companion
test asserts the recorder still holds a real ``INSERT INTO``, so the guard
cannot pass vacuously if the recorder's insert moves or disappears.
"""

from __future__ import annotations

import re

from tripwires.source import PACKAGE, identifiers, modules, string_literals

ALLOWED_WRITER = "warden/audit/recorder.py"

_WRITE_SQL = re.compile(
    r"\bINSERT\s+INTO\b|\bCOPY\s+\S+.*\bFROM\b|\bMERGE\s+INTO\b", re.IGNORECASE | re.DOTALL
)
_TABLE = re.compile(r"\baudit_events\b")


def _writers() -> set[str]:
    found: set[str] = set()
    for module in modules():
        literals = list(string_literals(module.tree))
        names = set(identifiers(module.tree))
        refers_to_table = "AUDIT_EVENTS" in names or any(_TABLE.search(s) for s in literals)
        writes = any(_WRITE_SQL.search(s) for s in literals) or bool(
            names & {"bulk_insert", "insert"}
        )
        if refers_to_table and writes:
            found.add(module.rel)
    return found


def test_only_the_recorder_writes_audit_rows() -> None:
    assert _writers() == {ALLOWED_WRITER}


def test_the_recorder_still_holds_the_audit_insert() -> None:
    (recorder,) = [m for m in modules(PACKAGE / "audit") if m.rel == ALLOWED_WRITER]
    inserts = [s for s in string_literals(recorder.tree) if re.search(r"\bINSERT\s+INTO\b", s)]
    assert inserts, "the audit recorder no longer contains its INSERT INTO statement"
    assert "AUDIT_EVENTS" in set(identifiers(recorder.tree))
