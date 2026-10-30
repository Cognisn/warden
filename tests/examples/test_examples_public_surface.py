"""Tripwire: the sample console uses only warden's public surface.

The sample under ``examples/`` shows a product how to integrate, so it may
use only what a product can: names a warden package exports, public modules,
and warden's HTTP routes. A leading underscore marks a module or name as
internal. This fails on ``import warden._x``, ``from warden.x._y import z``,
``from warden.x import _name``, and ``x._name`` where ``x`` was bound by
importing from warden.
"""

from __future__ import annotations

import ast
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def _private(name: str) -> bool:
    return name.startswith("_") and not name.startswith("__")


def _warden(module: str) -> bool:
    return module.split(".")[0] == "warden"


def _private_path(module: str) -> bool:
    return any(_private(part) for part in module.split("."))


def violations(source: str, filename: str = "<sample>") -> list[str]:
    """Every reach into a private warden module or name in ``source``."""
    tree = ast.parse(source, filename=filename)
    bound: set[str] = set()
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _warden(alias.name):
                    bound.add(alias.asname or alias.name.split(".")[0])
                    if _private_path(alias.name):
                        found.append(f"import {alias.name} (line {node.lineno})")
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and _warden(node.module or ""):
            module = node.module or ""
            bound |= {alias.asname or alias.name for alias in node.names}
            if _private_path(module):
                found.append(f"from {module} import ... (line {node.lineno})")
            found += [
                f"from {module} import {a.name} (line {node.lineno})"
                for a in node.names
                if _private(a.name)
            ]
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and _private(node.attr):
            root: ast.expr = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in bound:
                found.append(f"{ast.unparse(node)} (line {node.lineno})")
    return found


def sample_sources() -> list[Path]:
    return sorted(EXAMPLES.rglob("*.py"))


def test_the_sample_has_python_to_check() -> None:
    assert any(p.parent.name == "console" for p in sample_sources())


def test_nothing_under_examples_reaches_into_warden_internals() -> None:
    offenders = {
        p.relative_to(EXAMPLES).as_posix(): v
        for p in sample_sources()
        if (v := violations(p.read_text(encoding="utf-8"), str(p)))
    }
    assert not offenders, offenders


def test_the_check_sees_each_kind_of_private_reach() -> None:
    # The guard must be able to fail: each line below is one forbidden reach.
    cases = [
        "import warden._internal",
        "from warden.identity._helpers import thing",
        "from warden.identity.http import _private_helper",
        "from warden.identity import service\nservice._Account",
        "import warden.identity\nwarden.identity.service._USERS",
    ]
    for case in cases:
        assert violations(case), case
    assert not violations("from warden.identity import Identity, require_permission")
    assert not violations("import os\nos._exit")
