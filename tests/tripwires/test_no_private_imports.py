"""Tripwire: no warden module reaches into another module's private names.

A leading underscore marks a name as internal to its module. A module that
needs one from elsewhere gets a public helper instead, so the owner can
change its internals without breaking a caller it cannot see. Checked for
``from warden.x import _name`` and for ``x._name`` where ``x`` was bound by
importing from warden.
"""

from __future__ import annotations

import ast

from tripwires.source import Module, modules


def _private(name: str) -> bool:
    return name.startswith("_") and not name.startswith("__")


def _from_warden(node: ast.ImportFrom) -> bool:
    return node.level == 0 and (node.module or "").split(".")[0] == "warden"


def _warden_bindings(tree: ast.Module) -> set[str]:
    """Local names bound by an import from warden (modules or anything else)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "warden":
                    names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and _from_warden(node):
            names |= {alias.asname or alias.name for alias in node.names}
    return names


def _violations(module: Module) -> list[str]:
    bound = _warden_bindings(module.tree)
    found = []
    for node in ast.walk(module.tree):
        if isinstance(node, ast.ImportFrom) and _from_warden(node):
            found += [f"{node.module}.{a.name}" for a in node.names if _private(a.name)]
        elif isinstance(node, ast.Attribute) and _private(node.attr):
            root: ast.expr = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in bound:
                found.append(f"{ast.unparse(node)} (line {node.lineno})")
    return found


def test_no_module_reaches_into_another_modules_private_names() -> None:
    offenders = {m.rel: v for m in modules() if (v := _violations(m))}
    assert not offenders, offenders
