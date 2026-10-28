"""Tripwire: warden reads configuration only through konfig.

No module under ``src/warden`` touches ``os.environ`` or ``os.getenv``,
or opens or reads a file itself.

One read is exempt by name: the SIEM export an operator passes to
``warden audit verify --anchors FILE``, which is input data rather than
configuration (ruling of 28 October 2026). The exemption is a single
(module, function, operation) triple, and a companion test fails unless it
matches exactly one read, so it can neither widen silently nor go stale.
"""

from __future__ import annotations

import ast

from tripwires.source import modules

_FORBIDDEN_ATTRS = {"environ", "environb", "getenv", "putenv", "read_text", "read_bytes"}
_FORBIDDEN_CALLS = {"open"}

# (module, enclosing function, forbidden name) allowed to read a file.
_EXEMPT = {("warden/cli.py", "_read_anchors_file", "read_text")}


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Each node's innermost enclosing function name, keyed by ``id(node)``."""
    owner: dict[int, str] = {}

    def visit(node: ast.AST, current: str) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            current = node.name
        for child in ast.iter_child_nodes(node):
            owner[id(child)] = current
            visit(child, current)

    visit(tree, "")
    return owner


def _findings() -> list[tuple[str, bool]]:
    """Every forbidden use, and whether it is the named exemption."""
    findings: list[tuple[str, bool]] = []
    for module in modules():
        owner = _enclosing_functions(module.tree)
        for node in ast.walk(module.tree):
            where = f"{module.rel}:{getattr(node, 'lineno', 0)}"
            name: str | None = None
            if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_ATTRS:
                name, text = node.attr, f"{where}: .{node.attr}"
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                findings += [
                    (f"{where}: from os import {a.name}", False)
                    for a in node.names
                    if a.name in _FORBIDDEN_ATTRS
                ]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in _FORBIDDEN_CALLS
            ):
                name, text = node.func.id, f"{where}: {node.func.id}()"
            if name is not None:
                exempt = (module.rel, owner.get(id(node), ""), name) in _EXEMPT
                findings.append((text, exempt))
    return findings


def test_no_module_reads_the_environment_or_files_directly() -> None:
    assert [text for text, exempt in _findings() if not exempt] == []


def test_the_anchors_file_exemption_covers_exactly_one_read() -> None:
    exempt = [text for text, exempt in _findings() if exempt]
    assert len(exempt) == 1, exempt
    assert exempt[0].startswith("warden/cli.py:") and exempt[0].endswith(": .read_text")
