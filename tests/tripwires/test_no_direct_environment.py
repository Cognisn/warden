"""Tripwire: warden reads configuration only through konfig.

No module under ``src/warden`` touches ``os.environ`` or ``os.getenv``,
or opens or reads a file itself.
"""

from __future__ import annotations

import ast

from tripwires.source import modules

_FORBIDDEN_ATTRS = {"environ", "environb", "getenv", "putenv", "read_text", "read_bytes"}
_FORBIDDEN_CALLS = {"open"}


def _findings() -> list[str]:
    findings: list[str] = []
    for module in modules():
        for node in ast.walk(module.tree):
            where = f"{module.rel}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_ATTRS:
                findings.append(f"{where}: .{node.attr}")
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                findings += [
                    f"{where}: from os import {a.name}"
                    for a in node.names
                    if a.name in _FORBIDDEN_ATTRS
                ]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in _FORBIDDEN_CALLS
            ):
                findings.append(f"{where}: {node.func.id}()")
    return findings


def test_no_module_reads_the_environment_or_files_directly() -> None:
    assert _findings() == []
