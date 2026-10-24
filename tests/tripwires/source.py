"""Helpers for tripwires that read warden's own source."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
PACKAGE = SRC / "warden"


@dataclass(frozen=True)
class Module:
    path: Path
    name: str
    tree: ast.Module

    @property
    def rel(self) -> str:
        return self.path.relative_to(SRC).as_posix()

    @property
    def is_package(self) -> bool:
        return self.path.name == "__init__.py"


def module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def modules(root: Path = PACKAGE) -> Iterator[Module]:
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        yield Module(path=path, name=module_name(path), tree=tree)


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def string_literals(tree: ast.AST) -> Iterator[str]:
    """Every string constant in the code, excluding docstrings."""
    skip = _docstring_nodes(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            yield node.value


def identifiers(tree: ast.AST) -> Iterator[str]:
    """Every name, attribute and imported alias used in the code."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, ast.alias):
            yield node.name.rsplit(".", 1)[-1]
            if node.asname:
                yield node.asname


def imported_modules(module: Module) -> Iterator[str]:
    """Absolute names of every module ``module`` imports, relative imports resolved."""
    package = module.name if module.is_package else module.name.rpartition(".")[0]
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".")
                base_parts = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(base_parts)
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            yield target
            for alias in node.names:
                yield f"{target}.{alias.name}"
