"""Tripwire: anchored validation uses ``fullmatch``, never ``match`` with ``$``.

Python's ``$`` also matches just before a trailing newline, so
``re.match(r"[a-z]+$", "abc\\n")`` succeeds. warden validates with
``fullmatch`` instead. This scan fails on:

- any call to ``re.match``;
- ``.match(`` on a name bound to ``re.compile(...)``;
- any regex literal given to ``re`` that uses an unescaped ``$`` anchor.
"""

from __future__ import annotations

import ast

from tripwires.source import modules

_RE_FUNCS = {
    "compile",
    "match",
    "fullmatch",
    "search",
    "sub",
    "subn",
    "split",
    "findall",
    "finditer",
}


def _has_dollar_anchor(pattern: str) -> bool:
    escaped = False
    in_class = False
    for ch in pattern:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == "$":
            return True
    return False


def _is_re_call(node: ast.Call, func: str | None = None) -> bool:
    target = node.func
    return (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "re"
        and (target.attr == func if func else target.attr in _RE_FUNCS)
    )


def _compiled_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign | ast.AnnAssign)
            and isinstance(node.value, ast.Call)
            and _is_re_call(node.value, "compile")
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
                elif isinstance(target, ast.Attribute):
                    names.add(target.attr)
    return names


def _findings() -> list[str]:
    findings: list[str] = []
    for module in modules():
        compiled = _compiled_names(module.tree)
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.Call):
                continue
            where = f"{module.rel}:{node.lineno}"
            if _is_re_call(node, "match"):
                findings.append(f"{where}: re.match (use re.fullmatch)")
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "match"
                and isinstance(func.value, ast.Name | ast.Attribute)
                and (func.value.id if isinstance(func.value, ast.Name) else func.value.attr)
                in compiled
            ):
                findings.append(f"{where}: Pattern.match (use .fullmatch)")
            if _is_re_call(node) and node.args:
                first = node.args[0]
                if (
                    isinstance(first, ast.Constant)
                    and isinstance(first.value, str)
                    and _has_dollar_anchor(first.value)
                ):
                    findings.append(f"{where}: $ anchor in pattern (use fullmatch or \\Z)")
    return findings


def test_no_anchored_pattern_relies_on_match_or_dollar() -> None:
    assert _findings() == []


def test_the_scan_sees_the_patterns_it_guards() -> None:
    """The scan must actually find compiled patterns, or it guards nothing."""
    compiled = set().union(*(_compiled_names(m.tree) for m in modules()))
    assert {"_MOUNT_PREFIX", "_SD_ID", "_ACTION"} <= compiled
    identity = {"_EMAIL", "_LEGACY", "_CODE", "_RECOVERY", "_PERMISSION", "_ROLE", "_TOKEN"}
    assert identity | {"_B64URL", "_REFRESH"} <= compiled


def test_dollar_detection() -> None:
    assert _has_dollar_anchor(r"[a-z]+$")
    assert not _has_dollar_anchor(r"[a-z$]+")
    assert not _has_dollar_anchor(r"cost\$")
