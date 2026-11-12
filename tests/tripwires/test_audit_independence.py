"""Tripwire: ``warden.audit`` imports nothing from ``warden.identity`` (design D11).

Checked three ways: no audit module names identity in an import or an
import string; no warden module reachable from audit (config, db, keys, the
package root) does either; and importing ``warden.audit`` in a fresh
interpreter loads no ``warden.identity`` module.
"""

from __future__ import annotations

import subprocess
import sys

from tripwires.source import PACKAGE, Module, imported_modules, modules, string_literals

IDENTITY = "warden.identity"


def _names_identity(name: str) -> bool:
    return name == IDENTITY or name.startswith(IDENTITY + ".")


def _violations(module: Module) -> list[str]:
    found = [name for name in imported_modules(module) if _names_identity(name)]
    found += [s for s in string_literals(module.tree) if IDENTITY in s]
    return found


def test_no_audit_module_imports_identity() -> None:
    offenders = {m.rel: v for m in modules(PACKAGE / "audit") if (v := _violations(m))}
    assert offenders == {}


def test_nothing_audit_depends_on_imports_identity() -> None:
    by_name = {m.name: m for m in modules()}
    seen: set[str] = set()
    pending = ["warden", *[m.name for m in by_name.values() if m.name.startswith("warden.audit")]]
    offenders: dict[str, list[str]] = {}
    while pending:
        name = pending.pop()
        if name in seen or name not in by_name:
            continue
        seen.add(name)
        module = by_name[name]
        if violations := _violations(module):
            offenders[module.rel] = violations
        for imported in imported_modules(module):
            parts = imported.split(".")
            for i in range(1, len(parts) + 1):
                candidate = ".".join(parts[:i])
                if candidate.startswith("warden"):
                    pending.append(candidate)
    assert offenders == {}
    # The walk must reach audit's real dependencies, or it guards nothing.
    assert {"warden", "warden.db", "warden.db.pool", "warden.audit.recorder"} <= seen


def test_importing_audit_loads_no_identity_module() -> None:
    probe = (
        "import sys, warden.audit; "
        "print(','.join(m for m in sys.modules if m == 'warden.identity'"
        " or m.startswith('warden.identity.')))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=60, check=True
    )
    assert result.stdout.strip() == ""
