"""Fail if any runtime dependency of warden carries a copyleft licence.

    python scripts/licence_audit.py

Walks the installed runtime dependency tree of ``cognisn-warden`` (extras
excluded, environment markers evaluated for this interpreter) and reads each
distribution's licence metadata. A dependency is refused if it is copyleft
(GPL, AGPL, LGPL, MPL, EUPL, EPL, CDDL, SSPL, OSL) or declares no licence.
A dual licence passes if any alternative is permissive.

Exceptions are listed below, each with the reason it was agreed. Adding one
needs explicit agreement and a licence check, recorded in the project's
knowledge base.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import metadata

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = "cognisn-warden"

EXCEPTIONS: dict[str, str] = {
    "psycopg": (
        "LGPL-3.0: agreed in the 0.1.0 development plan (section 7) as warden's database"
        " driver; used unmodified as a separately installed library"
    ),
}

_COPYLEFT = re.compile(
    r"\b(?:A?GPL|LGPL|GPLv\d|MPL|EUPL|EPL|CDDL|SSPL|OSL)\b"
    r"|GNU (?:Affero |Lesser |Library )?General Public"
    r"|Mozilla Public|Eclipse Public|European Union Public|Common Development and Distribution",
    re.IGNORECASE,
)
_UNKNOWN = {"", "unknown", "none", "license :: osi approved"}


@dataclass(frozen=True)
class Package:
    name: str
    licences: list[str]
    requires: list[str] = field(default_factory=list)


@dataclass
class Report:
    checked: list[Package] = field(default_factory=list)
    violations: list[Package] = field(default_factory=list)
    excepted: list[Package] = field(default_factory=list)


def classify(licences: list[str]) -> str:
    """``permissive``, ``copyleft`` or ``unknown`` for a distribution's licence strings."""
    known = [text.strip() for text in licences if text.strip().lower() not in _UNKNOWN]
    if not known:
        return "unknown"
    for text in known:
        alternatives = re.split(r"\s+OR\s+", text)
        if len(alternatives) > 1:
            if all(_COPYLEFT.search(alt) for alt in alternatives):
                return "copyleft"
        elif _COPYLEFT.search(text):
            return "copyleft"
    return "permissive"


def installed(name: str) -> Package:
    dist = metadata.distribution(name)
    meta = dist.metadata
    licence_field = (meta.get("License") or "").strip()
    licences = [
        meta.get("License-Expression") or "",
        licence_field.splitlines()[0] if licence_field else "",
        *[c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")],
    ]
    return Package(
        name=canonicalize_name(meta["Name"]), licences=licences, requires=dist.requires or []
    )


def audit(
    root: str = ROOT,
    lookup: Callable[[str], Package] = installed,
    exceptions: dict[str, str] | None = None,
) -> Report:
    allowed = EXCEPTIONS if exceptions is None else exceptions
    report = Report()
    seen: set[str] = set()
    pending = [root]
    while pending:
        name = canonicalize_name(pending.pop())
        if name in seen:
            continue
        seen.add(name)
        package = lookup(name)
        report.checked.append(package)
        if name != canonicalize_name(root):
            verdict = classify(package.licences)
            if verdict != "permissive":
                (report.excepted if name in allowed else report.violations).append(package)
        for spec in package.requires:
            requirement = Requirement(spec)
            if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
                continue
            pending.append(requirement.name)
    report.checked.sort(key=lambda p: p.name)
    return report


def main() -> int:
    report = audit()
    for package in report.checked:
        shown = "; ".join(text for text in package.licences if text) or "(none declared)"
        print(f"{package.name:<24} {classify(package.licences):<10} {shown}")
    for package in report.excepted:
        print(f"EXCEPTION {package.name}: {EXCEPTIONS[package.name]}")
    if report.violations:
        for package in report.violations:
            print(f"REFUSED {package.name}: {classify(package.licences)} licence", file=sys.stderr)
        return 1
    print(f"licence audit passed: {len(report.checked) - 1} runtime dependencies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
