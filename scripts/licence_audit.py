"""Enforce warden's licence policy on its runtime dependencies.

    python scripts/licence_audit.py

Walks the installed runtime dependency tree of ``cognisn-warden`` (extras
excluded, environment markers evaluated for this interpreter) and reads each
distribution's licence metadata. The policy:

- No strong copyleft (GPL, AGPL, SSPL, EUPL, OSL) in a runtime dependency,
  ever. Naming such a package as an exception does not admit it.
- Weak copyleft (LGPL, MPL, EPL, CDDL) only as a named, reviewed exception
  for a package used unmodified and installed separately.
- A package that declares no licence is refused unless it is named.

For a dual licence the most permissive alternative counts.

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
        " driver; used unmodified as a separately installed package"
    ),
    "certifi": (
        "MPL-2.0: the CA bundle httpx depends on, needed by single sign-on; agreed under"
        " the licence policy of 27 October 2026; used unmodified as a separately installed"
        " package"
    ),
    "fido2": (
        "MPL-2.0: fido2 itself is BSD-2-Clause, but it bundles the public suffix list"
        " (public_suffix_list.dat, MPL-2.0), which warden's WebAuthn relying-party checks"
        " read; agreed on 6 November 2026 (ruling P2); used unmodified as a separately"
        " installed package"
    ),
}

_STRONG = re.compile(
    r"\b(?:A?GPL|GPLv\d|SSPL|EUPL|OSL)\b"
    r"|GNU (?:Affero )?General Public|Server Side Public|European Union Public"
    r"|Open Software Licen[cs]e",
    re.IGNORECASE,
)
_WEAK = re.compile(
    r"\b(?:LGPL|LGPLv\d|MPL|EPL|CDDL)\b"
    r"|GNU (?:Lesser|Library)|Mozilla Public|Eclipse Public"
    r"|Common Development and Distribution",
    re.IGNORECASE,
)
_RANK = {"permissive": 0, "weak copyleft": 1, "strong copyleft": 2}
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


def _one(text: str) -> str:
    if _STRONG.search(text):
        return "strong copyleft"
    if _WEAK.search(text):
        return "weak copyleft"
    return "permissive"


def classify(licences: list[str]) -> str:
    """``permissive``, ``weak copyleft``, ``strong copyleft`` or ``unknown``.

    Each licence string is judged by its most permissive ``OR`` alternative;
    the distribution by its least permissive string.
    """
    known = [text.strip() for text in licences if text.strip().lower() not in _UNKNOWN]
    if not known:
        return "unknown"
    verdicts = [
        min((_one(alt) for alt in re.split(r"\s+OR\s+", text)), key=_RANK.__getitem__)
        for text in known
    ]
    return max(verdicts, key=_RANK.__getitem__)


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
            if verdict == "strong copyleft":
                report.violations.append(package)
            elif verdict != "permissive":
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
        print(f"{package.name:<24} {classify(package.licences):<16} {shown}")
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
