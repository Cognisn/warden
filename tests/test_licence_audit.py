"""The licence audit fails on any copyleft runtime dependency."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "licence_audit.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("licence_audit", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["licence_audit"] = module
    spec.loader.exec_module(module)
    return module


audit = _load()


def _pkg(name: str, licences: list[str], requires: list[str] | None = None) -> object:
    return audit.Package(name=name, licences=licences, requires=requires or [])


@pytest.mark.parametrize(
    "licences",
    [
        ["GPL-3.0-only"],
        ["AGPL-3.0-or-later"],
        ["LGPL-2.1"],
        ["MPL-2.0"],
        ["EUPL-1.2"],
        ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"],
        ["License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"],
        ["MIT", "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)"],
        ["GPL-2.0 OR LGPL-3.0"],
    ],
)
def test_copyleft_licences_are_flagged(licences: list[str]) -> None:
    assert audit.classify(licences) == "copyleft"


@pytest.mark.parametrize(
    "licences",
    [
        ["MIT"],
        ["Apache-2.0"],
        ["Apache-2.0 OR BSD-3-Clause"],
        ["MIT OR GPL-3.0-only"],
        ["PSF-2.0"],
        ["License :: OSI Approved :: BSD License"],
    ],
)
def test_permissive_licences_pass(licences: list[str]) -> None:
    assert audit.classify(licences) == "permissive"


def test_missing_licence_information_is_flagged() -> None:
    assert audit.classify(["", "UNKNOWN"]) == "unknown"


def test_audit_walks_the_runtime_tree_and_reports_copyleft() -> None:
    packages = {
        "root": _pkg("root", ["Apache-2.0"], ["a", "b; extra == 'dev'"]),
        "a": _pkg("a", ["MIT"], ["c"]),
        "b": _pkg("b", ["GPL-3.0"]),
        "c": _pkg("c", ["AGPL-3.0"]),
    }
    report = audit.audit("root", packages.__getitem__, exceptions={})
    assert [p.name for p in report.violations] == ["c"]
    assert "b" not in {p.name for p in report.checked}


def test_listed_exceptions_pass_with_their_reason() -> None:
    packages = {
        "root": _pkg("root", ["MIT"], ["psycopg"]),
        "psycopg": _pkg("psycopg", ["LGPL-3.0-only"]),
    }
    report = audit.audit("root", packages.__getitem__, exceptions={"psycopg": "agreed"})
    assert report.violations == []
    assert [p.name for p in report.excepted] == ["psycopg"]


def test_the_real_runtime_tree_passes_with_only_the_agreed_exception() -> None:
    report = audit.audit("cognisn-warden")
    assert report.violations == []
    assert {p.name for p in report.excepted} <= set(audit.EXCEPTIONS)
    assert "cognisn-konfig" in {p.name for p in report.checked}
