"""The licence audit enforces the licence policy for runtime dependencies.

No strong copyleft (GPL, AGPL, SSPL, EUPL, OSL), ever. Weak copyleft (LGPL,
MPL) only as a named, reviewed exception for an unmodified, separately
installed package.
"""

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
        ["GPL-2.0-or-later"],
        ["AGPL-3.0-or-later"],
        ["SSPL-1.0"],
        ["EUPL-1.2"],
        ["OSL-3.0"],
        ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"],
        ["License :: OSI Approved :: GNU Affero General Public License v3"],
        ["License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)"],
        ["License :: OSI Approved :: Open Software License 3.0 (OSL-3.0)"],
        ["Server Side Public License"],
        ["LGPL-3.0", "License :: OSI Approved :: GNU General Public License v2 (GPLv2)"],
        ["GPL-2.0 OR AGPL-3.0"],
    ],
)
def test_strong_copyleft_licences_are_flagged(licences: list[str]) -> None:
    assert audit.classify(licences) == "strong copyleft"


@pytest.mark.parametrize(
    "licences",
    [
        ["LGPL-2.1"],
        ["LGPL-3.0-only"],
        ["MPL-2.0"],
        ["License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"],
        ["MIT", "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)"],
        ["License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)"],
        ["GPL-2.0 OR LGPL-3.0"],
    ],
)
def test_weak_copyleft_licences_are_flagged(licences: list[str]) -> None:
    assert audit.classify(licences) == "weak copyleft"


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
        "root": _pkg("root", ["Apache-2.0"], ["a", "b; extra == 'dev'", "d"]),
        "a": _pkg("a", ["MIT"], ["c"]),
        "b": _pkg("b", ["GPL-3.0"]),
        "c": _pkg("c", ["AGPL-3.0"]),
        "d": _pkg("d", ["MPL-2.0"]),
    }
    report = audit.audit("root", packages.__getitem__, exceptions={})
    assert sorted(p.name for p in report.violations) == ["c", "d"]
    assert "b" not in {p.name for p in report.checked}


def test_a_strong_copyleft_package_fails_even_when_named_as_an_exception() -> None:
    packages = {
        "root": _pkg("root", ["MIT"], ["gplpkg"]),
        "gplpkg": _pkg("gplpkg", ["GPL-3.0-only"]),
    }
    report = audit.audit("root", packages.__getitem__, exceptions={"gplpkg": "agreed"})
    assert [p.name for p in report.violations] == ["gplpkg"]
    assert report.excepted == []


def test_a_named_exception_that_turns_strong_copyleft_fails() -> None:
    packages = {
        "root": _pkg("root", ["MIT"], ["psycopg"]),
        "psycopg": _pkg("psycopg", ["AGPL-3.0-only"]),
    }
    report = audit.audit("root", packages.__getitem__)
    assert [p.name for p in report.violations] == ["psycopg"]


def test_an_unnamed_weak_copyleft_package_fails() -> None:
    packages = {
        "root": _pkg("root", ["MIT"], ["mplpkg"]),
        "mplpkg": _pkg("mplpkg", ["MPL-2.0"]),
    }
    report = audit.audit("root", packages.__getitem__)
    assert [p.name for p in report.violations] == ["mplpkg"]


def test_listed_exceptions_pass_with_their_reason() -> None:
    packages = {
        "root": _pkg("root", ["MIT"], ["psycopg"]),
        "psycopg": _pkg("psycopg", ["LGPL-3.0-only"]),
    }
    report = audit.audit("root", packages.__getitem__, exceptions={"psycopg": "agreed"})
    assert report.violations == []
    assert [p.name for p in report.excepted] == ["psycopg"]


def test_the_named_exceptions_are_psycopg_certifi_and_fido2_with_their_reasons() -> None:
    assert set(audit.EXCEPTIONS) == {"psycopg", "certifi", "fido2"}
    assert "LGPL-3.0" in audit.EXCEPTIONS["psycopg"]
    assert "MPL-2.0" in audit.EXCEPTIONS["certifi"]
    assert "httpx" in audit.EXCEPTIONS["certifi"]
    assert "MPL-2.0" in audit.EXCEPTIONS["fido2"]
    assert "public suffix list" in audit.EXCEPTIONS["fido2"]
    for reason in audit.EXCEPTIONS.values():
        assert "unmodified" in reason and "separately installed" in reason


def test_fido2s_declared_licences_need_the_named_exception() -> None:
    # fido2 is BSD-2-Clause, but it bundles the public suffix list under
    # MPL-2.0 and declares that licence too, so the audit sees weak copyleft.
    declared = [
        "",
        "Copyright (c) 2018 Yubico AB",
        "License :: OSI Approved :: BSD License",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    ]
    assert audit.classify(declared) == "weak copyleft"
    packages = {
        "root": _pkg("root", ["MIT"], ["fido2"]),
        "fido2": _pkg("fido2", declared, ["cryptography (>=2.6,!=35,<52)"]),
        "cryptography": _pkg("cryptography", ["Apache-2.0 OR BSD-3-Clause"]),
    }
    assert [p.name for p in audit.audit("root", packages.__getitem__, exceptions={}).violations] == [
        "fido2"
    ]
    report = audit.audit("root", packages.__getitem__)
    assert report.violations == []
    assert [p.name for p in report.excepted] == ["fido2"]


def test_both_named_exceptions_pass() -> None:
    packages = {
        "root": _pkg("root", ["MIT"], ["psycopg", "httpx"]),
        "psycopg": _pkg("psycopg", ["LGPL-3.0-only"]),
        "httpx": _pkg("httpx", ["BSD-3-Clause"], ["certifi"]),
        "certifi": _pkg("certifi", ["MPL-2.0"]),
    }
    report = audit.audit("root", packages.__getitem__)
    assert report.violations == []
    assert sorted(p.name for p in report.excepted) == ["certifi", "psycopg"]


def test_the_real_runtime_tree_passes_with_only_the_agreed_exception() -> None:
    report = audit.audit("cognisn-warden")
    assert report.violations == []
    assert {p.name for p in report.excepted} <= set(audit.EXCEPTIONS)
    assert "cognisn-konfig" in {p.name for p in report.checked}
    # fido2 is a runtime dependency, and the audit sees its bundled MPL-2.0 file.
    assert "fido2" in {p.name for p in report.excepted}
