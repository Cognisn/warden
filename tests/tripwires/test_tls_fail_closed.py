"""Tripwire: nothing in warden turns TLS verification off.

Fails on any use of ``CERT_NONE`` or ``CERT_OPTIONAL``, any assignment of
anything but ``True`` to ``check_hostname``, any ``verify_mode`` assignment
other than ``CERT_REQUIRED``, an unverified-context factory, or a
``check_hostname=``/``verify=`` keyword set to a false constant. A companion
test proves the scan reaches the syslog transport and that the transport
still requires verification, so the guard cannot pass vacuously.
"""

from __future__ import annotations

import ast

from tripwires.source import PACKAGE, identifiers, modules, string_literals

TRANSPORT = "warden/audit/syslog/transport.py"

_FORBIDDEN_NAMES = {
    "CERT_NONE",
    "CERT_OPTIONAL",
    "_create_unverified_context",
    "_create_default_https_context",
}


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_cert_required(node: ast.expr) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == "CERT_REQUIRED") or (
        isinstance(node, ast.Name) and node.id == "CERT_REQUIRED"
    )


def _findings() -> list[str]:
    findings: list[str] = []
    for module in modules():
        names = set(identifiers(module.tree)) | set(string_literals(module.tree))
        findings += [f"{module.rel}: {name}" for name in sorted(names & _FORBIDDEN_NAMES)]
        for node in ast.walk(module.tree):
            where = f"{module.rel}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    if not isinstance(target, ast.Attribute) or value is None:
                        continue
                    if target.attr == "check_hostname" and not _is_true(value):
                        findings.append(f"{where}: check_hostname assigned a non-True value")
                    if target.attr == "verify_mode" and not _is_cert_required(value):
                        findings.append(f"{where}: verify_mode assigned other than CERT_REQUIRED")
            elif isinstance(node, ast.keyword) and node.arg in {"check_hostname", "verify"}:
                if isinstance(node.value, ast.Constant) and not node.value.value:
                    findings.append(f"{where}: {node.arg}= set to a false value")
    return findings


def test_no_module_disables_tls_verification() -> None:
    assert _findings() == []


def test_the_scan_reaches_the_transport_and_it_requires_verification() -> None:
    (transport,) = [m for m in modules(PACKAGE / "audit") if m.rel == TRANSPORT]
    assigned = {
        target.attr: node.value
        for node in ast.walk(transport.tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
    }
    assert _is_true(assigned["check_hostname"])
    assert _is_cert_required(assigned["verify_mode"])
    assert TRANSPORT in {m.rel for m in modules()}
