"""Tripwire: every warden audit event carries the client address, unless it has no request.

Scans ``src/warden`` for every ``AuditEvent(...)`` whose action begins
``warden.`` (a literal, an f-string, a module constant, or a parameter, which
counts as one) and fails when it has no ``source_ip`` keyword, or passes the
literal ``None``. Each exception is on ``ALLOWED``, keyed by module, enclosing
function and action, with the reason the event has no request to take an
address from: start-up, the warden command line, or a background job.

Companion checks refuse an allow-list entry without such a reason, and an
entry that no longer matches a call without ``source_ip``, so the list cannot
grow quietly or go stale. Another asserts the scan still finds the calls, so
the guard cannot pass vacuously.

The routes' own tests (``tests/identity/test_audit_source_ip_routes.py``)
show the address reaches the row; this guard keeps a new event from being
written without a way to carry it (GitHub #3).
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass

from tripwires.source import Module, modules

# Why an event may have no address. The reason must say which, then why.
REASON_KINDS = ("start-up: ", "cli: ", "background: ")
MIN_REASON_WORDS = 8

# (module, enclosing function, action as written) -> reason.
ALLOWED: dict[tuple[str, str, str], str] = {
    ("warden/audit/anchor.py", "anchor", "ANCHOR_ACTION"): (
        "cli: `warden audit anchor` and a product's scheduled anchoring append the anchor; "
        "warden has no anchoring route, so no request supplies an address."
    ),
    ("warden/audit/retention.py", "purge", "PURGE_ACTION"): (
        "cli: `warden audit purge` runs the retention purge, refusing a broken chain; "
        "warden has no purge route, so no request supplies an address."
    ),
    ("warden/audit/retention.py", "_purge_prefix", "PURGE_ACTION"): (
        "cli: `warden audit purge` writes the signed checkpoint; warden has no purge route, "
        "so no request supplies an address."
    ),
    (
        "warden/identity/password_policy/store.py",
        "PasswordPolicies.ensure_default",
        "'warden.identity.password_policy.created'",
    ): (
        "start-up: the default password policy is seeded once from configuration, by warden "
        "itself with no actor, on the first read of the policies, whichever caller makes it; "
        "it is not an administrator's change made in answer to a request."
    ),
}


@dataclass(frozen=True)
class Site:
    module: str
    function: str
    action: str
    line: int
    source_ip: str | None
    """The ``source_ip`` keyword as written, or None when absent."""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.module, self.function, self.action)


def _constants() -> dict[str, str]:
    """Every module-level string constant in warden, by name."""
    found: dict[str, str] = {}
    for module in modules():
        for node in module.tree.body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        found[target.id] = node.value.value
    return found


def _is_warden(action: ast.expr, constants: dict[str, str]) -> bool:
    if isinstance(action, ast.Constant) and isinstance(action.value, str):
        return action.value.startswith("warden.")
    if isinstance(action, ast.JoinedStr):
        first = action.values[0] if action.values else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.startswith("warden.")
        return True
    if isinstance(action, ast.Name) and action.id in constants:
        return constants[action.id].startswith("warden.")
    # A parameter or anything else unresolved: assume it is warden's.
    return True


def _sites_in(module: Module, constants: dict[str, str]) -> list[Site]:
    sites: list[Site] = []

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            scope = (*scope, node.name)
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name == "AuditEvent":
                keywords = {k.arg: k.value for k in node.keywords if k.arg is not None}
                action = keywords.get("action")
                if action is None or _is_warden(action, constants):
                    given = keywords.get("source_ip")
                    sites.append(
                        Site(
                            module=module.rel,
                            function=".".join(_owner(scope)),
                            action="?" if action is None else ast.unparse(action),
                            line=node.lineno,
                            source_ip=None if given is None else ast.unparse(given),
                        )
                    )
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(module.tree, ())
    return sites


def _owner(scope: tuple[str, ...]) -> tuple[str, ...]:
    """The class and method, or the function, a call sits in (nested routes keep their name)."""
    return scope[-2:] if len(scope) >= 2 and scope[-2][:1].isupper() else scope[-1:]


def sites() -> list[Site]:
    constants = _constants()
    return [site for module in modules() for site in _sites_in(module, constants)]


def _missing(site: Site) -> bool:
    return site.source_ip is None or site.source_ip == "None"


def test_every_warden_audit_event_carries_the_client_address() -> None:
    offenders = [
        f"{s.module}:{s.line} {s.function} {s.action} (source_ip={s.source_ip})"
        for s in sites()
        if _missing(s) and s.key not in ALLOWED
    ]
    assert not offenders, (
        "these audit events record no client address; pass source_ip through from the "
        "request, or, if no request can reach them, add them to ALLOWED with the reason:\n"
        + "\n".join(offenders)
    )


def test_every_allowed_event_says_why_it_has_no_request() -> None:
    unreasoned = [
        key
        for key, reason in ALLOWED.items()
        if not reason.startswith(REASON_KINDS)
        or len(reason.split()) < MIN_REASON_WORDS
        or "request" not in reason
    ]
    assert not unreasoned, (
        f"every allow-list entry needs a reason beginning one of {REASON_KINDS}, saying why "
        f"no request supplies an address: {unreasoned}"
    )


def test_every_allowed_event_still_exists_without_an_address() -> None:
    missing = {s.key for s in sites() if _missing(s)}
    stale = sorted(set(ALLOWED) - missing)
    assert not stale, f"allow-list entries that match no call without source_ip: {stale}"


def test_the_scan_still_finds_warden_audit_events() -> None:
    found = sites()
    assert len(found) >= 60, f"the scan found only {len(found)} audit events"
    by_module = Counter(s.module for s in found)
    for module in (
        "warden/identity/roles.py",
        "warden/identity/users.py",
        "warden/identity/service.py",
        "warden/audit/retention.py",
    ):
        assert by_module[module], f"the scan found no audit event in {module}"
