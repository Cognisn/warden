"""The client-behaviour guide (docs/guide/clients.md) and the contract agree on the routes.

Every operation in ``docs/contract/openapi.json`` is named in the guide as a
link to the contract, and every route the guide names is in the contract, so
neither can gain or lose a route without the other.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "guide" / "clients.md"
CONTRACT = ROOT / "docs" / "contract" / "openapi.json"
METHODS = ("get", "put", "post", "delete", "patch")
_LINKED = re.compile(r"\[`(GET|PUT|POST|DELETE|PATCH) (/[^`\s]*)`\]\(\.\./contract/openapi\.json\)")
_NAMED = re.compile(r"`(GET|PUT|POST|DELETE|PATCH) (/[^`\s]*)`")


def _contract_routes() -> set[tuple[str, str]]:
    document = json.loads(CONTRACT.read_text(encoding="utf-8"))
    return {
        (method.upper(), path)
        for path, item in document["paths"].items()
        for method in item
        if method in METHODS
    }


# Routes added in wave 17 (feat/0.1.0-password-policy-admin) that the guide
# does not link yet: docs/guide/ belongs to wave 18's guide workstream
# (ruling PW13), which links each one and removes it from this set. The
# companion test fails for an entry that is linked already or has left the
# contract, so the set can only shrink.
_AWAITING_GUIDE = frozenset(
    {
        ("GET", "/admin/password-policies"),
        ("POST", "/admin/password-policies"),
        ("GET", "/admin/password-policies/{policy_id}"),
        ("PUT", "/admin/password-policies/{policy_id}"),
        ("DELETE", "/admin/password-policies/{policy_id}"),
        ("PUT", "/admin/password-policies/{policy_id}/priority"),
        ("PUT", "/admin/password-policy-order"),
        ("PUT", "/admin/password-policies/{policy_id}/builtin-list"),
        ("PUT", "/admin/password-policies/{policy_id}/watch-lists/{list_id}"),
        ("DELETE", "/admin/password-policies/{policy_id}/watch-lists/{list_id}"),
        ("GET", "/admin/password-policies/{policy_id}/affected-users"),
        ("POST", "/admin/password-policies/affected-users"),
        ("PUT", "/admin/password-policy-roles/{role}"),
        ("DELETE", "/admin/password-policy-roles/{role}"),
        ("GET", "/admin/users/{user_id}/password-policy"),
        ("PUT", "/admin/users/{user_id}/password-policy"),
        ("DELETE", "/admin/users/{user_id}/password-policy"),
        ("PUT", "/admin/users/{user_id}/password-change-required"),
        ("DELETE", "/admin/users/{user_id}/password-change-required"),
        ("GET", "/admin/watch-lists"),
        ("POST", "/admin/watch-lists"),
        ("GET", "/admin/watch-lists/{list_id}"),
        ("PUT", "/admin/watch-lists/{list_id}"),
        ("DELETE", "/admin/watch-lists/{list_id}"),
        ("POST", "/admin/watch-lists/{list_id}/entries"),
        ("POST", "/admin/watch-lists/{list_id}/entries/removal"),
        ("POST", "/admin/watch-lists/{list_id}/terms"),
        ("POST", "/admin/watch-lists/{list_id}/terms/removal"),
        ("GET", "/admin/password-exposures"),
    }
)


def test_every_contract_route_is_linked_from_the_guide() -> None:
    linked = set(_LINKED.findall(GUIDE.read_text(encoding="utf-8")))
    missing = sorted(_contract_routes() - linked - _AWAITING_GUIDE)
    assert not missing, f"routes the guide does not link: {missing}"


def test_routes_awaiting_the_guide_are_in_the_contract_and_not_yet_linked() -> None:
    linked = set(_LINKED.findall(GUIDE.read_text(encoding="utf-8")))
    assert sorted(_AWAITING_GUIDE - _contract_routes()) == []
    assert sorted(_AWAITING_GUIDE & linked) == []


def test_every_route_the_guide_names_is_in_the_contract() -> None:
    named = set(_NAMED.findall(GUIDE.read_text(encoding="utf-8")))
    unknown = sorted(named - _contract_routes())
    assert not unknown, f"routes the guide names that the contract lacks: {unknown}"


def test_the_guide_is_written_with_lf_line_endings() -> None:
    assert b"\r" not in GUIDE.read_bytes()
