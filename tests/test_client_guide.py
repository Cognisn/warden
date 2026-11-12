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


def test_every_contract_route_is_linked_from_the_guide() -> None:
    linked = set(_LINKED.findall(GUIDE.read_text(encoding="utf-8")))
    missing = sorted(_contract_routes() - linked)
    assert not missing, f"routes the guide does not link: {missing}"


def test_every_route_the_guide_names_is_in_the_contract() -> None:
    named = set(_NAMED.findall(GUIDE.read_text(encoding="utf-8")))
    unknown = sorted(named - _contract_routes())
    assert not unknown, f"routes the guide names that the contract lacks: {unknown}"


def test_the_guide_is_written_with_lf_line_endings() -> None:
    assert b"\r" not in GUIDE.read_bytes()
