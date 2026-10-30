"""The committed HTTP contract (docs/contract/openapi.json) matches the routes.

``scripts/export_openapi.py`` mounts every warden router under the default
prefixes in a reference app and writes its OpenAPI document. This test
regenerates the document and fails on any difference, so a change to a
route's path, parameters or documented responses shows in review as a change
to the committed contract. Regenerate with ``python scripts/export_openapi.py``.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi import APIRouter
from fastapi.routing import APIRoute

from warden.config import HttpConfig
from warden.identity import Identity
from warden.identity.http import REFUSAL_BODY

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export_openapi.py"
CONTRACT = ROOT / "docs" / "contract" / "openapi.json"
METHODS = ("get", "put", "post", "delete", "patch")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("export_openapi", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["export_openapi"] = module
    spec.loader.exec_module(module)
    return module


exporter = _load()


def _operations(document: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (path, method, operation)
        for path, item in document["paths"].items()
        for method, operation in item.items()
        if method in METHODS
    ]


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(exporter.openapi_text())
    return loaded


def test_the_committed_contract_matches_the_routes() -> None:
    committed = CONTRACT.read_text(encoding="utf-8")
    assert committed == exporter.openapi_text(), (
        "the HTTP contract changed; run python scripts/export_openapi.py and commit the result"
    )


def test_the_contract_is_written_with_lf_line_endings() -> None:
    assert b"\r" not in CONTRACT.read_bytes()


def test_the_drift_check_sees_a_changed_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # The guard's own can-fail companion: the same app with one route moved
    # gives a different document.
    committed = exporter.openapi_text()
    original = Identity.auth_router

    def moved(self: Identity) -> APIRouter:
        router = original(self)
        route = next(r for r in router.routes if isinstance(r, APIRoute) and r.path == "/sign-in")
        route.path = "/log-in"
        return router

    monkeypatch.setattr(Identity, "auth_router", moved)
    changed = exporter.openapi_text()
    assert changed != committed
    assert "/auth/log-in" in json.loads(changed)["paths"]


def test_the_reference_app_mounts_every_router_under_the_default_prefixes(
    document: dict[str, Any],
) -> None:
    http = HttpConfig(public_base_url="https://app.example.com")
    expected = {
        f"{http.auth_prefix}/sign-in",
        f"{http.auth_prefix}/invitations/accept",
        f"{http.auth_prefix}/sso/start",
        f"{http.admin_prefix}/users",
        f"{http.admin_prefix}/sso/settings",
        f"{http.audit_prefix}/events",
        f"{http.audit_prefix}/syslog/status",
        f"{http.keys_prefix}/jwks.json",
    }
    assert expected <= set(document["paths"])


def test_the_check_option_reports_drift(tmp_path: Path) -> None:
    stale = tmp_path / "openapi.json"
    stale.write_text("{}\n", encoding="utf-8", newline="\n")
    assert exporter.main(["--check", "--output", str(stale)]) == 1
    exporter.main(["--output", str(stale)])
    assert exporter.main(["--check", "--output", str(stale)]) == 0
    assert stale.read_text(encoding="utf-8") == exporter.openapi_text()


def test_every_operation_has_a_summary_a_description_and_a_tag(
    document: dict[str, Any],
) -> None:
    for path, method, operation in _operations(document):
        where = f"{method.upper()} {path}"
        assert operation.get("summary"), where
        assert operation.get("description"), where
        assert operation.get("tags"), where


# Routes with no failure to document: the reset request always answers 202,
# and the published key sets are public and unconditional.
NEVER_FAIL = {
    ("/auth/password-reset", "post"),
    ("/keys/jwks.json", "get"),
    ("/keys/jwks-historical.json", "get"),
}


def test_every_operation_documents_a_failure_response(document: dict[str, Any]) -> None:
    for path, method, operation in _operations(document):
        if (path, method) in NEVER_FAIL:
            continue
        codes = {code for code in operation["responses"] if not code.startswith(("2", "3"))}
        assert codes, f"{method.upper()} {path} documents no failure"


def test_every_documented_response_has_a_description(document: dict[str, Any]) -> None:
    for path, method, operation in _operations(document):
        for code, response in operation["responses"].items():
            assert response.get("description"), f"{method.upper()} {path} {code}"


def test_the_uniform_refusal_schema_admits_only_its_exact_body(
    document: dict[str, Any],
) -> None:
    schema = document["components"]["schemas"]["WardenRefusal"]
    assert schema["properties"]["detail"]["const"] == "authentication failed"
    assert schema["required"] == ["detail"]
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/auth/sign-in", "post"),
        ("/auth/totp/verify", "post"),
        ("/auth/recovery-code", "post"),
        ("/auth/refresh", "post"),
        ("/auth/sign-out", "post"),
        ("/auth/password", "post"),
        ("/auth/totp/enrolment", "post"),
        ("/auth/totp/enrolment/confirm", "post"),
        ("/auth/invitations/accept", "post"),
        ("/auth/password-reset/complete", "post"),
        ("/auth/sso/handoff", "post"),
        ("/admin/users", "get"),
        ("/admin/api-keys", "post"),
    ],
)
def test_routes_that_refuse_uniformly_point_at_the_uniform_refusal(
    document: dict[str, Any], path: str, method: str
) -> None:
    response = document["paths"][path][method]["responses"]["401"]
    content = response["content"]["application/json"]
    assert content["schema"] == {"$ref": "#/components/schemas/WardenRefusal"}
    assert json.dumps(content["example"], separators=(",", ":")).encode() == REFUSAL_BODY
    assert "www-authenticate" in response["headers"]


def test_every_json_body_route_documents_its_request_body(document: dict[str, Any]) -> None:
    # Identity's routes read their bodies themselves (so FastAPI's 422 never
    # echoes a password); the contract still states each body's shape.
    for path, method, operation in _operations(document):
        if method in ("post", "put") and path.startswith(("/auth/", "/admin/")):
            bodiless = {
                ("/auth/sign-out", "post"),
                ("/admin/sso/settings/reset", "post"),
                ("/admin/sso/test", "post"),
                ("/admin/users/{user_id}/password-reset", "post"),
                ("/admin/invitations/{user_id}/resend", "post"),
            }
            if (path, method) in bodiless:
                continue
            body = operation.get("requestBody")
            assert body is not None, f"{method.upper()} {path}"
            assert "application/json" in body["content"], f"{method.upper()} {path}"
