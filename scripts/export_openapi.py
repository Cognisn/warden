"""Export warden's HTTP contract as an OpenAPI document.

Builds a reference app that mounts every warden router under the default
prefixes of ``HttpConfig``, as a product would, and writes the app's OpenAPI
document to ``docs/contract/openapi.json``::

    python scripts/export_openapi.py            # write the document
    python scripts/export_openapi.py --check    # exit 1 if the committed one differs

The reference app is never served: it has no database, so building it opens
no connection, and every value in it is synthetic. ``tests/test_openapi_contract.py``
regenerates the document and fails on any difference, so a route change shows
in review as a change to the committed contract.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from psycopg import AsyncConnection

import warden
from warden.audit import ActionRegistry, AuditRecorder, set_recorder
from warden.audit.router import audit_router
from warden.audit.syslog import SyslogForwarder, SyslogSettings, syslog_router
from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry, new_totp_key
from warden.jwks import keys_router
from warden.keys import KeyStore

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "contract" / "openapi.json"

ADMIN_PERMISSION = "example.administer"

DESCRIPTION = """\
The HTTP contract of warden, the identity and audit library for Cognisn \
products. A product mounts warden's routers under prefixes it chooses; this \
document shows them under the defaults (`/auth`, `/admin`, `/audit` and `/keys`). \
What a client must do with these routes (token storage, refresh, the uniform \
refusal, single sign-on, the throttle) is in `docs/guide/clients.md`.

Routes under `/audit` and the single sign-on administration routes under \
`/admin/sso` are guarded by an authorisation dependency the product supplies; \
their refusals are the product's own.
"""


class _NoDatabase:
    """A connection source that refuses: the reference app is described, never served."""

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection[Any]]:
        raise RuntimeError("the reference app has no database")
        yield  # pragma: no cover


class _Secrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def get(self, key: str) -> str | None:
        return self._values.get(key)

    def set(self, key: str, value: str) -> None:
        self._values[key] = value


async def _product_authorisation() -> None:
    """Stands in for the product's dependency, which refuses or returns an actor id."""
    return None


def contract_version() -> str:
    """The contract's version: the release series, so pre-release stamps leave it alone."""
    major, minor = warden.__version__.split(".")[:2]
    return f"{major}.{minor}"


def reference_config() -> WardenConfig:
    return parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept-invitation?t={token}",
                "reset_password_link": "https://app.example.com/reset-password?t={token}",
                "sso_completion_link": "https://app.example.com/sso-complete",
            }
        }
    )


def build_reference_app() -> FastAPI:
    """Every warden router, mounted under the default prefixes."""
    config = reference_config()
    db = Database(_NoDatabase())
    secrets = _Secrets({config.identity.totp_key_secret: new_totp_key()})
    keys = KeyStore(db, secrets, config.keys)
    recorder = AuditRecorder(db, ActionRegistry())
    permissions = PermissionRegistry()
    permissions.register_permission(ADMIN_PERMISSION, "Administer users and single sign-on")
    forwarder = SyslogForwarder(
        db, SyslogSettings(host="syslog.example.com", port=6514, hostname="app.example.com")
    )

    # Identity registers its audit actions with the installed recorder while it
    # is built; put back whatever was installed before.
    previous = set_recorder(recorder)
    try:
        identity = Identity(config, db, keys, permissions, secrets=secrets)
    finally:
        set_recorder(previous)

    http = config.http
    app = FastAPI(
        title="warden",
        version=contract_version(),
        description=DESCRIPTION,
        license_info={"name": "Apache-2.0", "identifier": "Apache-2.0"},
    )
    identity.install(app)
    app.include_router(identity.auth_router(), prefix=http.auth_prefix)
    app.include_router(identity.lifecycle_router(), prefix=http.auth_prefix)
    app.include_router(identity.sso_router(), prefix=http.auth_prefix)
    app.include_router(identity.admin_router(permission=ADMIN_PERMISSION), prefix=http.admin_prefix)
    app.include_router(
        identity.sso_settings_router(authorise=_product_authorisation), prefix=http.admin_prefix
    )
    app.include_router(
        audit_router(recorder=recorder, keys=keys, authorise=_product_authorisation),
        prefix=http.audit_prefix,
    )
    app.include_router(
        syslog_router(forwarder, authorise=_product_authorisation, recorder=recorder),
        prefix=http.audit_prefix,
    )
    app.include_router(keys_router(keys=keys), prefix=http.keys_prefix)
    return app


def render(document: dict[str, Any]) -> str:
    """The document as committed: two-space indent, ASCII, one trailing newline."""
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


def openapi_text() -> str:
    return render(build_reference_app().openapi())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export warden's OpenAPI contract.")
    parser.add_argument("--check", action="store_true", help="fail if the document differs")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="the document's path")
    args = parser.parse_args(argv)
    text = openapi_text()
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else None
        if current != text:
            print("the OpenAPI contract is out of date; run scripts/export_openapi.py")
            return 1
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
