"""Fixtures for the WebAuthn ceremonies: the service, a test CA and user helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from soft_authenticator import TestCa

from warden.config import WardenConfig, parse_config
from warden.db import Database
from warden.identity.webauthn import WebAuthn


def webauthn_config(**webauthn: Any) -> WardenConfig:
    return parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "identity": {"require_mfa": False},
            "webauthn": webauthn,
        }
    )


WebAuthnFactory = Callable[..., WebAuthn]


@pytest.fixture
def make_webauthn(db: Database) -> WebAuthnFactory:
    def factory(**webauthn: Any) -> WebAuthn:
        return WebAuthn(webauthn_config(**webauthn), db)

    return factory


@pytest.fixture
def webauthn(make_webauthn: WebAuthnFactory) -> WebAuthn:
    return make_webauthn()


@pytest.fixture(scope="session")
def ca() -> TestCa:
    return TestCa.create("Example")


@pytest.fixture(scope="session")
def rogue_ca() -> TestCa:
    return TestCa.create("Rogue")


@pytest.fixture
def strict_webauthn(make_webauthn: WebAuthnFactory, ca: TestCa) -> WebAuthn:
    """A relying party that trusts only ``ca``'s attestation root (ruling P3)."""
    return make_webauthn(attestation_roots=ca.root_pem)
