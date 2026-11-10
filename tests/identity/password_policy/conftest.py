"""Fixtures for password policy tests: identity's audit actions are registered,
as ``Identity`` registers them at construction, for tests that use a store alone."""

from __future__ import annotations

import pytest

from warden.audit import ActionRegistry
from warden.identity.actions import register_actions


@pytest.fixture(autouse=True)
def _identity_actions(audit_registry: ActionRegistry) -> None:
    register_actions(audit_registry)
