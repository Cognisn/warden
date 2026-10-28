"""The ``warden.`` action namespace belongs to warden (ruling of 27 October 2026).

Every action warden itself registers lives under ``warden.``. A product's
registration in that namespace is refused, so a product cannot shadow or
pre-empt one of warden's own actions; warden registers through an internal
path.
"""

from __future__ import annotations

import pytest

from warden.audit import ActionRegistry, Severity
from warden.audit.actions import register_audit_actions
from warden.audit.syslog import register_syslog_actions
from warden.identity.actions import IDENTITY_ACTIONS, register_actions


@pytest.mark.parametrize(
    "action", ["warden.audit.purge", "warden.identity.sign_in", "warden.product.thing"]
)
def test_a_product_registration_in_the_warden_namespace_is_refused(action: str) -> None:
    registry = ActionRegistry()
    with pytest.raises(ValueError, match="reserved"):
        registry.register(action, severity=Severity.NOTICE, summary="{actor}")
    assert action not in registry


def test_a_product_cannot_pre_empt_a_warden_action() -> None:
    registry = ActionRegistry()
    with pytest.raises(ValueError):
        registry.register("warden.audit.export", severity=Severity.DEBUG, summary="quiet")
    register_audit_actions(registry)
    assert registry.get("warden.audit.export").severity == Severity.NOTICE


@pytest.mark.parametrize("action", ["wardens.thing", "product.warden", "vor.warden.thing"])
def test_names_merely_containing_warden_are_the_products(action: str) -> None:
    registry = ActionRegistry()
    registry.register(action, severity=Severity.INFO, summary="{actor}")
    assert action in registry


def test_every_action_warden_registers_is_in_the_warden_namespace() -> None:
    registry = ActionRegistry()
    register_audit_actions(registry)
    register_syslog_actions(registry)
    register_actions(registry)
    names = [spec.action for spec in registry.actions()]
    assert len(names) == 4 + len(IDENTITY_ACTIONS)
    assert all(name.startswith("warden.") for name in names), names
    assert "warden.audit.anchor" in names
    assert "warden.syslog.test_sent" in names
    assert "warden.identity.sign_in" in names
    assert not any(name.startswith("identity.") for name in names)


def test_warden_registrations_stay_idempotent() -> None:
    registry = ActionRegistry()
    for _ in range(2):
        register_audit_actions(registry)
        register_syslog_actions(registry)
        register_actions(registry)
