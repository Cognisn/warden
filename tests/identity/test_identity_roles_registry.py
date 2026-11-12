"""The product's permission registry and role definitions. No database."""

from __future__ import annotations

import pytest

from warden.identity.roles import PermissionRegistry


@pytest.fixture
def registry() -> PermissionRegistry:
    registry = PermissionRegistry()
    registry.register_permission("cases.read", "Read cases")
    registry.register_permission("cases.write", "Edit cases")
    registry.register_permission("users.manage", "Manage users")
    return registry


def test_roles_are_named_permission_sets(registry: PermissionRegistry) -> None:
    registry.define_role("analyst", {"cases.read", "cases.write"})
    assert registry.role("analyst").permissions == frozenset({"cases.read", "cases.write"})
    assert not registry.role("analyst").administrator


def test_permissions_for_several_roles_are_the_union(registry: PermissionRegistry) -> None:
    registry.define_role("viewer", {"cases.read"})
    registry.define_role("admin", {"users.manage"}, administrator=True)
    assert registry.permissions_for(["viewer", "admin"]) == frozenset(
        {"cases.read", "users.manage"}
    )


def test_unknown_roles_grant_nothing(registry: PermissionRegistry) -> None:
    registry.define_role("viewer", {"cases.read"})
    assert registry.permissions_for(["viewer", "retired-role"]) == frozenset({"cases.read"})


def test_a_role_may_only_use_registered_permissions(registry: PermissionRegistry) -> None:
    with pytest.raises(ValueError, match="unregistered"):
        registry.define_role("viewer", {"cases.read", "cases.delete"})


def test_redefinition_must_match(registry: PermissionRegistry) -> None:
    registry.define_role("viewer", {"cases.read"})
    registry.define_role("viewer", {"cases.read"})
    with pytest.raises(ValueError, match="already defined"):
        registry.define_role("viewer", {"cases.write"})
    registry.register_permission("cases.read", "Read cases")
    with pytest.raises(ValueError, match="already registered"):
        registry.register_permission("cases.read", "Something else")


def test_administrator_roles_are_listed(registry: PermissionRegistry) -> None:
    registry.define_role("viewer", {"cases.read"})
    registry.define_role("admin", {"users.manage"}, administrator=True)
    registry.define_role("owner", {"users.manage", "cases.write"}, administrator=True)
    assert registry.administrator_roles() == frozenset({"admin", "owner"})


@pytest.mark.parametrize(
    "name", ["Cases.read", "cases", "cases.", ".read", "cases read", "cases.read\n", "cäses.read"]
)
def test_permission_names_are_dotted_lower_case(registry: PermissionRegistry, name: str) -> None:
    with pytest.raises(ValueError):
        registry.register_permission(name, "x")


@pytest.mark.parametrize("name", ["", "Admin", "admin\n", "has space", "-admin", "a" * 65])
def test_role_names_are_validated(registry: PermissionRegistry, name: str) -> None:
    with pytest.raises(ValueError):
        registry.define_role(name, {"cases.read"})


def test_unknown_role_lookup_raises(registry: PermissionRegistry) -> None:
    with pytest.raises(KeyError):
        registry.role("nobody")
    assert "nobody" not in registry
