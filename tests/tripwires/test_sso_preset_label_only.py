"""Tripwire: the single sign-on provider preset is a label, never behaviour.

``sso.provider_preset`` (entra, google, okta, generic) picks the setup
guidance an administrator sees. No identity module that signs anyone in may
read it, import the presets, or name a preset, so sign-in cannot branch on
it. Only the modules that store and present the label may.
"""

from __future__ import annotations

import typing

from tripwires.source import (
    PACKAGE,
    Module,
    identifiers,
    imported_modules,
    modules,
    string_literals,
)
from warden.config import SsoConfig

IDENTITY = PACKAGE / "identity"
# The modules that store or present the label; nothing else may touch it.
ALLOWED = {
    "warden/identity/sso/presets.py",
    "warden/identity/sso/settings.py",
    "warden/identity/routers/sso_settings.py",
}
# Sign-in code the scan must cover, so it cannot pass by scanning nothing.
SIGN_IN = {
    "warden/identity/service.py",
    "warden/identity/sso/service.py",
    "warden/identity/sso/provider.py",
    "warden/identity/sso/validation.py",
    "warden/identity/routers/sso.py",
    "warden/identity/routers/auth.py",
}
FIELD = "provider_preset"
PRESETS_MODULE = "warden.identity.sso.presets"


def preset_names() -> set[str]:
    annotation = SsoConfig.model_fields[FIELD].annotation
    return {str(v) for v in typing.get_args(annotation)}


def _violations(module: Module) -> list[str]:
    names = preset_names()
    found = [f"reads {n}" for n in identifiers(module.tree) if n in {FIELD, "PRESETS"}]
    found += [f"imports {m}" for m in imported_modules(module) if m.startswith(PRESETS_MODULE)]
    found += [
        f"names {s!r}" for s in string_literals(module.tree) if s == FIELD or s.lower() in names
    ]
    return found


def scanned() -> list[Module]:
    return [m for m in modules(IDENTITY) if m.rel not in ALLOWED]


def test_no_sign_in_module_reads_the_preset() -> None:
    offenders = {m.rel: v for m in scanned() if (v := _violations(m))}
    assert offenders == {}


def test_the_scan_covers_the_sign_in_code() -> None:
    assert {m.rel for m in scanned()} >= SIGN_IN


def test_the_allowed_modules_really_carry_the_label() -> None:
    by_rel = {m.rel: m for m in modules(IDENTITY)}
    assert set(by_rel) >= ALLOWED
    for rel in ALLOWED:
        assert _violations(by_rel[rel]), f"{rel} no longer touches the preset; narrow ALLOWED"


def test_every_configured_preset_has_guidance() -> None:
    from warden.identity.sso.presets import PRESETS

    assert preset_names() == {"entra", "google", "okta", "generic"}
    assert {p.preset for p in PRESETS} == preset_names()
