"""Single sign-on setup guides: structured, numbered steps per provider preset
(ruling CS15). Presets stay guidance; these tests need no database."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

from warden.config import SsoConfig
from warden.identity.sso.presets import (
    COPY_BACK_SETTINGS,
    PLACEHOLDERS,
    PRESETS,
    SetupGuide,
    setup_guide,
)
from warden.identity.sso.settings import SsoSettings

CALLBACK = "https://app.example.com/auth/sso/callback"
TOKEN = re.compile(r"\{(\w+)\}")
GUIDE_DOC = Path(__file__).resolve().parents[3] / "docs" / "guide" / "sso-providers.md"
NAMES = ["entra", "google", "okta", "generic"]


def settings(**changes: object) -> SsoSettings:
    base = SsoSettings(
        enabled=True,
        issuer_url=None,
        client_id=None,
        scopes=("openid", "email", "profile"),
        allowed_email_domains=(),
        provider_preset="generic",
    )
    return dataclasses.replace(base, **changes)  # type: ignore[arg-type]


def guide(preset: str, **changes: object) -> SetupGuide:
    return setup_guide(
        preset, settings=settings(**changes), callback_uri=CALLBACK, display_name="Example Console"
    )


@pytest.mark.parametrize("preset", NAMES)
def test_every_preset_has_ordered_steps(preset: str) -> None:
    (entry,) = [p for p in PRESETS if p.preset == preset]
    assert len(entry.steps) >= 5
    assert all(s.title and s.text for s in entry.steps)
    assert len({s.title for s in entry.steps}) == len(entry.steps)


@pytest.mark.parametrize("preset", NAMES)
def test_every_placeholder_a_step_uses_is_declared_and_filled(preset: str) -> None:
    (entry,) = [p for p in PRESETS if p.preset == preset]
    for step in entry.steps:
        used = set(TOKEN.findall(step.text))
        assert used == set(step.placeholders), step.title
        assert used <= set(PLACEHOLDERS), step.title
    filled = guide(preset)
    for step in filled.steps:
        assert not TOKEN.search(step.text), step.title
        assert set(step.values) == set(
            next(s for s in entry.steps if s.title == step.title).placeholders
        )


def test_the_api_fills_exactly_the_placeholders_it_declares() -> None:
    assert set(PLACEHOLDERS) == {"callback_uri", "scopes", "issuer", "display_name"}


@pytest.mark.parametrize("preset", NAMES)
def test_every_copy_back_names_a_real_setting(preset: str) -> None:
    (entry,) = [p for p in PRESETS if p.preset == preset]
    named = {c.setting for s in entry.steps for c in s.copy_back}
    # The three values an administrator pastes into warden, each once at least.
    assert named == set(COPY_BACK_SETTINGS) == {"issuer_url", "client_id", "client_secret"}
    fields = {f.name for f in dataclasses.fields(SsoSettings)}
    assert {"issuer_url", "client_id"} <= fields
    assert "client_secret" in SsoConfig.model_fields
    for step in entry.steps:
        for item in step.copy_back:
            assert item.setting in COPY_BACK_SETTINGS
            assert item.label


@pytest.mark.parametrize("preset", NAMES)
def test_the_callback_uri_and_scopes_reach_the_text(preset: str) -> None:
    filled = guide(preset)
    text = "\n".join(s.text for s in filled.steps)
    assert CALLBACK in text
    assert "openid email profile" in text
    assert "Example Console" in text


def test_the_fill_uses_the_instance_values() -> None:
    filled = setup_guide(
        "okta",
        settings=settings(issuer_url="https://idp.example.com/oauth2/default", scopes=("openid",)),
        callback_uri="https://other.example.org/cb",
        display_name="Other",
    )
    text = "\n".join(s.text for s in filled.steps)
    assert "https://other.example.org/cb" in text
    assert CALLBACK not in text
    assert "https://idp.example.com/oauth2/default" in text
    assert "openid email profile" not in text
    values = {k: v for s in filled.steps for k, v in s.values.items()}
    assert values["callback_uri"] == "https://other.example.org/cb"
    assert values["scopes"] == "openid"
    assert values["display_name"] == "Other"


def test_the_issuer_falls_back_to_the_presets_hint_until_one_is_set() -> None:
    (entry,) = [p for p in PRESETS if p.preset == "entra"]
    values = {k: v for s in guide("entra").steps for k, v in s.values.items()}
    assert values["issuer"] == entry.issuer_hint
    values = {
        k: v
        for s in guide("entra", issuer_url="https://login.example.com/t/v2.0").steps
        for k, v in s.values.items()
    }
    assert values["issuer"] == "https://login.example.com/t/v2.0"


def test_an_unknown_preset_falls_back_to_generic() -> None:
    generic = guide("generic")
    for name in ("", "ping", "ENTRA", "../entra"):
        assert guide(name) == generic
    assert generic.preset == "generic"
    assert guide("entra").preset == "entra"
    assert guide("entra") != generic


def test_the_guides_do_not_carry_real_identifiers_or_long_dashes() -> None:
    uuid_like = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    for entry in PRESETS:
        for step in entry.steps:
            assert not uuid_like.search(step.text), step.title
            assert chr(0x2014) not in step.text + step.title
            assert chr(0x2013) not in step.text + step.title


def test_the_provider_guide_matches_the_data() -> None:
    doc = GUIDE_DOC.read_text(encoding="utf-8")
    for entry in PRESETS:
        assert entry.label in doc
        for number, step in enumerate(entry.steps, start=1):
            assert f"{number}. {step.title}" in doc, (entry.preset, step.title)
    assert doc.count("Checked on 2026-11-23") >= 4
    assert chr(0x2014) not in doc and chr(0x2013) not in doc
