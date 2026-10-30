"""Single sign-on administration routes. The product mounts them under
``config.http.admin_prefix`` and supplies ``authorise``.

| Route | Body | Answer |
|---|---|---|
| ``GET /sso/settings`` | | the effective settings, the callback URI, presets |
| ``PUT /sso/settings`` | fields to change | the effective settings |
| ``POST /sso/settings/reset`` | | the configuration's settings |
| ``PUT /sso/client-secret`` | ``client_secret`` | 204; the secret is never returned |
| ``POST /sso/test`` | | a configuration report; nobody is signed in |
| ``DELETE /sso/users/{user_id}/pin`` | | 204, or 404 if there was no pin |

Turning ``enabled`` off ends every session issued through single sign-on.
"""

# No ``from __future__ import annotations``: FastAPI must resolve the local
# ``Actor`` dependency alias at definition time.

import dataclasses
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from warden.identity.http import NO_STORE, SourceIp, client_ip, json_response, read_object
from warden.identity.routers.contract import (
    PRODUCT_AUTHORISATION,
    SsoClientSecretBody,
    WardenSsoReport,
    detail,
    json_body,
    no_store,
)
from warden.identity.sso.presets import PRESETS
from warden.identity.sso.settings import SsoSettings, SsoSettingsError

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_sso_settings_router"]


# Documentation models for the contract, here rather than in
# ``routers.contract`` because only this module may name the preset (see
# ``tests/tripwires/test_sso_preset_label_only.py``). Never used to parse or
# build a request or response.


class WardenPresetGuide(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preset: str
    label: str
    issuer_hint: str
    notes: str


class WardenSsoSettingsView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    issuer_url: str | None
    client_id: str | None
    scopes: list[str]
    allowed_email_domains: list[str]
    provider_preset: str | None
    callback_url: str = Field(description="The redirect URI to register with the provider.")
    client_secret_set: bool
    presets: list[WardenPresetGuide] = Field(description="Setup guidance; labels only.")


class SsoSettingsBody(BaseModel):
    """Only the fields to change; each is validated by the configuration's rules."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    issuer_url: str | None = None
    client_id: str | None = None
    scopes: list[str] | None = None
    allowed_email_domains: list[str] | None = None
    provider_preset: str | None = Field(
        default=None, description="A label for setup guidance: one of `presets[].preset`."
    )


_VIEW = {"model": WardenSsoSettingsView, "description": "The effective settings."}


def build_sso_settings_router(identity: "Identity", *, authorise: Callable[..., Any]) -> APIRouter:
    router = APIRouter(tags=["warden: single sign-on administration"])
    Actor = Annotated[Any, Depends(authorise)]
    trusted_proxies = tuple(identity.config.audit.trusted_proxies)

    def source(request: Request) -> SourceIp:
        return client_ip(request, trusted_proxies)

    def actor_id(actor: Any) -> str | None:
        return None if actor is None else str(actor)

    def view(settings: SsoSettings) -> Response:
        body: dict[str, Any] = {
            "enabled": settings.enabled,
            "issuer_url": settings.issuer_url,
            "client_id": settings.client_id,
            "scopes": list(settings.scopes),
            "allowed_email_domains": list(settings.allowed_email_domains),
            "provider_preset": settings.provider_preset,
            "callback_url": identity.sso.callback_url,
            "client_secret_set": identity.sso.client_secret_set(),
            "presets": [dataclasses.asdict(p) for p in PRESETS],
        }
        return json_response(body)

    @router.get(
        "/sso/settings",
        summary="Show the single sign-on settings",
        description=(
            "The effective settings (run-time overrides over the configuration), the derived "
            "callback URI to register with the provider, whether a client secret is stored "
            "(never the secret), and setup guidance for each provider preset."
        ),
        responses={200: _VIEW, **PRODUCT_AUTHORISATION},
    )
    async def get_settings(actor: Actor) -> Response:
        return view(await identity.sso.settings.current())

    @router.put(
        "/sso/settings",
        summary="Change the single sign-on settings",
        description=(
            "Only the fields given change; each is checked by the configuration's rules, and "
            "the 400 names the fields, never their values. Turning `enabled` off ends every "
            "session issued through single sign-on, in the same transaction."
        ),
        responses={
            200: _VIEW,
            400: detail(
                "Not a JSON object, an unknown or invalid field, or a field missing while enabled.",
                "the body must be a JSON object",
                "invalid settings: issuer_url",
            ),
            **PRODUCT_AUTHORISATION,
        },
        openapi_extra=json_body(SsoSettingsBody),
    )
    async def put_settings(request: Request, actor: Actor) -> Response:
        body = await read_object(request)
        if body is None:
            return json_response({"detail": "the body must be a JSON object"}, 400)
        try:
            settings = await identity.sso.settings.update(actor=actor_id(actor), **body)
        except SsoSettingsError as exc:
            return json_response({"detail": str(exc)}, 400)
        return view(settings)

    @router.post(
        "/sso/settings/reset",
        summary="Drop the run-time overrides",
        description="Back to the configuration's settings.",
        responses={200: _VIEW, **PRODUCT_AUTHORISATION},
    )
    async def reset_settings(actor: Actor) -> Response:
        return view(await identity.sso.settings.reset(actor=actor_id(actor)))

    @router.put(
        "/sso/client-secret",
        status_code=204,
        summary="Store the OIDC client secret",
        description=(
            "Written to konfig's secrets store under the name in `sso.client_secret`; never "
            "returned or logged."
        ),
        responses={
            204: {"description": "Stored.", "headers": no_store()},
            400: detail(
                "Not a usable secret.", "the client secret must be 1 to 4096 printable characters"
            ),
            **PRODUCT_AUTHORISATION,
        },
        openapi_extra=json_body(SsoClientSecretBody),
    )
    async def put_client_secret(request: Request, actor: Actor) -> Response:
        body = await read_object(request) or {}
        try:
            await identity.sso.set_client_secret(
                body.get("client_secret"), actor=actor_id(actor), source_ip=source(request)
            )
        except ValueError:
            return json_response(
                {"detail": "the client secret must be 1 to 4096 printable characters"}, 400
            )
        return Response(status_code=204, headers=NO_STORE)

    @router.post(
        "/sso/test",
        summary="Test the single sign-on configuration",
        description=(
            "Checks the settings, the client secret, discovery, the shared signing algorithms "
            "and the provider's JWKS. It signs nobody in and redeems nothing."
        ),
        responses={
            200: {"model": WardenSsoReport, "description": "Each check and its reason."},
            **PRODUCT_AUTHORISATION,
        },
    )
    async def test_configuration(request: Request, actor: Actor) -> Response:
        report = await identity.sso.test_configuration(
            actor=actor_id(actor), source_ip=source(request)
        )
        return json_response(
            {"ok": report.ok, "checks": [dataclasses.asdict(c) for c in report.checks]}
        )

    @router.delete(
        "/sso/users/{user_id}/pin",
        status_code=204,
        summary="Remove a user's single sign-on subject pin",
        description=(
            "The user's next single sign-on matches by verified email again and pins the new "
            "subject, for example after the provider re-created the account."
        ),
        responses={
            204: {"description": "Unpinned.", "headers": no_store()},
            404: detail("The user has no pin.", "no such pin"),
            **PRODUCT_AUTHORISATION,
        },
    )
    async def unpin(user_id: str, actor: Actor) -> Response:
        try:
            parsed = uuid.UUID(user_id)
        except ValueError:
            return json_response({"detail": "no such pin"}, 404)
        if not await identity.sso.unpin(parsed, actor=actor_id(actor)):
            return json_response({"detail": "no such pin"}, 404)
        return Response(status_code=204, headers=NO_STORE)

    return router
