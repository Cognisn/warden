"""Key publication: warden's public signing keys as JWK Sets (design D14).

Other components verify warden's access tokens and audit checkpoints with
these keys without being able to sign. Each key is an RFC 8037 OKP JSON Web
Key (``kty``, ``crv``, ``x``, ``kid``, ``alg``, ``use``); no private member
is ever included. The product mounts the router at ``http.keys_prefix``:

    app.include_router(keys_router(keys=key_store), prefix=config.http.keys_prefix)

Routes, relative to the mount prefix, both unauthenticated and read-only:

- ``GET /jwks.json``: the keys that sign and verify live credentials
  (neither retired nor revoked).
- ``GET /jwks-historical.json``: those keys plus retired ones, for verifying
  historical artefacts such as audit checkpoints.

A revoked key is in neither. Responses may be cached publicly for a few
minutes, so a verifier that meets an unknown key id should fetch again.
Serving a set records no audit event.

This module is separate from ``warden.keys`` so that importing the key store,
as audit does, never loads FastAPI.
"""

# No `from __future__ import annotations`, as in the other router modules.

from typing import Any

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

from warden.keys import KeyStore

__all__ = ["keys_router"]

_MEDIA_TYPE = "application/jwk-set+json"
_CACHE_CONTROL = "public, max-age=300"


async def _jwk_set(keys: KeyStore, *, include_retired: bool) -> Response:
    published = await keys.public_keys(include_retired=include_retired)
    body: dict[str, Any] = {"keys": [key.jwk() for key in published]}
    return JSONResponse(body, media_type=_MEDIA_TYPE, headers={"cache-control": _CACHE_CONTROL})


def keys_router(*, keys: KeyStore) -> APIRouter:
    """The key publication routes, serving ``keys``' public keys."""
    router = APIRouter()

    @router.get("/jwks.json")
    async def live_keys() -> Response:
        return await _jwk_set(keys, include_retired=False)

    @router.get("/jwks-historical.json")
    async def historical_keys() -> Response:
        return await _jwk_set(keys, include_retired=True)

    return router
