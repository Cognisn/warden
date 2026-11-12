"""Talking to the identity provider: HTTP, discovery and the JWKS cache.

Discovery is cached for ``sso.discovery_cache_seconds``. The document's
``issuer`` must equal the configured issuer exactly, character for
character (OpenID Connect Discovery, section 4.3): no case folding, no
trailing-slash tolerance, no prefix match. Every endpoint it names must use
https. A failed fetch is never cached.

The JWKS is cached for ``sso.jwks_cache_seconds``. A token naming a key id
the cache does not hold forces a refetch, at most once every
``sso.jwks_refetch_min_seconds``, so the provider's key rotation is picked
up promptly while a stream of forged key ids cannot hammer the provider.
Only asymmetric signing keys are kept.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus, urlsplit

import httpx

from warden.identity.sso.errors import SsoError

__all__ = ["Discovery", "JwksCache", "ProviderHttp", "ProviderMetadata"]

_DISCOVERY_PATH = "/.well-known/openid-configuration"
_MAX_BODY = 512 * 1024
_KEY_TYPES = frozenset({"RSA", "EC", "OKP"})


class ProviderHttp:
    """The one HTTP client single sign-on uses to reach the provider.

    Redirects are not followed and bodies are size-capped. Every failure
    raises ``SsoError`` with the caller's fixed reason; the underlying
    error text is never kept.
    """

    def __init__(self, client: httpx.AsyncClient | None = None, *, timeout: float = 10.0) -> None:
        self._client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        self._owned = client is None

    async def aclose(self) -> None:
        if self._owned:
            await self._client.aclose()

    async def get_json(self, url: str, *, failure: str) -> dict[str, Any]:
        status, body = await self._send("GET", url, failure=failure)
        if status != 200 or body is None:
            raise SsoError(failure)
        return body

    async def post_form(
        self,
        url: str,
        form: Mapping[str, str],
        *,
        failure: str,
        auth: tuple[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        return await self._send("POST", url, failure=failure, data=dict(form), auth=auth)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        failure: str,
        data: dict[str, str] | None = None,
        auth: tuple[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        try:
            headers = {"accept": "application/json"}
            if auth is not None:
                headers["authorization"] = _basic(*auth)
            request = self._client.build_request(method, url, data=data, headers=headers)
            response = await self._client.send(request, stream=True, follow_redirects=False)
            try:
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > _MAX_BODY:
                        raise SsoError(failure)
                    chunks.append(chunk)
            finally:
                await response.aclose()
        except (httpx.HTTPError, ValueError):
            raise SsoError(failure) from None
        try:
            value = json.loads(b"".join(chunks))
        except (ValueError, UnicodeDecodeError):
            return response.status_code, None
        return response.status_code, value if isinstance(value, dict) else None


def _basic(client_id: str, secret: str) -> str:
    """HTTP Basic credentials for the token endpoint: each part form-encoded
    first (RFC 6749, section 2.3.1)."""
    pair = f"{quote_plus(client_id)}:{quote_plus(secret)}".encode()
    return "Basic " + base64.b64encode(pair).decode("ascii")


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    signing_algorithms: tuple[str, ...]
    token_auth_methods: tuple[str, ...]


def _https(value: object) -> str:
    if not isinstance(value, str):
        raise SsoError("discovery_invalid")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.fragment:
        raise SsoError("discovery_invalid")
    return value


def _strings(value: object, *, required: bool) -> tuple[str, ...] | None:
    if value is None and not required:
        return None
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise SsoError("discovery_invalid")
    return tuple(value)


def parse_metadata(issuer: str, doc: Mapping[str, Any]) -> ProviderMetadata:
    """Check a discovery document against the configured issuer."""
    advertised = doc.get("issuer")
    # Exact string equality: the issuer is the provider's identity.
    if not isinstance(advertised, str) or advertised != issuer:
        raise SsoError("issuer_mismatch")
    algorithms = _strings(doc.get("id_token_signing_alg_values_supported"), required=True)
    challenges = _strings(doc.get("code_challenge_methods_supported"), required=False)
    if challenges is not None and "S256" not in challenges:
        raise SsoError("discovery_invalid")
    auth_methods = _strings(doc.get("token_endpoint_auth_methods_supported"), required=False)
    return ProviderMetadata(
        issuer=advertised,
        authorization_endpoint=_https(doc.get("authorization_endpoint")),
        token_endpoint=_https(doc.get("token_endpoint")),
        jwks_uri=_https(doc.get("jwks_uri")),
        signing_algorithms=algorithms or (),
        token_auth_methods=auth_methods or ("client_secret_basic",),
    )


class Discovery:
    """The provider's metadata, cached per issuer."""

    def __init__(
        self,
        http: ProviderHttp,
        *,
        cache_seconds: float = 3600,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http = http
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._cached: dict[str, tuple[ProviderMetadata, float]] = {}
        self._lock = asyncio.Lock()

    def invalidate(self) -> None:
        self._cached.clear()

    async def get(self, issuer: str) -> ProviderMetadata:
        hit = self._cached.get(issuer)
        if hit is not None and self._clock() - hit[1] < self._cache_seconds:
            return hit[0]
        async with self._lock:
            hit = self._cached.get(issuer)
            if hit is not None and self._clock() - hit[1] < self._cache_seconds:
                return hit[0]
            metadata = await self.fetch(issuer)
            self._cached[issuer] = (metadata, self._clock())
            return metadata

    async def fetch(self, issuer: str) -> ProviderMetadata:
        """Fetch and check the metadata, bypassing the cache."""
        url = issuer.rstrip("/") + _DISCOVERY_PATH
        doc = await self._http.get_json(url, failure="discovery_unavailable")
        return parse_metadata(issuer, doc)


@dataclass(slots=True)
class _KeySet:
    keys: dict[str, dict[str, Any]]
    fetched_at: float
    attempted_at: float


def _usable(jwk: object) -> bool:
    if not isinstance(jwk, dict):
        return False
    if not isinstance(jwk.get("kid"), str) or jwk.get("kty") not in _KEY_TYPES:
        return False
    if jwk.get("use") not in (None, "sig") or "d" in jwk:
        return False
    ops = jwk.get("key_ops")
    return ops is None or (isinstance(ops, list) and "verify" in ops)


class JwksCache:
    """The provider's signing keys, by key id."""

    def __init__(
        self,
        http: ProviderHttp,
        *,
        cache_seconds: float = 3600,
        refetch_min_seconds: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http = http
        self._cache_seconds = cache_seconds
        self._refetch_min = refetch_min_seconds
        self._clock = clock
        self._sets: dict[str, _KeySet] = {}
        self._lock = asyncio.Lock()

    def invalidate(self) -> None:
        self._sets.clear()

    async def key(self, jwks_uri: str, kid: str) -> dict[str, Any] | None:
        """The JWK with ``kid``, or None if the provider does not publish it."""
        async with self._lock:
            entry = self._sets.get(jwks_uri)
            if entry is None or self._clock() - entry.fetched_at >= self._cache_seconds:
                entry = await self._fetch(jwks_uri, entry)
            found = entry.keys.get(kid)
            if found is None and self._clock() - entry.attempted_at >= self._refetch_min:
                entry = await self._fetch(jwks_uri, entry)
                found = entry.keys.get(kid)
            return found

    async def fetch_all(self, jwks_uri: str) -> dict[str, dict[str, Any]]:
        """Fetch the key set afresh, without touching the cache (for configuration tests)."""
        doc = await self._http.get_json(jwks_uri, failure="jwks_unavailable")
        return self._parse(doc)

    async def _fetch(self, jwks_uri: str, previous: _KeySet | None) -> _KeySet:
        now = self._clock()
        if previous is not None:
            previous.attempted_at = now  # a failed refetch still counts against the limit
        doc = await self._http.get_json(jwks_uri, failure="jwks_unavailable")
        entry = _KeySet(self._parse(doc), fetched_at=now, attempted_at=now)
        self._sets[jwks_uri] = entry
        return entry

    @staticmethod
    def _parse(doc: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise SsoError("jwks_unavailable")
        return {jwk["kid"]: jwk for jwk in keys if _usable(jwk)}
