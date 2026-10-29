"""A fake OIDC provider for unit tests (imported as ``fake_idp``).

It serves discovery, JWKS and the token endpoint through an
``httpx.MockTransport``, so no test reaches a network. Keys are generated
per instance; id_tokens are minted with pyjwt, which the code under test
also uses only to verify.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ISSUER = "https://idp.example.com/tenant"
CLIENT_ID = "warden-client"
CLIENT_SECRET = "client-secret-dev-only"


@dataclass
class SigningKey:
    kid: str
    alg: str
    private: Any
    public_jwk: dict[str, Any]


def rsa_key(kid: str = "rsa-1", alg: str = "RS256") -> SigningKey:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": kid, "alg": alg, "use": "sig"})
    return SigningKey(kid, alg, private, public)


def ec_key(kid: str = "ec-1") -> SigningKey:
    private = ec.generate_private_key(ec.SECP256R1())
    public = json.loads(ECAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return SigningKey(kid, "ES256", private, public)


@dataclass
class FakeIdp:
    issuer: str = ISSUER
    client_id: str = CLIENT_ID
    client_secret: str = CLIENT_SECRET
    keys: list[SigningKey] = field(default_factory=lambda: [rsa_key()])
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    discovery_overrides: dict[str, Any] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    # Authorisation codes the token endpoint will redeem: code -> id_token claims.
    codes: dict[str, dict[str, Any]] = field(default_factory=dict)
    # PKCE challenges recorded at authorisation: code -> S256 challenge.
    challenges: dict[str, str] = field(default_factory=dict)
    token_status: int = 200
    fail_all: bool = False
    clock: Callable[[], float] = time.time

    # Documents

    @property
    def base(self) -> str:
        """The issuer without a trailing slash, as discovery appends paths to it."""
        return self.issuer.rstrip("/")

    def discovery(self) -> dict[str, Any]:
        doc = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.base}/authorize",
            "token_endpoint": f"{self.base}/token",
            "jwks_uri": f"{self.base}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": list(self.algorithms),
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
        }
        doc.update(self.discovery_overrides)
        return doc

    def jwks(self) -> dict[str, Any]:
        return {"keys": [k.public_jwk for k in self.keys]}

    # Tokens

    def claims(self, **overrides: Any) -> dict[str, Any]:
        now = int(self.clock())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": "subject-1",
            "aud": self.client_id,
            "exp": now + 300,
            "iat": now,
            "nonce": "nonce-1",
            "email": "user@example.com",
            "email_verified": True,
        }
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not _DROP}

    def mint(
        self,
        claims: dict[str, Any] | None = None,
        *,
        key: SigningKey | None = None,
        alg: str | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        signer = key or self.keys[0]
        head = {"kid": signer.kid, **(headers or {})}
        return jwt.encode(
            claims if claims is not None else self.claims(),
            signer.private,
            algorithm=alg or signer.alg,
            headers=head,
        )

    def issue_code(self, claims: dict[str, Any], challenge: str | None = None) -> str:
        code = uuid.uuid4().hex
        self.codes[code] = claims
        if challenge is not None:
            self.challenges[code] = challenge
        return code

    # Transport

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport())

    def count(self, path: str) -> int:
        return sum(1 for r in self.requests if r.url.path.endswith(path))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_all:
            raise httpx.ConnectError("provider stopped", request=request)
        path = request.url.path
        base = httpx.URL(self.base).path
        if path == f"{base}/.well-known/openid-configuration":
            return httpx.Response(200, json=self.discovery())
        if path == f"{base}/jwks":
            return httpx.Response(200, json=self.jwks())
        if path == f"{base}/token" and request.method == "POST":
            return self._token(request)
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        expected = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        if request.headers.get("authorization") != f"Basic {expected}":
            return httpx.Response(401, json={"error": "invalid_client"})
        code = form.get("code", "")
        claims = self.codes.pop(code, None)
        if claims is None or form.get("grant_type") != "authorization_code":
            return httpx.Response(400, json={"error": "invalid_grant"})
        challenge = self.challenges.pop(code, None)
        if challenge is not None:
            verifier = form.get("code_verifier", "")
            digest = hashlib.sha256(verifier.encode("ascii")).digest()
            actual = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            if actual != challenge:
                return httpx.Response(400, json={"error": "invalid_grant"})
        if self.token_status != 200:
            return httpx.Response(self.token_status, json={"error": "server_error"})
        return httpx.Response(
            200,
            json={
                "access_token": "provider-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": self.mint(claims),
            },
        )


class _Drop:
    def __repr__(self) -> str:
        return "DROP"


_DROP: Any = _Drop()
DROP: Any = _DROP
"""Pass as a claim value to ``FakeIdp.claims`` to leave the claim out."""
