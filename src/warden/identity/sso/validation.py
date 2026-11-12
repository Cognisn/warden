"""id_token validation (OpenID Connect Core 1.0, section 3.1.3.7), with pyjwt.

The signature algorithm must be in configuration's ``sso.allowed_algorithms``
and in the provider's advertised set; ``none`` and HS* are never accepted,
whatever either list says. The key comes from the provider's JWKS by key
id, and is used only with its own algorithm. pyjwt checks the signature;
every claim is then checked here, so each refusal has its own audited
reason: ``iss`` equal to the provider's issuer, ``aud`` containing the
client id (and ``azp`` equal to it when there are several audiences, or
whenever it is present), ``exp`` and ``iat`` within ``clock_skew_seconds``,
and ``nonce`` equal to the one this sign-in sent.
"""

from __future__ import annotations

import hmac
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeGuard

import jwt
from jwt.exceptions import InvalidKeyError, PyJWKError, PyJWTError

from warden.identity.sso.errors import SsoError
from warden.identity.sso.provider import JwksCache, ProviderMetadata

__all__ = ["IdTokenClaims", "IdTokenValidator"]

_MAX_TOKEN = 16 * 1024
_MAX_SUBJECT = 255
# Never accepted, whatever configuration or the provider says.
_FORBIDDEN = frozenset({"none", "HS256", "HS384", "HS512"})


@dataclass(frozen=True, slots=True)
class IdTokenClaims:
    issuer: str
    subject: str
    email: str | None
    email_verified: bool
    claims: Mapping[str, Any]


def _number(value: object) -> TypeGuard[int | float]:
    return isinstance(value, int | float) and not isinstance(value, bool)


class IdTokenValidator:
    def __init__(
        self,
        jwks: JwksCache,
        *,
        allowed_algorithms: tuple[str, ...],
        clock_skew_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._jwks = jwks
        self._allowed = frozenset(allowed_algorithms) - _FORBIDDEN
        self._skew = clock_skew_seconds
        self._clock = clock

    def usable_algorithms(self, metadata: ProviderMetadata) -> frozenset[str]:
        """Configuration's algorithms that the provider also advertises."""
        return self._allowed & frozenset(metadata.signing_algorithms)

    async def validate(
        self, token: object, *, metadata: ProviderMetadata, client_id: str, nonce: str
    ) -> IdTokenClaims:
        if not isinstance(token, str) or not token.isascii() or len(token) > _MAX_TOKEN:
            raise SsoError("malformed")
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError:
            raise SsoError("malformed") from None
        if "crit" in header:
            raise SsoError("malformed")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self.usable_algorithms(metadata):
            raise SsoError("algorithm_not_allowed")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise SsoError("unknown_key")
        jwk = await self._jwks.key(metadata.jwks_uri, kid)
        if jwk is None:
            raise SsoError("unknown_key")
        if jwk.get("alg") not in (None, alg):
            raise SsoError("algorithm_not_allowed")
        try:
            key = jwt.PyJWK(jwk, algorithm=alg)
        except (PyJWKError, InvalidKeyError):
            raise SsoError("algorithm_not_allowed") from None
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except jwt.InvalidSignatureError:
            raise SsoError("bad_signature") from None
        except (PyJWTError, ValueError):
            raise SsoError("malformed") from None
        return self._check(claims, metadata.issuer, client_id, nonce)

    def _check(
        self, claims: dict[str, Any], issuer: str, client_id: str, nonce: str
    ) -> IdTokenClaims:
        if claims.get("iss") != issuer:
            raise SsoError("issuer")
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud
        if (
            not isinstance(audiences, list)
            or not all(isinstance(a, str) for a in audiences)
            or client_id not in audiences
        ):
            raise SsoError("audience")
        azp = claims.get("azp")
        if (len(set(audiences)) > 1 or azp is not None) and azp != client_id:
            raise SsoError("authorised_party")
        now = self._clock()
        exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
        if not _number(exp) or exp <= now - self._skew:
            raise SsoError("expired")
        if not _number(iat) or iat > now + self._skew:
            raise SsoError("issued_in_future")
        if nbf is not None and (not _number(nbf) or nbf > now + self._skew):
            raise SsoError("issued_in_future")
        sent = claims.get("nonce")
        if not isinstance(sent, str) or not hmac.compare_digest(
            sent.encode("utf-8"), nonce.encode("utf-8")
        ):
            raise SsoError("nonce")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not 0 < len(sub) <= _MAX_SUBJECT:
            raise SsoError("malformed")
        email = claims.get("email")
        return IdTokenClaims(
            issuer=issuer,
            subject=sub,
            email=email if isinstance(email, str) else None,
            email_verified=claims.get("email_verified") is True,
            claims=claims,
        )
