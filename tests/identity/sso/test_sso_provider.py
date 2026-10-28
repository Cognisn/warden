"""Discovery, JWKS caching and id_token validation, against a local fake provider."""

from __future__ import annotations

import json
import time
from typing import Any

import jwt
import pytest
from fake_idp import CLIENT_ID, DROP, ISSUER, FakeIdp, ec_key, rsa_key

from warden.identity.sso.errors import SsoError
from warden.identity.sso.provider import Discovery, JwksCache, ProviderHttp, ProviderMetadata
from warden.identity.sso.validation import IdTokenValidator


class Clock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def http(idp: FakeIdp) -> ProviderHttp:
    return ProviderHttp(idp.client())


async def reason_of(awaitable: Any) -> str:
    with pytest.raises(SsoError) as caught:
        await awaitable
    return caught.value.reason


# Discovery


async def test_discovery_reads_the_provider_metadata(idp: FakeIdp, http: ProviderHttp) -> None:
    metadata = await Discovery(http).get(ISSUER)
    assert metadata.issuer == ISSUER
    assert metadata.authorization_endpoint == f"{ISSUER}/authorize"
    assert metadata.token_endpoint == f"{ISSUER}/token"
    assert metadata.jwks_uri == f"{ISSUER}/jwks"
    assert metadata.signing_algorithms == ("RS256", "ES256")


async def test_discovery_is_cached_for_its_period(idp: FakeIdp, http: ProviderHttp) -> None:
    clock = Clock()
    discovery = Discovery(http, cache_seconds=600, clock=clock)
    await discovery.get(ISSUER)
    clock.now += 599
    await discovery.get(ISSUER)
    assert idp.count("/openid-configuration") == 1
    clock.now += 2
    await discovery.get(ISSUER)
    assert idp.count("/openid-configuration") == 2


@pytest.mark.parametrize(
    "advertised",
    [
        ISSUER + "/",  # trailing slash
        ISSUER.upper(),  # case
        ISSUER + "x",  # prefix match only
        "https://idp.example.org/tenant",  # another host
        ISSUER + " ",
    ],
)
async def test_discovery_requires_exact_issuer_equality(
    idp: FakeIdp, http: ProviderHttp, advertised: str
) -> None:
    idp.discovery_overrides["issuer"] = advertised
    assert await reason_of(Discovery(http).get(ISSUER)) == "issuer_mismatch"


async def test_discovery_refuses_a_non_string_issuer(idp: FakeIdp, http: ProviderHttp) -> None:
    idp.discovery_overrides["issuer"] = [ISSUER]
    assert await reason_of(Discovery(http).get(ISSUER)) == "issuer_mismatch"


@pytest.mark.parametrize("field", ["authorization_endpoint", "token_endpoint", "jwks_uri"])
async def test_discovery_refuses_a_plain_http_endpoint(
    idp: FakeIdp, http: ProviderHttp, field: str
) -> None:
    idp.discovery_overrides[field] = "http://idp.example.com/tenant/x"
    assert await reason_of(Discovery(http).get(ISSUER)) == "discovery_invalid"


@pytest.mark.parametrize(
    "overrides",
    [
        {"id_token_signing_alg_values_supported": DROP},
        {"id_token_signing_alg_values_supported": "RS256"},
        {"code_challenge_methods_supported": ["plain"]},
        {"jwks_uri": DROP},
    ],
)
async def test_discovery_refuses_incomplete_metadata(
    idp: FakeIdp, http: ProviderHttp, overrides: dict[str, Any]
) -> None:
    for key, value in overrides.items():
        if value is DROP:
            idp.discovery_overrides[key] = None
        else:
            idp.discovery_overrides[key] = value
    assert await reason_of(Discovery(http).get(ISSUER)) == "discovery_invalid"


async def test_discovery_failure_is_not_cached(idp: FakeIdp, http: ProviderHttp) -> None:
    discovery = Discovery(http)
    idp.fail_all = True
    assert await reason_of(discovery.get(ISSUER)) == "discovery_unavailable"
    idp.fail_all = False
    assert (await discovery.get(ISSUER)).issuer == ISSUER


# JWKS


async def test_jwks_returns_a_known_key_from_cache(idp: FakeIdp, http: ProviderHttp) -> None:
    jwks = JwksCache(http)
    assert await jwks.key(f"{ISSUER}/jwks", "rsa-1") is not None
    assert await jwks.key(f"{ISSUER}/jwks", "rsa-1") is not None
    assert idp.count("/jwks") == 1


async def test_jwks_refetches_once_for_an_unknown_key_id(idp: FakeIdp, http: ProviderHttp) -> None:
    clock = Clock()
    jwks = JwksCache(http, cache_seconds=3600, refetch_min_seconds=60, clock=clock)
    uri = f"{ISSUER}/jwks"
    await jwks.key(uri, "rsa-1")
    clock.now += 61
    idp.keys.append(rsa_key("rsa-2"))  # the provider rotates
    assert await jwks.key(uri, "rsa-2") is not None
    assert idp.count("/jwks") == 2


async def test_jwks_refetch_for_unknown_ids_is_rate_limited(
    idp: FakeIdp, http: ProviderHttp
) -> None:
    clock = Clock()
    jwks = JwksCache(http, cache_seconds=3600, refetch_min_seconds=60, clock=clock)
    uri = f"{ISSUER}/jwks"
    await jwks.key(uri, "rsa-1")
    for _ in range(20):
        assert await jwks.key(uri, "forged") is None
    assert idp.count("/jwks") == 1
    clock.now += 60
    assert await jwks.key(uri, "forged") is None
    assert idp.count("/jwks") == 2


async def test_jwks_expires_after_its_cache_period(idp: FakeIdp, http: ProviderHttp) -> None:
    clock = Clock()
    jwks = JwksCache(http, cache_seconds=300, refetch_min_seconds=60, clock=clock)
    uri = f"{ISSUER}/jwks"
    await jwks.key(uri, "rsa-1")
    idp.keys = [rsa_key("rsa-2")]  # rsa-1 withdrawn
    clock.now += 301
    assert await jwks.key(uri, "rsa-1") is None
    assert idp.count("/jwks") == 2


async def test_jwks_ignores_symmetric_and_encryption_keys(idp: FakeIdp, http: ProviderHttp) -> None:
    idp.keys[0].public_jwk["use"] = "enc"
    oct_key = rsa_key("oct-1")
    oct_key.public_jwk = {"kty": "oct", "kid": "oct-1", "k": "c2VjcmV0"}
    idp.keys.append(oct_key)
    jwks = JwksCache(http)
    assert await jwks.key(f"{ISSUER}/jwks", "rsa-1") is None
    assert await jwks.key(f"{ISSUER}/jwks", "oct-1") is None


# id_token validation


@pytest.fixture
async def metadata(http: ProviderHttp) -> ProviderMetadata:
    return await Discovery(http).get(ISSUER)


@pytest.fixture
def validator(http: ProviderHttp) -> IdTokenValidator:
    return IdTokenValidator(
        JwksCache(http), allowed_algorithms=("RS256", "ES256", "PS256"), clock_skew_seconds=60
    )


async def check(
    validator: IdTokenValidator, metadata: ProviderMetadata, token: str, nonce: str = "nonce-1"
) -> str:
    return await reason_of(
        validator.validate(token, metadata=metadata, client_id=CLIENT_ID, nonce=nonce)
    )


async def test_a_valid_id_token_is_accepted(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    claims = await validator.validate(
        idp.mint(), metadata=metadata, client_id=CLIENT_ID, nonce="nonce-1"
    )
    assert claims.issuer == ISSUER
    assert claims.subject == "subject-1"
    assert claims.email == "user@example.com"
    assert claims.email_verified is True


async def test_an_es256_token_is_accepted(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    key = ec_key()
    idp.keys.append(key)
    claims = await validator.validate(
        idp.mint(key=key), metadata=metadata, client_id=CLIENT_ID, nonce="nonce-1"
    )
    assert claims.subject == "subject-1"


def _unsigned(claims: dict[str, Any], header: dict[str, Any]) -> str:
    def b64(data: dict[str, Any]) -> str:
        import base64

        raw = json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{b64(header)}.{b64(claims)}."


async def test_alg_none_is_refused(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    token = _unsigned(idp.claims(), {"alg": "none", "kid": "rsa-1", "typ": "JWT"})
    assert await check(validator, metadata, token) == "algorithm_not_allowed"


async def test_hs256_signed_with_the_public_key_is_refused(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    # The classic key-confusion forgery: HMAC keyed with the provider's public key.
    import base64
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import serialization

    secret = (
        idp.keys[0]
        .private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    unsigned = _unsigned(idp.claims(), {"alg": "HS256", "kid": "rsa-1", "typ": "JWT"})
    mac = hmac.new(secret, unsigned[:-1].encode(), hashlib.sha256).digest()
    token = unsigned + base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    idp.algorithms.append("HS256")  # even if the provider advertised it
    metadata = await Discovery(ProviderHttp(idp.client())).get(ISSUER)
    assert await check(validator, metadata, token) == "algorithm_not_allowed"


async def test_an_algorithm_the_provider_does_not_advertise_is_refused(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    key = rsa_key("ps-1", alg="PS256")
    idp.keys.append(key)
    # PS256 is allowed by configuration but the provider advertises only RS256 and ES256.
    assert await check(validator, metadata, idp.mint(key=key)) == "algorithm_not_allowed"


async def test_an_algorithm_configuration_does_not_allow_is_refused(
    idp: FakeIdp, http: ProviderHttp, metadata: ProviderMetadata
) -> None:
    key = ec_key()
    idp.keys.append(key)
    strict = IdTokenValidator(JwksCache(http), allowed_algorithms=("RS256",), clock_skew_seconds=60)
    assert await check(strict, metadata, idp.mint(key=key)) == "algorithm_not_allowed"


async def test_a_key_is_used_only_with_its_own_algorithm(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    idp.algorithms.append("PS256")
    metadata = await Discovery(ProviderHttp(idp.client())).get(ISSUER)
    # rsa-1 is published for RS256; a PS256 token under its kid is refused.
    token = idp.mint(alg="PS256")
    assert await check(validator, metadata, token) == "algorithm_not_allowed"


async def test_a_wrong_signature_is_refused(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    impostor = rsa_key("rsa-1")  # same kid, different key
    assert await check(validator, metadata, idp.mint(key=impostor)) == "bad_signature"


async def test_an_unknown_or_missing_key_id_is_refused(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    stranger = rsa_key("rsa-9")
    assert await check(validator, metadata, idp.mint(key=stranger)) == "unknown_key"
    keyless = jwt.encode(idp.claims(), idp.keys[0].private, algorithm="RS256")
    assert await check(validator, metadata, keyless) == "unknown_key"


async def test_a_critical_header_is_refused(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    token = idp.mint(headers={"crit": ["exp"]})
    assert await check(validator, metadata, token) == "malformed"


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        ({"iss": ISSUER + "/"}, "issuer"),
        ({"iss": DROP}, "issuer"),
        ({"aud": "another-client"}, "audience"),
        ({"aud": DROP}, "audience"),
        ({"aud": [CLIENT_ID, "another-client"]}, "authorised_party"),
        ({"aud": [CLIENT_ID, "another-client"], "azp": "another-client"}, "authorised_party"),
        ({"azp": "another-client"}, "authorised_party"),
        ({"nonce": "nonce-2"}, "nonce"),
        ({"nonce": DROP}, "nonce"),
        ({"sub": DROP}, "malformed"),
        ({"sub": ""}, "malformed"),
        ({"sub": 42}, "malformed"),
    ],
)
async def test_claims_are_checked(
    idp: FakeIdp,
    validator: IdTokenValidator,
    metadata: ProviderMetadata,
    claims: dict[str, Any],
    reason: str,
) -> None:
    assert await check(validator, metadata, idp.mint(idp.claims(**claims))) == reason


async def test_several_audiences_with_our_azp_are_accepted(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    token = idp.mint(idp.claims(aud=[CLIENT_ID, "another-client"], azp=CLIENT_ID))
    claims = await validator.validate(
        token, metadata=metadata, client_id=CLIENT_ID, nonce="nonce-1"
    )
    assert claims.subject == "subject-1"


async def test_times_are_checked_with_the_clock_skew(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    now = int(time.time())
    within = idp.mint(idp.claims(exp=now - 30, iat=now + 30))
    claims = await validator.validate(
        within, metadata=metadata, client_id=CLIENT_ID, nonce="nonce-1"
    )
    assert claims.subject == "subject-1"
    assert await check(validator, metadata, idp.mint(idp.claims(exp=now - 90))) == "expired"
    assert await check(validator, metadata, idp.mint(idp.claims(exp=DROP))) == "expired"
    future = idp.mint(idp.claims(iat=now + 90))
    assert await check(validator, metadata, future) == "issued_in_future"
    assert await check(validator, metadata, idp.mint(idp.claims(iat=DROP))) == "issued_in_future"


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c", "x" * 20_000, "é.é.é"])
async def test_garbage_is_refused(
    validator: IdTokenValidator, metadata: ProviderMetadata, token: str
) -> None:
    assert await check(validator, metadata, token) == "malformed"


async def test_email_verified_must_be_a_real_true(
    idp: FakeIdp, validator: IdTokenValidator, metadata: ProviderMetadata
) -> None:
    for value in ("true", 1, DROP):
        token = idp.mint(idp.claims(email_verified=value))
        claims = await validator.validate(
            token, metadata=metadata, client_id=CLIENT_ID, nonce="nonce-1"
        )
        assert claims.email_verified is False


async def test_none_and_hs_are_never_usable_whatever_the_lists_say(
    idp: FakeIdp, http: ProviderHttp
) -> None:
    # Configuration refuses these at start-up; the validator refuses them again,
    # so a mistake upstream cannot admit them.
    idp.algorithms = ["RS256", "none", "HS256", "HS384", "HS512"]
    metadata = await Discovery(http).get(ISSUER)
    lax = IdTokenValidator(
        JwksCache(http),
        allowed_algorithms=("RS256", "none", "HS256", "HS384", "HS512"),
        clock_skew_seconds=60,
    )
    assert lax.usable_algorithms(metadata) == {"RS256"}
    del idp.keys[0].public_jwk["alg"]  # a key that does not pin its algorithm
    token = _unsigned(idp.claims(), {"alg": "none", "kid": "rsa-1", "typ": "JWT"})
    assert await check(lax, metadata, token) == "algorithm_not_allowed"
