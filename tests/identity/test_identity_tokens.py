"""Access tokens and refresh families."""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
from identity_support import PASSWORD, UserFactory, audit_rows, race

from warden.db import Database
from warden.identity import AuthenticationRefused, Identity, TokenPair, User, UserStatus
from warden.keys import KeyStore

pytestmark = pytest.mark.db

REFUSAL = b'{"detail":"authentication failed"}'


async def _signed_in(identity: Identity, make_user: UserFactory) -> tuple[User, TokenPair]:
    user = await make_user()
    result = await identity.sign_in(user.email, PASSWORD)
    assert result.tokens is not None
    return user, result.tokens


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parts(token: str) -> tuple[dict[str, object], dict[str, object], str]:
    header, payload, signature = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    return (
        json.loads(base64.urlsafe_b64decode(pad(header))),
        json.loads(base64.urlsafe_b64decode(pad(payload))),
        signature,
    )


async def test_access_token_carries_kid_and_claims(
    identity: Identity, keys: KeyStore, make_user: UserFactory
) -> None:
    user, tokens = await _signed_in(identity, make_user)
    header, claims, _ = _parts(tokens.access_token)
    assert header == {"alg": "EdDSA", "typ": "at+jwt", "kid": (await keys.active_key()).key_id}
    assert claims["sub"] == str(user.id)
    assert claims["sid"] == str(tokens.session_id)
    assert claims["iss"] == "https://app.example.com"
    assert claims["amr"] == ["pwd"]
    assert isinstance(claims["exp"], int) and isinstance(claims["iat"], int)
    assert claims["exp"] - claims["iat"] == 900
    principal = await identity.authenticate(tokens.access_token)
    assert principal.user_id == user.id and principal.session_id == tokens.session_id


async def test_tampered_tokens_are_refused(identity: Identity, make_user: UserFactory) -> None:
    _, tokens = await _signed_in(identity, make_user)
    header, claims, signature = _parts(tokens.access_token)
    raw_header, raw_claims, _ = tokens.access_token.split(".")
    no_alg = _b64(json.dumps(dict(header, alg="none")).encode())
    bad_kid = _b64(json.dumps(dict(header, kid="unknown")).encode())
    forged_claims = dict(claims, sub="00000000-0000-0000-0000-000000000000")
    for bad in (
        f"{raw_header}.{_b64(json.dumps(forged_claims).encode())}.{signature}",
        f"{no_alg}.{raw_claims}.",
        f"{bad_kid}.{raw_claims}.{signature}",
        tokens.access_token + "\n",
        tokens.access_token[:-2],
        "a.b",
        "",
        "é.é.é",
        "x" * 10_000,
    ):
        with pytest.raises(AuthenticationRefused):
            await identity.authenticate(bad)


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "HS256", "typ": "at+jwt"},
        {"alg": "EdDSA", "typ": "JWT"},
        {"alg": "EdDSA", "typ": "at+jwt", "crit": ["exp"]},
        {"alg": "EdDSA"},
    ],
)
async def test_validly_signed_tokens_with_the_wrong_header_are_refused(
    identity: Identity, keys: KeyStore, make_user: UserFactory, header: dict[str, object]
) -> None:
    """The header is checked strictly even when the signature itself is good."""
    _, tokens = await _signed_in(identity, make_user)
    claims = tokens.access_token.split(".")[1]
    full = {**header, "kid": (await keys.active_key()).key_id}
    signing_input = f"{_b64(json.dumps(full).encode())}.{claims}"
    signature = await keys.sign(signing_input.encode())
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(f"{signing_input}.{_b64(signature.signature)}")


async def test_an_expired_access_token_is_refused(
    identity: Identity, make_user: UserFactory
) -> None:
    user, tokens = await _signed_in(identity, make_user)
    expired, _ = await identity.sessions.issue_access_token(
        user.id, tokens.session_id, ["pwd"], now=time.time() - 3600
    )
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(expired)


async def test_a_retired_key_refuses_live_tokens(
    identity: Identity, keys: KeyStore, make_user: UserFactory
) -> None:
    """Token verification uses KeyStore.verify, never verify_historical."""
    _, tokens = await _signed_in(identity, make_user)
    old = await keys.active_key()
    await keys.rotate()
    await identity.authenticate(tokens.access_token)  # still unretired: still valid
    await keys.retire(old.key_id)
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(tokens.access_token)


async def test_a_revoked_key_refuses_live_tokens(
    identity: Identity, keys: KeyStore, make_user: UserFactory
) -> None:
    _, tokens = await _signed_in(identity, make_user)
    old = await keys.active_key()
    await keys.rotate()
    await keys.revoke(old.key_id)
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(tokens.access_token)


async def test_new_tokens_are_signed_with_the_rotated_key(
    identity: Identity, keys: KeyStore, make_user: UserFactory
) -> None:
    await keys.rotate()
    _, tokens = await _signed_in(identity, make_user)
    header, _, _ = _parts(tokens.access_token)
    assert header["kid"] == (await keys.active_key()).key_id


async def test_refresh_rotates_the_token(identity: Identity, make_user: UserFactory) -> None:
    _, tokens = await _signed_in(identity, make_user)
    renewed = await identity.refresh(tokens.refresh_token)
    assert renewed.refresh_token != tokens.refresh_token
    assert renewed.session_id == tokens.session_id
    await identity.authenticate(renewed.access_token)
    again = await identity.refresh(renewed.refresh_token)
    assert again.session_id == tokens.session_id


async def test_reuse_after_the_grace_window_revokes_the_family(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    """#131: a replayed refresh token is detected through its family."""
    user, tokens = await _signed_in(identity, make_user)
    renewed = await identity.refresh(tokens.refresh_token)
    async with db.connection() as conn:  # move the rotation outside the grace window
        await conn.execute(
            "UPDATE warden.refresh_tokens SET used_at = used_at - interval '1 minute'"
            " WHERE used_at IS NOT NULL"
        )
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(tokens.refresh_token)
    # The whole family is gone: the legitimate holder's newer tokens no longer work.
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(renewed.refresh_token)
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(renewed.access_token)
    rows = await audit_rows(db, "identity.session.reuse_detected")
    assert len(rows) == 1
    assert rows[0]["actor"] == str(user.id)
    assert rows[0]["resource_id"] == str(tokens.session_id)
    assert rows[0]["details"] == {"reason": "refresh_reuse", "generation": 0}


async def test_reuse_of_an_older_generation_revokes_even_inside_the_grace_window(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    _, tokens = await _signed_in(identity, make_user)
    second = await identity.refresh(tokens.refresh_token)
    third = await identity.refresh(second.refresh_token)
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(tokens.refresh_token)  # two generations back
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(third.refresh_token)
    assert len(await audit_rows(db, "identity.session.reuse_detected")) == 1


async def test_the_immediate_predecessor_inside_the_grace_window_is_refused_without_revoking(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    """Two tabs refreshing together: the loser is refused, the family survives."""
    _, tokens = await _signed_in(identity, make_user)
    renewed = await identity.refresh(tokens.refresh_token)
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(tokens.refresh_token)
    await identity.refresh(renewed.refresh_token)  # still valid
    assert await audit_rows(db, "identity.session.reuse_detected") == []
    reasons = [r["details"]["reason"] for r in await audit_rows(db, "identity.session.refresh")]
    assert reasons == ["reuse_within_grace"]


async def test_grace_never_un_revokes(identity: Identity, make_user: UserFactory) -> None:
    _, tokens = await _signed_in(identity, make_user)
    await identity.refresh(tokens.refresh_token)
    await identity.sessions.revoke(tokens.session_id, reason="sign_out")
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(tokens.refresh_token)


async def test_concurrent_refreshes_of_one_token_rotate_once(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    for _ in range(4):
        _, tokens = await _signed_in(identity, make_user)
        token = tokens.refresh_token
        results = await race(*(lambda t=token: identity.refresh(t) for _ in range(3)))
        winners = [r for r in results if isinstance(r, TokenPair)]
        assert len(winners) == 1, results
        assert sum(isinstance(r, AuthenticationRefused) for r in results) == 2, results
        await identity.refresh(winners[0].refresh_token)  # the family survives the race


async def test_refresh_issues_nothing_to_an_inactive_user(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    """#132: refresh checks the user's current status."""
    for status in (UserStatus.SUSPENDED, UserStatus.DEACTIVATED):
        user, tokens = await _signed_in(identity, make_user)
        await identity.users.set_status(user.id, status, actor="t")
        with pytest.raises(AuthenticationRefused):
            await identity.refresh(tokens.refresh_token)
        with pytest.raises(AuthenticationRefused):
            await identity.authenticate(tokens.access_token)
    reasons = [r["details"]["reason"] for r in await audit_rows(db, "identity.session.refresh")]
    assert reasons == ["user_inactive", "user_inactive"]


async def test_refresh_token_expiry_is_enforced(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    _, tokens = await _signed_in(identity, make_user)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.refresh_tokens SET expires_at = now() - interval '1 second'"
        )
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(tokens.refresh_token)
    reasons = [r["details"]["reason"] for r in await audit_rows(db, "identity.session.refresh")]
    assert reasons == ["token_expired"]


async def test_the_absolute_lifespan_ends_a_session(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    _, tokens = await _signed_in(identity, make_user)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE warden.sessions SET created_at = created_at - interval '13 hours',"
            " expires_at = expires_at - interval '13 hours'"
        )
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(tokens.refresh_token)
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(tokens.access_token)


async def test_shortening_the_lifespan_cuts_off_existing_sessions(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    _, tokens = await _signed_in(identity, make_user)
    async with db.connection() as conn:  # a session two hours old
        await conn.execute(
            "UPDATE warden.sessions SET created_at = created_at - interval '2 hours'"
        )
    await identity.refresh(tokens.refresh_token)
    await identity.policy.update(
        actor="admin-1", session_lifespan_seconds=3600, refresh_token_ttl_seconds=1800
    )
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(tokens.access_token)


async def test_a_refresh_token_never_outlives_its_session(
    identity: Identity, make_user: UserFactory, db: Database
) -> None:
    await _signed_in(identity, make_user)
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT bool_and(t.expires_at <= s.expires_at) FROM warden.refresh_tokens t"
            " JOIN warden.sessions s ON s.id = t.session_id"
        )
        row = await cur.fetchone()
    assert row == (True,)


async def test_sign_out_revokes_the_session(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory, db: Database
) -> None:
    _, tokens = await _signed_in(identity, make_user)
    auth = {"authorization": f"Bearer {tokens.access_token}"}
    response = await client.post("/auth/sign-out", headers=auth)
    assert response.status_code == 204
    with pytest.raises(AuthenticationRefused):
        await identity.authenticate(tokens.access_token)
    refused = await client.post("/auth/refresh", json={"refresh_token": tokens.refresh_token})
    assert refused.status_code == 401 and refused.content == REFUSAL
    assert len(await audit_rows(db, "identity.sign_out")) == 1


async def test_refresh_over_http(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory
) -> None:
    _, tokens = await _signed_in(identity, make_user)
    response = await client.post("/auth/refresh", json={"refresh_token": tokens.refresh_token})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["status"] == "signed_in"
    for bad in ({"refresh_token": tokens.refresh_token}, {}, {"refresh_token": 5}, []):
        refused = await client.post("/auth/refresh", json=bad)
        assert refused.status_code == 401 and refused.content == REFUSAL


async def test_change_password(
    client: httpx.AsyncClient, identity: Identity, make_user: UserFactory, db: Database
) -> None:
    user, tokens = await _signed_in(identity, make_user)
    other = await identity.sign_in(user.email, PASSWORD)
    assert other.tokens is not None
    auth = {"authorization": f"Bearer {tokens.access_token}"}
    new = "a much better passphrase"
    wrong = await client.post(
        "/auth/password", headers=auth, json={"current_password": "nope", "new_password": new}
    )
    assert wrong.status_code == 400
    weak = await client.post(
        "/auth/password", headers=auth, json={"current_password": PASSWORD, "new_password": "x"}
    )
    assert weak.status_code == 400
    ok = await client.post(
        "/auth/password", headers=auth, json={"current_password": PASSWORD, "new_password": new}
    )
    assert ok.status_code == 204
    assert (await identity.sign_in(user.email, new)).tokens is not None
    with pytest.raises(AuthenticationRefused):
        await identity.sign_in(user.email, PASSWORD)
    # Other sessions end; this one continues.
    with pytest.raises(AuthenticationRefused):
        await identity.refresh(other.tokens.refresh_token)
    await identity.authenticate(tokens.access_token)
    outcomes = [r["outcome"] for r in await audit_rows(db, "identity.password.changed")]
    assert outcomes == ["failure", "failure", "success"]
