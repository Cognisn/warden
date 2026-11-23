"""Microsoft Entra ID's verified email: ``xms_edov`` with ``email``, for Entra's issuer only.

Skuld release warden 0.2.0, question 2 (answer: accept xms_edov for Entra).
Entra ID puts no ``email_verified`` claim in its ID tokens; its optional
``xms_edov`` claim says whether the owner of the email's domain has been
verified. When the configured issuer is Entra ID's v2.0 issuer for a tenant
(matched in full on the URL, never by the preset), ``xms_edov`` exactly
``true`` with a non-empty ``email`` counts as a verified email. Every other
issuer still needs ``email_verified`` exactly ``true`` and ``xms_edov`` is
ignored. The allowed email domains still apply.

The tenant ids are placeholders.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from fake_idp import CLIENT_ID, CLIENT_SECRET, DROP, ISSUER, FakeIdp
from fastapi import FastAPI
from identity_support import RecordingSender, UserFactory, audit_rows
from sso_support import CLIENT_SECRET_NAME, callback, completion, sign_in, sso_config

from warden.config import WardenConfig
from warden.db import Database
from warden.identity import Identity, SignInMethod
from warden.identity.sso.provider import Discovery, JwksCache, ProviderHttp
from warden.identity.sso.service import SingleSignOn
from warden.identity.sso.validation import IdTokenValidator

TENANT = "11111111-2222-3333-4444-555555555555"
ENTRA = f"https://login.microsoftonline.com/{TENANT}/v2.0"
ALICE = "alice@example.com"


async def _verified(issuer: str, **claims: Any) -> bool:
    idp = FakeIdp(issuer=issuer)
    http = ProviderHttp(idp.client())
    metadata = await Discovery(http).get(issuer)
    validator = IdTokenValidator(
        JwksCache(http), allowed_algorithms=("RS256",), clock_skew_seconds=60
    )
    token = idp.mint(idp.claims(**claims))
    validated = await validator.validate(
        token, metadata=metadata, client_id=CLIENT_ID, nonce="nonce-1"
    )
    return validated.email_verified


# The rule, in the validator.


async def test_entra_xms_edov_true_with_an_email_is_a_verified_email() -> None:
    assert await _verified(ENTRA, email_verified=DROP, xms_edov=True) is True


@pytest.mark.parametrize("value", [False, "true", 1, "1", None, DROP])
async def test_entra_xms_edov_must_be_exactly_true(value: Any) -> None:
    assert await _verified(ENTRA, email_verified=DROP, xms_edov=value) is False


@pytest.mark.parametrize("email", [DROP, "", None, 42])
async def test_entra_xms_edov_needs_a_non_empty_email(email: Any) -> None:
    assert await _verified(ENTRA, email_verified=DROP, xms_edov=True, email=email) is False


async def test_entra_email_verified_true_still_counts() -> None:
    assert await _verified(ENTRA, email_verified=True) is True


@pytest.mark.parametrize(
    "issuer",
    [
        ISSUER,
        "https://accounts.example.com/google",
        # Near misses of Entra's v2.0 issuer: none of them is it.
        f"https://login.microsoftonline.com/{TENANT}/v2.0/",
        f"https://login.microsoftonline.com/{TENANT}/v2.00",
        f"https://login.microsoftonline.com/{TENANT}",
        f"https://login.microsoftonline.com/{TENANT}/v2.0/extra",
        f"https://login.microsoftonline.com.example.com/{TENANT}/v2.0",
        f"https://login.microsoftonline.com/{TENANT}x/v2.0",
        f"https://login.microsoftonline.com/x{TENANT}/v2.0",
        "https://login.microsoftonline.com/common/v2.0",
        "https://login.microsoftonline.com/organizations/v2.0",
        "https://login.microsoftonline.com/contoso.example.com/v2.0",
        f"https://sts.windows.net/{TENANT}/",
        f"https://idp.example.com/login.microsoftonline.com/{TENANT}/v2.0",
    ],
)
async def test_other_issuers_ignore_xms_edov(issuer: str) -> None:
    assert await _verified(issuer, email_verified=DROP, xms_edov=True) is False
    assert await _verified(issuer, email_verified=True, xms_edov=True) is True
    assert await _verified(issuer, email_verified=False, xms_edov=True) is False


# Through warden's routes, with a database.


@pytest.fixture
def config() -> WardenConfig:
    return sso_config(issuer_url=ENTRA, allowed_email_domains="example.com")


@pytest.fixture
def secrets(secrets: Any) -> Any:
    secrets.set(CLIENT_SECRET_NAME, CLIENT_SECRET)
    return secrets


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp(issuer=ENTRA)


@pytest.fixture
def sso(identity: Identity, idp: FakeIdp, secrets: Any) -> SingleSignOn:
    identity.sso = SingleSignOn(
        identity.config,
        identity.db,
        identity.sessions,
        identity.policy,
        secrets,
        http=ProviderHttp(idp.client()),
        settings_max_age=0,
    )
    return identity.sso


@pytest.fixture
def app(identity: Identity, sso: SingleSignOn) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.lifecycle_router(), prefix="/auth")
    application.include_router(identity.sso_router(), prefix="/auth")
    return application


async def _reasons(db: Database) -> list[str]:
    return [r["details"]["reason"] for r in await audit_rows(db, "warden.identity.sso.sign_in")]


async def _pin(db: Database, user_id: uuid.UUID) -> tuple[str, str] | None:
    async with db.connection() as conn:
        cur = await conn.execute(
            "SELECT issuer, subject FROM warden.sso_identities WHERE user_id = %s", (user_id,)
        )
        row = await cur.fetchone()
    return None if row is None else (str(row[0]), str(row[1]))


@pytest.mark.db
async def test_a_first_entra_sign_in_with_xms_edov_signs_in(
    client: httpx.AsyncClient, idp: FakeIdp, make_user: UserFactory, db: Database
) -> None:
    alice = await make_user(ALICE)
    answer = await sign_in(
        client, idp, sub="s-alice", email=ALICE, email_verified=DROP, xms_edov=True
    )
    assert answer.status_code == 200, answer.text
    assert answer.json()["status"] == "signed_in"
    assert await _pin(db, alice.id) == (ENTRA, "s-alice")


@pytest.mark.db
@pytest.mark.parametrize("xms_edov", [False, "true", DROP])
async def test_a_first_entra_sign_in_without_a_true_xms_edov_is_refused(
    client: httpx.AsyncClient, idp: FakeIdp, make_user: UserFactory, db: Database, xms_edov: Any
) -> None:
    alice = await make_user(ALICE)
    answer = await sign_in(
        client, idp, sub="s-alice", email=ALICE, email_verified=DROP, xms_edov=xms_edov
    )
    assert answer.status_code == 401
    assert (await _reasons(db))[-1] == "email_unverified"
    assert await _pin(db, alice.id) is None


@pytest.mark.db
async def test_the_allowed_email_domains_still_apply_to_xms_edov(
    client: httpx.AsyncClient, idp: FakeIdp, make_user: UserFactory, db: Database
) -> None:
    await make_user("alice@example.org")
    answer = await sign_in(
        client, idp, sub="s-alice", email="alice@example.org", email_verified=DROP, xms_edov=True
    )
    assert answer.status_code == 401
    assert (await _reasons(db))[-1] == "domain_not_allowed"


@pytest.mark.db
async def test_an_invitation_is_accepted_through_entra_with_xms_edov(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
) -> None:
    invitation = await identity.invitations.create(
        "invitee@example.com", actor="admin-1", sign_in_method=SignInMethod.SSO_ONLY
    )
    token = mail.token()
    started = await client.post("/auth/sso/start", data={"invitation": token})
    assert started.status_code == 303, started.text
    params = dict(httpx.URL(started.headers["location"]).params.items())
    code = idp.issue_code(
        idp.claims(
            sub="s-invitee",
            email="invitee@example.com",
            email_verified=DROP,
            xms_edov=True,
            nonce=params["nonce"],
        ),
        challenge=params["code_challenge"],
    )
    landed = completion(await callback(client, code, params["state"]))
    assert "code" in landed, landed
    assert await _pin(db, invitation.user_id) == (ENTRA, "s-invitee")


@pytest.mark.db
async def test_an_entra_invitation_without_xms_edov_is_refused_and_stays_usable(
    client: httpx.AsyncClient,
    idp: FakeIdp,
    identity: Identity,
    mail: RecordingSender,
    db: Database,
) -> None:
    invitation = await identity.invitations.create(
        "invitee@example.com", actor="admin-1", sign_in_method=SignInMethod.SSO_ONLY
    )
    token = mail.token()
    started = await client.post("/auth/sso/start", data={"invitation": token})
    params = dict(httpx.URL(started.headers["location"]).params.items())
    code = idp.issue_code(
        idp.claims(
            sub="s-invitee",
            email="invitee@example.com",
            email_verified=DROP,
            nonce=params["nonce"],
        ),
        challenge=params["code_challenge"],
    )
    landed = completion(await callback(client, code, params["state"]))
    assert landed == {"error": "sso_failed"}
    assert (await _reasons(db))[-1] == "email_unverified"
    assert await _pin(db, invitation.user_id) is None
    user = await identity.users.get(invitation.user_id)
    assert user is not None and user.status == "invited"
