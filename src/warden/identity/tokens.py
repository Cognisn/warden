"""Sessions: EdDSA access tokens and rotating refresh-token families.

**Access tokens** are compact JWS (``typ: at+jwt``, ``alg: EdDSA``) signed
by ``KeyStore.sign`` with the key id in the header, and verified only by
``KeyStore.verify``: a retired or revoked key refuses a live token. Every
verification also checks, in the database, that the session is live and the
user active, so signing out, suspension and a shortened lifespan take effect
on the next request.

**Refresh tokens** are opaque and stored hashed. A session is one family:
each refresh uses up the presented token with one guarded ``UPDATE`` and
issues its successor. Presenting a used token is reuse, and revokes the
whole family with an audited reason, except that the immediate predecessor
presented within the grace window is only refused (two tabs refreshing at
once). Grace never un-revokes; the trade-off is that a replay inside the
window is not detected.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, record_audit
from warden.db import Database, schema, table
from warden.identity.errors import AuthenticationRefused
from warden.identity.http import SourceIp
from warden.identity.policy import PolicyStore, SessionPolicy
from warden.keys import KeyStore, KeyStoreError

__all__ = ["AccessClaims", "NewSession", "Sessions", "TokenPair"]

_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_REFRESH = re.compile(r"[A-Za-z0-9_-]{32,128}")
_MAX_TOKEN = 4096
_HEADER_KEYS = frozenset({"alg", "typ", "kid"})
# Tolerated clock difference between replicas for ``iat``.
_IAT_LEEWAY = 60

_SESSIONS = table(schema.SESSIONS)
_REFRESH_TOKENS = table(schema.REFRESH_TOKENS)
_USERS = table(schema.USERS)

# A session ends at the earlier of the lifespan it started with and the current one.
_ENDS_AT = sql.SQL("least(s.expires_at, s.created_at + %(lifespan)s * interval '1 second')")


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    session_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class NewSession:
    """A session written in a transaction, before its access token is signed.

    Signing borrows its own pooled connection, so it happens after the
    transaction commits (``Sessions.finish``); a request never holds two
    connections at once.
    """

    user_id: uuid.UUID
    session_id: uuid.UUID
    amr: tuple[str, ...]
    refresh_token: str
    refresh_expires_in: int


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    amr: tuple[str, ...]
    expires_at: int


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


class Sessions:
    def __init__(
        self,
        db: Database,
        keys: KeyStore,
        policy: PolicyStore,
        *,
        issuer: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._keys = keys
        self._policy = policy
        self._issuer = issuer
        self._clock = clock

    # Access tokens

    async def issue_access_token(
        self,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        amr: Sequence[str],
        *,
        now: float | None = None,
    ) -> tuple[str, int]:
        """A signed access token and its lifetime in seconds."""
        ttl = (await self._policy.current()).access_token_ttl_seconds
        issued = int(self._clock() if now is None else now)
        claims = _b64(
            _json(
                {
                    "iss": self._issuer,
                    "sub": str(user_id),
                    "sid": str(session_id),
                    "iat": issued,
                    "exp": issued + ttl,
                    "jti": uuid.uuid4().hex,
                    "amr": list(amr),
                }
            )
        )
        # The key id goes in the signed header, so read it first; if a rotation
        # lands between that read and the signature, sign again with the new key.
        for _ in range(3):
            kid = (await self._keys.active_key()).key_id
            signing_input = f"{_b64(_json({'alg': 'EdDSA', 'typ': 'at+jwt', 'kid': kid}))}.{claims}"
            signature = await self._keys.sign(signing_input.encode("ascii"))
            if signature.key_id == kid:
                return f"{signing_input}.{_b64(signature.signature)}", ttl
        raise KeyStoreError("the signing key changed repeatedly while signing a token")

    async def verify_access_token(self, token: object) -> AccessClaims | None:
        """The claims of a validly signed, unexpired token, or None. No session check."""
        if not isinstance(token, str) or len(token) > _MAX_TOKEN:
            return None
        parts = token.split(".")
        if len(parts) != 3 or any(_B64URL.fullmatch(p) is None for p in parts):
            return None
        try:
            header = json.loads(_unb64(parts[0]))
            signature = _unb64(parts[2])
        except (ValueError, binascii.Error):
            return None
        if (
            not isinstance(header, dict)
            or header.keys() != _HEADER_KEYS
            or header["alg"] != "EdDSA"
            or header["typ"] != "at+jwt"
            or not isinstance(header["kid"], str)
            or len(signature) != 64
        ):
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        if not await self._keys.verify(signing_input, signature, header["kid"]):
            return None
        try:
            claims = json.loads(_unb64(parts[1]))
        except (ValueError, binascii.Error):
            return None
        return self._check_claims(claims)

    def _check_claims(self, claims: object) -> AccessClaims | None:
        if not isinstance(claims, dict):
            return None
        now = self._clock()
        exp, iat, amr = claims.get("exp"), claims.get("iat"), claims.get("amr")
        if (
            claims.get("iss") != self._issuer
            or not isinstance(exp, int)
            or isinstance(exp, bool)
            or not isinstance(iat, int)
            or isinstance(iat, bool)
            or not isinstance(amr, list)
            or not all(isinstance(m, str) for m in amr)
        ):
            return None
        if exp <= now or iat > now + _IAT_LEEWAY:
            return None
        try:
            user_id = uuid.UUID(str(claims.get("sub")))
            session_id = uuid.UUID(str(claims.get("sid")))
        except ValueError:
            return None
        return AccessClaims(user_id=user_id, session_id=session_id, amr=tuple(amr), expires_at=exp)

    async def live_email(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, session_id: uuid.UUID
    ) -> str | None:
        """The user's email if the session is live and the user active, else None."""
        policy = await self._policy.current()
        cur = await conn.execute(
            sql.SQL(
                "SELECT u.email FROM {} s JOIN {} u ON u.id = s.user_id"
                " WHERE s.id = %(sid)s AND s.user_id = %(uid)s AND s.revoked_at IS NULL"
                " AND u.status = 'active' AND now() < {}"
            ).format(_SESSIONS, _USERS, _ENDS_AT),
            {"sid": session_id, "uid": user_id, "lifespan": policy.session_lifespan_seconds},
        )
        row = await cur.fetchone()
        return None if row is None else str(row[0])

    # Sessions and refresh tokens

    async def start(
        self,
        conn: AsyncConnection[Any],
        user_id: uuid.UUID,
        amr: Sequence[str],
        policy: SessionPolicy,
    ) -> NewSession:
        """Open a session (a new family) inside the caller's transaction.

        Read ``policy`` before opening the transaction; call ``finish`` after
        it commits.
        """
        session_id = uuid.uuid4()
        await conn.execute(
            sql.SQL(
                "INSERT INTO {} (id, user_id, created_at, expires_at, amr)"
                " VALUES (%s, %s, now(), now() + %s * interval '1 second', %s)"
            ).format(_SESSIONS),
            (session_id, user_id, policy.session_lifespan_seconds, list(amr)),
        )
        refresh, refresh_ttl = await self._insert_refresh(
            conn, session_id, 0, policy, policy.session_lifespan_seconds
        )
        return NewSession(user_id, session_id, tuple(amr), refresh, refresh_ttl)

    async def finish(self, new: NewSession) -> TokenPair:
        """Sign the access token for a committed session."""
        access, ttl = await self.issue_access_token(new.user_id, new.session_id, new.amr)
        return TokenPair(access, ttl, new.refresh_token, new.refresh_expires_in, new.session_id)

    async def _insert_refresh(
        self,
        conn: AsyncConnection[Any],
        session_id: uuid.UUID,
        generation: int,
        policy: SessionPolicy,
        session_remaining: float,
    ) -> tuple[str, int]:
        ttl = int(min(float(policy.refresh_token_ttl_seconds), float(session_remaining)))
        token = secrets.token_urlsafe(32)
        await conn.execute(
            sql.SQL(
                "INSERT INTO {} (token_hash, session_id, generation, issued_at, expires_at)"
                " VALUES (%s, %s, %s, now(), now() + %s * interval '1 second')"
            ).format(_REFRESH_TOKENS),
            (_hash(token), session_id, generation, ttl),
        )
        return token, ttl

    async def rotate(self, refresh_token: object, *, source_ip: SourceIp = None) -> TokenPair:
        """Use up ``refresh_token`` and issue its successor, or raise ``AuthenticationRefused``.

        Every refusal is audited with its reason; a detected reuse revokes the
        family in the same transaction as its audit event.
        """
        if not isinstance(refresh_token, str) or _REFRESH.fullmatch(refresh_token) is None:
            await self._refused("malformed", None, None, source_ip)
        policy = await self._policy.current()
        token_hash = _hash(refresh_token)
        new: NewSession | None = None
        reason: str | None = None
        user_id: uuid.UUID | None = None
        session_id: uuid.UUID | None = None
        async with self._db.transaction() as tx:
            for _attempt in range(2):
                row = await self._classify(tx, token_hash, policy)
                if row is None:
                    reason = "unknown_token"
                    break
                user_id, session_id = row["user_id"], row["session_id"]
                reason = self._refusal_reason(row)
                if reason == "refresh_reuse":
                    await self._revoke_for_reuse(tx, row, source_ip)
                    break
                if reason is not None:
                    break
                cur = await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET used_at = now() WHERE token_hash = %s AND used_at IS NULL"
                        " RETURNING 1"
                    ).format(_REFRESH_TOKENS),
                    (token_hash,),
                )
                if await cur.fetchone() is None:
                    reason = "concurrent_use"
                    continue  # another request used it first: classify again
                refresh, refresh_ttl = await self._insert_refresh(
                    tx, session_id, row["generation"] + 1, policy, row["remaining"]
                )
                await tx.execute(
                    sql.SQL("UPDATE {} SET last_refreshed_at = now() WHERE id = %s").format(
                        _SESSIONS
                    ),
                    (session_id,),
                )
                new = NewSession(user_id, session_id, tuple(row["amr"]), refresh, refresh_ttl)
                break
            else:
                reason = "concurrent_use"
        if reason is not None or new is None:
            await self._refused(reason or "concurrent_use", user_id, session_id, source_ip)
        return await self.finish(new)

    async def _classify(
        self, tx: AsyncConnection[Any], token_hash: bytes, policy: SessionPolicy
    ) -> dict[str, Any] | None:
        cur = await tx.execute(
            sql.SQL(
                "SELECT t.session_id, t.generation, t.expires_at <= now() AS token_expired,"
                " t.used_at IS NOT NULL AS used,"
                " t.used_at IS NOT NULL AND now() - t.used_at"
                " <= %(grace)s * interval '1 second' AS within_grace,"
                " (SELECT max(x.generation) FROM {} x WHERE x.session_id = t.session_id) AS tip,"
                " s.user_id, s.revoked_at IS NOT NULL AS revoked,"
                " now() >= {} AS ended,"
                " extract(epoch FROM {} - now()) AS remaining,"
                " u.status, s.amr"
                " FROM {} t JOIN {} s ON s.id = t.session_id JOIN {} u ON u.id = s.user_id"
                " WHERE t.token_hash = %(hash)s"
            ).format(_REFRESH_TOKENS, _ENDS_AT, _ENDS_AT, _REFRESH_TOKENS, _SESSIONS, _USERS),
            {
                "grace": policy.refresh_reuse_grace_seconds,
                "lifespan": policy.session_lifespan_seconds,
                "hash": token_hash,
            },
        )
        row = await cur.fetchone()
        if row is None:
            return None
        names = [d.name for d in cur.description or ()]
        return dict(zip(names, row, strict=True))

    @staticmethod
    def _refusal_reason(row: dict[str, Any]) -> str | None:
        if row["revoked"]:
            return "session_revoked"
        if row["used"]:
            if row["within_grace"] and row["generation"] == row["tip"] - 1:
                return "reuse_within_grace"
            return "refresh_reuse"
        if row["ended"]:
            return "session_ended"
        if row["status"] != "active":
            return "user_inactive"
        if row["token_expired"]:
            return "token_expired"
        return None

    async def _revoke_for_reuse(
        self, tx: AsyncConnection[Any], row: dict[str, Any], source_ip: SourceIp
    ) -> None:
        await self._revoke(tx, row["session_id"], "refresh_reuse")
        await record_audit(
            AuditEvent(
                action="identity.session.reuse_detected",
                outcome="failure",
                actor=str(row["user_id"]),
                resource_type="session",
                resource_id=str(row["session_id"]),
                source_ip=source_ip,
                details={"reason": "refresh_reuse", "generation": row["generation"]},
            ),
            conn=tx,
        )

    async def _refused(
        self,
        reason: str,
        user_id: uuid.UUID | None,
        session_id: uuid.UUID | None,
        source_ip: SourceIp,
    ) -> NoReturn:
        if reason != "refresh_reuse":  # already audited with the revocation
            await record_audit(
                AuditEvent(
                    action="identity.session.refresh",
                    outcome="failure",
                    actor=None if user_id is None else str(user_id),
                    resource_type="session",
                    resource_id=None if session_id is None else str(session_id),
                    source_ip=source_ip,
                    details={"reason": reason},
                )
            )
        raise AuthenticationRefused(reason)

    async def revoke(
        self, session_id: uuid.UUID, *, reason: str, conn: AsyncConnection[Any] | None = None
    ) -> bool:
        """End a session (and so its family). False if it was already ended."""
        async with self._db.transaction(conn) as tx:
            return await self._revoke(tx, session_id, reason)

    async def revoke_all(
        self,
        user_id: uuid.UUID,
        *,
        reason: str,
        keep: uuid.UUID | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> int:
        """End every live session of a user, except ``keep``. Returns how many ended."""
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET revoked_at = now(), revoked_reason = %s WHERE user_id = %s"
                    " AND revoked_at IS NULL AND id IS DISTINCT FROM %s"
                ).format(_SESSIONS),
                (reason, user_id, keep),
            )
            return cur.rowcount

    async def _revoke(self, tx: AsyncConnection[Any], session_id: uuid.UUID, reason: str) -> bool:
        cur = await tx.execute(
            sql.SQL(
                "UPDATE {} SET revoked_at = now(), revoked_reason = %s"
                " WHERE id = %s AND revoked_at IS NULL"
            ).format(_SESSIONS),
            (reason, session_id),
        )
        return cur.rowcount == 1
