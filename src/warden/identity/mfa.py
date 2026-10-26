"""Second factors: TOTP credentials, recovery codes and sign-in challenges.

Every single-use credential here is consumed by one guarded ``UPDATE``:

- a TOTP step, by raising ``last_used_step`` only if it is lower than the
  matched step, so a code is accepted at most once per step;
- a recovery code, by setting ``used_at`` only where it is still null;
- a challenge, by setting ``consumed_at`` only where it is still null.

Concurrent attempts block on the row and re-check the condition when the
first commits, so exactly one succeeds. Only a confirmed TOTP enrolment is
MFA: an unconfirmed credential never verifies.

TOTP secrets are stored sealed (``warden.identity.crypto``), bound to their
user; a secret that does not open is treated as no secret.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, record_audit
from warden.db import Database, table
from warden.identity import schema, totp
from warden.identity.crypto import SecretBox
from warden.identity.errors import MfaError

__all__ = ["CHALLENGE_TTL_SECONDS", "MAX_CHALLENGE_FAILURES", "Challenge", "Enrolment", "Mfa"]

CHALLENGE_TTL_SECONDS = 300
MAX_CHALLENGE_FAILURES = 5

ChallengePurpose = Literal["verify", "enrol"]

logger = logging.getLogger(__name__)

_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}")

_TOTP = table(schema.TOTP_CREDENTIALS)
_CODES = table(schema.RECOVERY_CODES)
_CHALLENGES = table(schema.MFA_CHALLENGES)

_CHALLENGE_LIVE = sql.SQL(
    "consumed_at IS NULL AND expires_at > now() AND failed_attempts < {}"
).format(sql.Literal(MAX_CHALLENGE_FAILURES))


@dataclass(frozen=True, slots=True)
class Enrolment:
    """A started TOTP enrolment, shown to the user once."""

    secret: bytes
    uri: str

    @property
    def secret_base32(self) -> str:
        return base64.b32encode(self.secret).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class Challenge:
    id: uuid.UUID
    user_id: uuid.UUID
    purpose: ChallengePurpose


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


class Mfa:
    def __init__(
        self,
        db: Database,
        *,
        issuer: str,
        box: SecretBox,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._issuer = issuer
        self._box = box
        self._clock = clock

    def _open(self, user_id: uuid.UUID, sealed: bytes, key_id: str) -> bytes | None:
        secret = self._box.open(key_id, bytes(sealed), context=user_id.bytes)
        if secret is None:
            logger.warning("TOTP secret for user %s does not open (key %s)", user_id, key_id)
        return secret

    async def reseal_all(self) -> int:
        """Re-seal every secret not sealed with the current key; returns how many.

        Run after rotating the TOTP key, before removing the previous key.
        """
        resealed = 0
        current = self._box.current_key_id
        async with self._db.transaction() as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT user_id, secret_sealed, key_id FROM {} WHERE key_id <> %s FOR UPDATE"
                ).format(_TOTP),
                (current,),
            )
            for user_id, sealed, key_id in await cur.fetchall():
                secret = self._open(user_id, sealed, key_id)
                if secret is None:
                    continue
                new_key_id, new_sealed = self._box.seal(secret, context=user_id.bytes)
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET secret_sealed = %s, key_id = %s WHERE user_id = %s"
                    ).format(_TOTP),
                    (new_sealed, new_key_id, user_id),
                )
                resealed += 1
        return resealed

    # TOTP enrolment

    async def has_confirmed_totp(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> bool:
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT 1 FROM {} WHERE user_id = %s AND confirmed_at IS NOT NULL").format(
                    _TOTP
                ),
                (user_id,),
            )
            return await cur.fetchone() is not None

    async def begin_enrolment(
        self,
        user_id: uuid.UUID,
        *,
        account: str,
        actor: str | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> Enrolment:
        """Start (or restart) an enrolment. Refused once an enrolment is confirmed."""
        secret = totp.generate_secret()
        key_id, sealed = self._box.seal(secret, context=user_id.bytes)
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "INSERT INTO {} (user_id, secret_sealed, key_id) VALUES (%s, %s, %s)"
                    " ON CONFLICT (user_id) DO UPDATE SET secret_sealed = EXCLUDED.secret_sealed,"
                    " key_id = EXCLUDED.key_id, created_at = now()"
                    " WHERE {}.confirmed_at IS NULL RETURNING 1"
                ).format(_TOTP, _TOTP),
                (user_id, sealed, key_id),
            )
            if await cur.fetchone() is None:
                raise MfaError(f"user {user_id} already has a confirmed TOTP enrolment")
            await record_audit(
                AuditEvent(
                    action="identity.mfa.enrolment_started",
                    outcome="success",
                    actor=actor or str(user_id),
                    resource_type="user",
                    resource_id=str(user_id),
                ),
                conn=tx,
            )
        return Enrolment(
            secret=secret,
            uri=totp.provisioning_uri(secret, account=account, issuer=self._issuer),
        )

    async def confirm_enrolment(
        self,
        user_id: uuid.UUID,
        code: object,
        *,
        actor: str | None = None,
        conn: AsyncConnection[Any] | None = None,
    ) -> list[str] | None:
        """Confirm with a current code. Returns fresh recovery codes, or None if refused.

        The confirming code's step is claimed, so it cannot also complete a sign-in.
        """
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "SELECT secret_sealed, key_id FROM {}"
                    " WHERE user_id = %s AND confirmed_at IS NULL FOR UPDATE"
                ).format(_TOTP),
                (user_id,),
            )
            row = await cur.fetchone()
            secret = None if row is None else self._open(user_id, row[0], row[1])
            if secret is None:
                return None
            step = totp.matching_step(secret, code, totp.step_for(self._clock()))
            if step is None:
                return None
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET confirmed_at = now(), last_used_step = %s"
                    " WHERE user_id = %s AND confirmed_at IS NULL RETURNING 1"
                ).format(_TOTP),
                (step, user_id),
            )
            if await cur.fetchone() is None:
                return None
            codes = await self._replace_recovery_codes(tx, user_id)
            await record_audit(
                AuditEvent(
                    action="identity.mfa.enrolled",
                    outcome="success",
                    actor=actor or str(user_id),
                    resource_type="user",
                    resource_id=str(user_id),
                ),
                conn=tx,
            )
        return codes

    async def _replace_recovery_codes(
        self, tx: AsyncConnection[Any], user_id: uuid.UUID
    ) -> list[str]:
        codes = totp.generate_recovery_codes()
        await tx.execute(sql.SQL("DELETE FROM {} WHERE user_id = %s").format(_CODES), (user_id,))
        async with tx.cursor() as cur:
            await cur.executemany(
                sql.SQL("INSERT INTO {} (user_id, code_hash) VALUES (%s, %s)").format(_CODES),
                [
                    (user_id, totp.hash_recovery_code(totp.parse_recovery_code(c) or ""))
                    for c in codes
                ],
            )
        return codes

    # Single-use claims (call inside the transaction that issues the session)

    async def claim_totp(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, code: object
    ) -> bool:
        """Accept ``code`` for a confirmed enrolment, at most once per step."""
        cur = await conn.execute(
            sql.SQL(
                "SELECT secret_sealed, key_id FROM {} WHERE user_id = %s"
                " AND confirmed_at IS NOT NULL"
            ).format(_TOTP),
            (user_id,),
        )
        row = await cur.fetchone()
        secret = None if row is None else self._open(user_id, row[0], row[1])
        if secret is None:
            return False
        step = totp.matching_step(secret, code, totp.step_for(self._clock()))
        if step is None:
            return False
        cur = await conn.execute(
            sql.SQL(
                "UPDATE {} SET last_used_step = %s WHERE user_id = %s"
                " AND confirmed_at IS NOT NULL"
                " AND (last_used_step IS NULL OR last_used_step < %s) RETURNING 1"
            ).format(_TOTP),
            (step, user_id, step),
        )
        return await cur.fetchone() is not None

    async def consume_recovery_code(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, code: object
    ) -> bool:
        """Use up one recovery code; True if it was valid and unused."""
        normalised = totp.parse_recovery_code(code)
        if normalised is None:
            return False
        cur = await conn.execute(
            sql.SQL(
                "UPDATE {} SET used_at = now() WHERE user_id = %s AND code_hash = %s"
                " AND used_at IS NULL RETURNING 1"
            ).format(_CODES),
            (user_id, totp.hash_recovery_code(normalised)),
        )
        return await cur.fetchone() is not None

    # Challenges: the short-lived handle between the password step and the second factor

    async def create_challenge(
        self, conn: AsyncConnection[Any], user_id: uuid.UUID, purpose: ChallengePurpose
    ) -> str:
        token = secrets.token_urlsafe(32)
        await conn.execute(
            sql.SQL(
                "INSERT INTO {} (token_hash, user_id, purpose, expires_at)"
                " VALUES (%s, %s, %s, now() + %s * interval '1 second')"
            ).format(_CHALLENGES),
            (_hash_token(token), user_id, purpose, CHALLENGE_TTL_SECONDS),
        )
        return token

    async def open_challenge(
        self, conn: AsyncConnection[Any], token: object, purpose: ChallengePurpose
    ) -> Challenge | None:
        """The live challenge ``token`` names, or None. Does not consume it."""
        if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
            return None
        cur = await conn.execute(
            sql.SQL(
                "SELECT id, user_id, purpose FROM {} WHERE token_hash = %s AND purpose = %s AND {}"
            ).format(_CHALLENGES, _CHALLENGE_LIVE),
            (_hash_token(token), purpose),
        )
        row = await cur.fetchone()
        return None if row is None else Challenge(id=row[0], user_id=row[1], purpose=row[2])

    async def consume_challenge(self, conn: AsyncConnection[Any], challenge: Challenge) -> bool:
        """Use up a challenge; False if another request already did."""
        cur = await conn.execute(
            sql.SQL("UPDATE {} SET consumed_at = now() WHERE id = %s AND {} RETURNING 1").format(
                _CHALLENGES, _CHALLENGE_LIVE
            ),
            (challenge.id,),
        )
        return await cur.fetchone() is not None

    async def record_failure(self, challenge: Challenge) -> None:
        """Count a wrong second factor against the challenge, in its own transaction."""
        async with self._db.transaction() as tx:
            await tx.execute(
                sql.SQL("UPDATE {} SET failed_attempts = failed_attempts + 1 WHERE id = %s").format(
                    _CHALLENGES
                ),
                (challenge.id,),
            )
