"""The credential store: each user's passkeys and security keys.

``WebAuthnCredential`` carries identifiers and flags only; the public key
and the authenticator's credential id stay in the database and this
package's queries. Every change is scoped by the owner, so one user can
never name another's credential.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import AsyncConnection, sql

from warden.db import Database, table
from warden.db.schema import WEBAUTHN_CREDENTIALS
from warden.identity.webauthn.errors import WebAuthnError, WebAuthnRefusal

__all__ = ["WebAuthnCredential", "WebAuthnCredentials"]

_CREDENTIALS = table(WEBAUTHN_CREDENTIALS)
COLUMNS = sql.SQL(
    "id, user_id, nickname, aaguid, transports, backup_eligible, backup_state, discoverable,"
    " user_verified, attestation_verified, sign_count, created_at, last_used_at"
)
MAX_NICKNAME = 64


@dataclass(frozen=True, slots=True)
class WebAuthnCredential:
    """A registered passkey or security key, as warden describes it."""

    id: uuid.UUID
    """warden's id for the credential (not the authenticator's credential id)."""
    user_id: uuid.UUID
    nickname: str | None
    aaguid: uuid.UUID
    """The authenticator model's AAGUID; all zeros when it gives none."""
    transports: tuple[str, ...]
    backup_eligible: bool
    backup_state: bool
    discoverable: bool
    """Whether the credential can be used without naming the user first."""
    user_verified: bool
    """Whether the user was verified when the credential was registered."""
    attestation_verified: bool
    """Whether its attestation chained to a configured trusted root."""
    sign_count: int
    created_at: datetime
    last_used_at: datetime | None

    @property
    def passkey(self) -> bool:
        """Whether it signs in on its own: discoverable and registered with user verification.

        The rule a discoverable sign-in applies to a stored credential.
        """
        return self.discoverable and self.user_verified


def credential_from_row(row: tuple[Any, ...]) -> WebAuthnCredential:
    return WebAuthnCredential(
        id=row[0],
        user_id=row[1],
        nickname=row[2],
        aaguid=row[3],
        transports=tuple(row[4]),
        backup_eligible=row[5],
        backup_state=row[6],
        discoverable=row[7],
        user_verified=row[8],
        attestation_verified=row[9],
        sign_count=row[10],
        created_at=row[11],
        last_used_at=row[12],
    )


def check_nickname(nickname: str | None, user_id: uuid.UUID) -> str | None:
    """None, or 1 to 64 characters without control characters."""
    if nickname is None:
        return None
    if not 1 <= len(nickname) <= MAX_NICKNAME or any(ch < " " or ch == "\x7f" for ch in nickname):
        raise WebAuthnError(WebAuthnRefusal.NICKNAME, user_id=user_id)
    return nickname


class WebAuthnCredentials:
    """Credentials in ``warden.webauthn_credentials``.

    Every method joins the caller's transaction when given ``conn``. None
    records an audit event: the callers that change credentials do.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    async def get(
        self,
        user_id: uuid.UUID,
        credential_id: uuid.UUID,
        *,
        conn: AsyncConnection[Any] | None = None,
    ) -> WebAuthnCredential | None:
        """The user's credential, or None if they hold no credential with that id."""
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT {} FROM {} WHERE id = %s AND user_id = %s").format(
                    COLUMNS, _CREDENTIALS
                ),
                (credential_id, user_id),
            )
            row = await cur.fetchone()
        return None if row is None else credential_from_row(row)

    async def count(self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None) -> int:
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT count(*) FROM {} WHERE user_id = %s").format(_CREDENTIALS),
                (user_id,),
            )
            row = await cur.fetchone()
        return 0 if row is None else int(row[0])

    async def rename(
        self,
        user_id: uuid.UUID,
        credential_id: uuid.UUID,
        nickname: str | None,
        *,
        conn: AsyncConnection[Any] | None = None,
    ) -> WebAuthnCredential | None:
        """Set or clear the nickname; None if the user holds no such credential."""
        check_nickname(nickname, user_id)
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL(
                    "UPDATE {} SET nickname = %s WHERE id = %s AND user_id = %s RETURNING {}"
                ).format(_CREDENTIALS, COLUMNS),
                (nickname, credential_id, user_id),
            )
            row = await cur.fetchone()
        return None if row is None else credential_from_row(row)

    async def remove(
        self,
        user_id: uuid.UUID,
        credential_id: uuid.UUID,
        *,
        conn: AsyncConnection[Any] | None = None,
    ) -> bool:
        """Remove one of the user's credentials; whether it existed."""
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE id = %s AND user_id = %s").format(_CREDENTIALS),
                (credential_id, user_id),
            )
            return cur.rowcount == 1

    async def remove_all(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> int:
        """Remove every credential the user holds; how many there were."""
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("DELETE FROM {} WHERE user_id = %s").format(_CREDENTIALS), (user_id,)
            )
            return cur.rowcount

    async def list(
        self, user_id: uuid.UUID, *, conn: AsyncConnection[Any] | None = None
    ) -> list[WebAuthnCredential]:
        """The user's credentials, oldest first (ties by id)."""
        async with self._db.transaction(conn) as tx:
            cur = await tx.execute(
                sql.SQL("SELECT {} FROM {} WHERE user_id = %s ORDER BY created_at, id").format(
                    COLUMNS, _CREDENTIALS
                ),
                (user_id,),
            )
            rows = await cur.fetchall()
        return [credential_from_row(row) for row in rows]
