"""Recheck (ruling PW8): compare passwords in use with watch lists that changed later.

For every user who holds a password, has a sealed fingerprint, and whose
effective policy enables the fingerprint, ``run`` opens the fingerprint in
memory, checks it against the policy's watch lists (the built-in list, the
attached lists' entries and, when enabled, the range API, asked once per
prefix within the run) and, on a match, flags a required change with the
reason ``watch_list``, ends the user's live sessions if the policy says so,
and audits the match. A fingerprint sealed with the previous key is
re-sealed with the current one. Terms are not checked: they need the
password itself, so sign-in checks them.

warden runs no scheduler: the product calls this (wave 17 adds
``warden passwords recheck``). The report and the audit carry counts only.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from psycopg import sql

from warden.audit import AuditEvent, record_audit
from warden.db import PASSWORD_POLICIES, PASSWORD_STATES, Database, table
from warden.identity.password_policy.fingerprint import Fingerprints, SealedFingerprint
from warden.identity.password_policy.hibp import RangeCache
from warden.identity.password_policy.state import ChangeReason, PasswordStates
from warden.identity.password_policy.store import EFFECTIVE_SQL, PasswordPolicies
from warden.identity.password_policy.watchlists import WatchLists
from warden.identity.tokens import Sessions

__all__ = ["PasswordRecheck", "RecheckReport"]

logger = logging.getLogger(__name__)

_STATES = table(PASSWORD_STATES)
_POLICIES = table(PASSWORD_POLICIES)
SESSION_END_REASON = "password_watch_list"


@dataclass(frozen=True, slots=True)
class RecheckReport:
    """What one run did, in counts."""

    checked: int
    """Fingerprints opened and checked."""
    matched: int
    """Fingerprints found on a watch list."""
    flagged: int
    """Users newly required to change their password."""
    sessions_ended: int
    resealed: int
    """Fingerprints moved from the previous key to the current one."""
    unopened: int
    """Fingerprints that would not open (an unknown key, or tampering)."""
    hibp_unavailable: int
    """Checks the range API could not answer."""
    hibp_lookups: int
    """Range requests made: one per prefix in the run."""


class PasswordRecheck:
    def __init__(
        self,
        db: Database,
        policies: PasswordPolicies,
        watch_lists: WatchLists,
        fingerprints: Fingerprints,
        states: PasswordStates,
        sessions: Sessions,
    ) -> None:
        self._db = db
        self._policies = policies
        self._lists = watch_lists
        self._fingerprints = fingerprints
        self._states = states
        self._sessions = sessions

    async def _candidates(self) -> list[tuple[uuid.UUID, uuid.UUID, str, bytes]]:
        declared = self._policies.declared_roles()
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT e.user_id, e.policy_id, s.fingerprint_key_id, s.fingerprint_sealed"
                    " FROM ({effective}) e"
                    " JOIN {states} s ON s.user_id = e.user_id"
                    " JOIN {policies} p ON p.id = e.policy_id"
                    " WHERE p.fingerprint_enabled AND s.fingerprint_sealed IS NOT NULL"
                    " ORDER BY e.user_id"
                ).format(effective=EFFECTIVE_SQL, states=_STATES, policies=_POLICIES),
                {"declared": declared},
            )
            return [(r[0], r[1], r[2], bytes(r[3])) for r in await cur.fetchall()]

    async def run(self, *, actor: str | None) -> RecheckReport:
        """Check every fingerprinted password in use; flag, end sessions and audit on a match."""
        counts = dict.fromkeys(
            ("checked", "matched", "flagged", "sessions_ended", "resealed", "unopened"), 0
        )
        unavailable = 0
        cache = RangeCache()
        candidates = await self._candidates() if self._fingerprints.available else []
        for user_id, policy_id, key_id, sealed in candidates:
            opened = self._fingerprints.open(user_id, SealedFingerprint(key_id, sealed))
            if opened is None:
                counts["unopened"] += 1
                logger.warning("password fingerprint for user %s does not open", user_id)
                continue
            if opened.resealed is not None:
                await self._states.store_fingerprint(user_id, opened.resealed)
                counts["resealed"] += 1
            policy = await self._policies.get(policy_id)
            checked = await self._lists.match_digest(opened.digest, policy, cache=cache)
            del opened
            counts["checked"] += 1
            unavailable += checked.hibp_unavailable
            if checked.match is None:
                continue
            counts["matched"] += 1
            async with self._db.transaction() as tx:
                flagged = await self._states.require_change(
                    user_id, ChangeReason.WATCH_LIST, match=checked.match, conn=tx
                )
                ended = 0
                if flagged and policy.settings.end_sessions_on_match:
                    ended = await self._sessions.revoke_all(
                        user_id, reason=SESSION_END_REASON, conn=tx
                    )
                details: dict[str, Any] = {
                    "reason": ChangeReason.WATCH_LIST.value,
                    "trigger": "recheck",
                    "source": checked.match.source.value,
                    "list_id": None
                    if checked.match.list_id is None
                    else str(checked.match.list_id),
                    "already_required": not flagged,
                    "sessions_ended": ended,
                }
                await record_audit(
                    AuditEvent(
                        action="warden.identity.password.change_required",
                        outcome="success",
                        actor=actor,
                        resource_type="user",
                        resource_id=str(user_id),
                        details=details,
                    ),
                    conn=tx,
                )
            counts["flagged"] += flagged
            counts["sessions_ended"] += ended
        report = RecheckReport(**counts, hibp_unavailable=unavailable, hibp_lookups=cache.lookups)
        await record_audit(
            AuditEvent(
                action="warden.identity.password.recheck_completed",
                outcome="success",
                actor=actor,
                resource_type="password_policy",
                details=asdict(report),
            )
        )
        return report
