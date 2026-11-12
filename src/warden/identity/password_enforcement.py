"""Password policies in force (rulings PW3 to PW12 of 10 November 2026).

One path for every place a password is set. ``PasswordEnforcement.accept``
checks a candidate against a policy: its rules, its watch lists (with the
range API's on-unavailable setting), the user's history and, where the
place asks for it, the minimum age. A refusal raises ``PasswordRejected``
naming every failure with a stable code and a plain message, and a
watch-list match carries the list's own reason; it never says which
history entry matched. ``record`` then keeps the new hash in the history,
stores the tier and expiry, clears any required change, writes or removes
the sealed fingerprint and audits ``warden.identity.password.changed``, all
in the caller's transaction.

At a password sign-in, after the password is proven and before any second
factor, ``assess_sign_in`` checks the plaintext against the effective
policy's watch lists, re-evaluates it against the current rules (tier and
expiry recomputed from when it was set), writes the fingerprint if the
policy keeps one and none exists, and flags a required change for a match
(``watch_list``), a failure under a policy that enforces on sign-in
(``policy``) or a passed expiry (``expired``). The flags are read when a
session would be issued, after the second factor.

``feedback`` serves the live check routes (PW10): each rule's result, the
passphrase and tier, and any watch-list match with its reason. It never
checks history, stores nothing and audits nothing.

Nothing here logs or audits a password, a hash, a digest, a prefix, a
fingerprint or a challenge: identifiers, rule codes and list ids only.
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, NoReturn

from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, record_audit
from warden.db import PASSWORD_HISTORY, Database, schema, table
from warden.identity.http import SourceIp
from warden.identity.password_policy import (
    BUILTIN_REASON,
    HIBP_REASON,
    ChangeReason,
    Fingerprints,
    PasswordHistory,
    PasswordPolicies,
    PasswordPolicy,
    PasswordRules,
    PasswordStates,
    PolicySettings,
    RuleCode,
    RuleResult,
    UserContext,
    WatchListMatch,
    WatchListNotFound,
    WatchLists,
    WatchListSource,
    evaluate,
)
from warden.identity.password_policy.store import resolve
from warden.identity.passwords import PasswordHasher
from warden.identity.users import UserError

__all__ = [
    "HISTORY_MESSAGE",
    "MIN_AGE_MESSAGE",
    "UNAVAILABLE_MESSAGE",
    "AcceptedPassword",
    "PasswordAdvice",
    "PasswordEnforcement",
    "PasswordFailure",
    "PasswordFeedback",
    "PasswordRejected",
    "PendingChange",
    "SetPlace",
]

SetPlace = Literal["created", "administrator", "change", "reset", "invitation", "forced_change"]
"""Where a password was set, as audited."""

HISTORY = "history"
MIN_AGE = "min_age"
WATCH_LIST = "watch_list"
WATCH_LIST_UNAVAILABLE = "watch_list_unavailable"

REJECTED_DETAIL = "password not accepted"
HISTORY_MESSAGE = "Choose a password you have not used recently"
MIN_AGE_MESSAGE = "Your password was changed too recently to change it again yet"
UNAVAILABLE_MESSAGE = (
    "The password could not be checked against breached passwords; try again later"
)
LISTED_MESSAGE = "This password is on a list of passwords that must not be used"
"""The reason shown for a match on a list that has since been deleted."""

_USERS = table(schema.USERS)
_HISTORY = table(PASSWORD_HISTORY)


def rule_message(code: RuleCode, rules: PasswordRules) -> str:
    """The plain message for a failed rule, naming the policy's limit."""
    if code is RuleCode.MIN_LENGTH:
        return f"Use at least {rules.min_length} characters"
    if code is RuleCode.MAX_LENGTH:
        return f"Use at most {rules.max_length} characters"
    if code is RuleCode.MIN_CLASSES:
        return (
            f"Use at least {rules.min_classes} kinds of character: lower case, upper case,"
            " digits, symbols and other letters"
        )
    if code is RuleCode.MAX_REPEAT:
        return f"Repeat a character at most {rules.max_repeat} times in a row"
    if code is RuleCode.NO_EMAIL:
        return "Do not use your email address"
    return "Do not use your name"


@dataclass(frozen=True, slots=True)
class PasswordFailure:
    """One reason a new password was refused: a stable code and a plain message.

    ``code`` is a rule code (``min_length``, ``max_length``, ``min_classes``,
    ``max_repeat``, ``no_email``, ``no_display_name``), ``watch_list`` (the
    message is the list's reason), ``watch_list_unavailable``, ``history``
    or ``min_age``.
    """

    code: str
    message: str


class PasswordRejected(UserError):
    """A new password was refused; ``failures`` names every reason.

    The message lists the codes only, never the password or anything
    derived from it.
    """

    def __init__(self, failures: Iterable[PasswordFailure]) -> None:
        self.failures = tuple(failures)
        codes = ", ".join(f.code for f in self.failures)
        super().__init__(f"the password was not accepted: {codes}")

    def body(self) -> dict[str, Any]:
        """The documented 400 body: every failure's code and message."""
        return {
            "detail": REJECTED_DETAIL,
            "failures": [{"code": f.code, "message": f.message} for f in self.failures],
        }


@dataclass(frozen=True, slots=True)
class PasswordAdvice:
    """What the description routes answer: the policy's rules and its history count."""

    rules: PasswordRules
    history_count: int

    def describe(self) -> dict[str, Any]:
        return {"rules": self.rules.describe(), "history_count": self.history_count}


@dataclass(frozen=True, slots=True)
class PasswordFeedback:
    """A live check's answer (PW10): never history, never stored, never audited."""

    rules: PasswordRules
    results: tuple[RuleResult, ...]
    passphrase: bool
    tier: str | None
    watch_list: WatchListMatch | None
    watch_list_unavailable: bool
    blocked: bool
    """Refused by a watch list, or by the range API's refuse-when-unavailable setting."""

    @property
    def ok(self) -> bool:
        """Whether the password would pass every check but history (which this never runs)."""
        return all(r.passed for r in self.results) and not self.blocked

    def body(self) -> dict[str, Any]:
        """The check route's answer. A match names the list's reason, never its id."""
        return {
            "ok": self.ok,
            "results": [
                {
                    "code": str(r.code),
                    "passed": r.passed,
                    "waived": r.waived,
                    "message": rule_message(r.code, self.rules),
                }
                for r in self.results
            ],
            "passphrase": self.passphrase,
            "tier": self.tier,
            "watch_list": None if self.watch_list is None else {"reason": self.watch_list.reason},
            "watch_list_unavailable": self.watch_list_unavailable,
        }


@dataclass(frozen=True, slots=True)
class AcceptedPassword:
    """A password that passed every check, hashed and ready to ``record``."""

    password_hash: str = field(repr=False)
    tier: str | None
    policy: PasswordPolicy
    password: str = field(repr=False)
    """Held only to seal the fingerprint in ``record``; never logged."""


@dataclass(frozen=True, slots=True)
class PendingChange:
    """A required change read in the transaction that would issue a session."""

    reason: ChangeReason
    match: WatchListMatch | None


def _match_details(match: WatchListMatch | None) -> dict[str, Any]:
    if match is None:
        return {}
    return {
        "source": match.source.value,
        "list_id": None if match.list_id is None else str(match.list_id),
    }


class PasswordEnforcement:
    """The effective policy applied wherever a password is set or used."""

    def __init__(
        self,
        db: Database,
        hasher: PasswordHasher,
        policies: PasswordPolicies,
        watch_lists: WatchLists,
        history: PasswordHistory,
        states: PasswordStates,
        fingerprints: Fingerprints,
        *,
        clock: Callable[[], float],
    ) -> None:
        self._db = db
        self._hasher = hasher
        self.policies = policies
        self._watch_lists = watch_lists
        self._history = history
        self._states = states
        self._fingerprints = fingerprints
        self._clock = clock

    def now(self) -> datetime:
        return datetime.fromtimestamp(self._clock(), UTC)

    # Which policy

    async def policy_for(self, user_id: uuid.UUID | None) -> PasswordPolicy:
        """The user's effective policy (PW1); the default for a user not yet stored."""
        if user_id is None:
            return await self.policies.default()
        return (await self.policies.effective(user_id)).policy

    async def policy_for_roles(self, roles: Iterable[str]) -> PasswordPolicy:
        """The policy ``roles`` would resolve to if granted, with no pin; else the default."""
        policies = {p.id: p for p in await self.policies.list()}
        role_map = {role: p.id for p in policies.values() for role in p.roles}
        default = next(p.id for p in policies.values() if p.is_default)
        declared = set(self.policies.declared_roles())
        policy, _, _ = resolve(policies, role_map, default, None, roles, declared)
        return policy

    @staticmethod
    def advice(policy: PasswordPolicy) -> PasswordAdvice:
        return PasswordAdvice(policy.settings.rules, policy.settings.history_count)

    def expiry(self, policy: PasswordPolicy, tier: str | None, set_at: datetime) -> datetime | None:
        """When a password of ``tier`` set at ``set_at`` expires under ``policy`` (PW5)."""
        found = next((t for t in policy.settings.rules.tiers if t.name == tier), None)
        if found is None or found.max_age_days is None:
            return None
        return set_at + timedelta(days=found.max_age_days)

    # Setting a password

    async def accept(
        self,
        password: object,
        *,
        policy: PasswordPolicy,
        context: UserContext,
        user_id: uuid.UUID | None,
        place: SetPlace,
        actor: str | None,
        source_ip: SourceIp = None,
        min_age: bool = False,
    ) -> AcceptedPassword:
        """Check ``password`` against ``policy`` and hash it; ``PasswordRejected`` if refused.

        History is checked for a stored user; the minimum age only where
        ``min_age`` asks for it (a user changing their own password). Every
        failure is named. A refusal is audited as
        ``warden.identity.password.rejected`` with the codes and list id only.
        """
        settings = policy.settings
        rules = settings.rules
        if not isinstance(password, str):
            failure = PasswordFailure(
                str(RuleCode.MIN_LENGTH), rule_message(RuleCode.MIN_LENGTH, rules)
            )
            await self._reject((failure,), None, user_id, policy, place, actor, source_ip)
        evaluation = evaluate(password, rules, context)
        failures = [
            PasswordFailure(str(code), rule_message(code, rules)) for code in evaluation.failed
        ]
        check = await self._watch_lists.match(password, settings)
        if check.hibp_unavailable:
            await self._audit_unavailable(user_id, settings, place, source_ip)
        if check.match is not None:
            failures.append(PasswordFailure(WATCH_LIST, check.match.reason))
        elif check.blocked(settings):
            failures.append(PasswordFailure(WATCH_LIST_UNAVAILABLE, UNAVAILABLE_MESSAGE))
        if (
            user_id is not None
            and settings.history_count > 0
            and await self._reused(user_id, password, settings.history_count)
        ):
            failures.append(PasswordFailure(HISTORY, HISTORY_MESSAGE))
        if (
            user_id is not None
            and min_age
            and settings.min_age_hours > 0
            and await self._history.too_soon(
                user_id, min_age_hours=settings.min_age_hours, now=self.now()
            )
        ):
            failures.append(PasswordFailure(MIN_AGE, MIN_AGE_MESSAGE))
        if failures:
            await self._reject(failures, check.match, user_id, policy, place, actor, source_ip)
        password_hash = await self._hasher.hash(password)
        return AcceptedPassword(password_hash, evaluation.tier, policy, password)

    async def _reused(self, user_id: uuid.UUID, password: str, count: int) -> bool:
        """Whether ``password`` is one of the user's last ``count`` passwords (PW6).

        The current password counts as the newest. It is in the history for
        every password set since enforcement began; for one set earlier it
        is checked from the user's row, and the history supplies the rest.
        """
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT u.password_hash, (SELECT h.password_hash FROM {} h"
                    " WHERE h.user_id = u.id ORDER BY h.set_at DESC, h.id DESC LIMIT 1)"
                    " FROM {} u WHERE u.id = %s"
                ).format(_HISTORY, _USERS),
                (user_id,),
            )
            row = await cur.fetchone()
        current, newest = (None, None) if row is None else row
        if current is not None and current != newest:
            if (await self._hasher.verify(current, password)).ok:
                return True
            count -= 1
        return await self._history.reused(user_id, password, count=count)

    async def _reject(
        self,
        failures: Iterable[PasswordFailure],
        match: WatchListMatch | None,
        user_id: uuid.UUID | None,
        policy: PasswordPolicy,
        place: SetPlace,
        actor: str | None,
        source_ip: SourceIp,
    ) -> NoReturn:
        refused = tuple(failures)
        await record_audit(
            AuditEvent(
                action="warden.identity.password.rejected",
                outcome="failure",
                actor=actor,
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details={
                    "via": place,
                    "policy_id": str(policy.id),
                    "codes": [f.code for f in refused],
                    **_match_details(match),
                },
            )
        )
        raise PasswordRejected(refused)

    async def _audit_unavailable(
        self,
        user_id: uuid.UUID | None,
        settings: PolicySettings,
        place: str,
        source_ip: SourceIp,
    ) -> None:
        await record_audit(
            AuditEvent(
                action="warden.identity.password.watch_list_unavailable",
                outcome="success" if settings.hibp_on_unavailable == "allow" else "failure",
                actor=None if user_id is None else str(user_id),
                resource_type=None if user_id is None else "user",
                resource_id=None if user_id is None else str(user_id),
                source_ip=source_ip,
                details={"via": place, "on_unavailable": settings.hibp_on_unavailable},
            )
        )

    async def record(
        self,
        conn: AsyncConnection[Any],
        user_id: uuid.UUID,
        accepted: AcceptedPassword,
        *,
        place: SetPlace,
        actor: str | None,
        source_ip: SourceIp = None,
        **details: Any,
    ) -> None:
        """Keep a newly set password's history, tier, expiry and fingerprint, in ``conn``.

        Clears any required change, and audits ``warden.identity.password.changed``.
        The caller has already written the hash to the user's row.
        """
        policy = accepted.policy
        settings = policy.settings
        now = self.now()
        expires_at = self.expiry(policy, accepted.tier, now)
        fingerprint = None
        if settings.fingerprint_enabled and self._fingerprints.available:
            fingerprint = self._fingerprints.seal(user_id, accepted.password)
        await self._history.record(user_id, accepted.password_hash, conn=conn)
        await self._states.record_set(
            user_id,
            tier=accepted.tier,
            set_at=now,
            expires_at=expires_at,
            fingerprint=fingerprint,
            conn=conn,
        )
        await record_audit(
            AuditEvent(
                action="warden.identity.password.changed",
                outcome="success",
                actor=actor,
                resource_type="user",
                resource_id=str(user_id),
                source_ip=source_ip,
                details={
                    "via": place,
                    "policy_id": str(policy.id),
                    "tier": accepted.tier,
                    "expires_at": None if expires_at is None else expires_at.isoformat(),
                    **details,
                },
            ),
            conn=conn,
        )

    # Signing in with a password

    async def assess_sign_in(
        self,
        user_id: uuid.UUID,
        password: str,
        context: UserContext,
        *,
        source_ip: SourceIp = None,
    ) -> None:
        """After a correct password, before any second factor: flag what the password needs.

        Never refuses the sign-in itself; the flags are read when a session
        would be issued (``pending``), after the second factor. A range API
        that cannot answer is audited and does not stop the sign-in.
        """
        policy = await self.policy_for(user_id)
        settings = policy.settings
        state = await self._states.get(user_id)
        now = self.now()
        check = await self._watch_lists.match(password, settings)
        if check.hibp_unavailable:
            await self._audit_unavailable(user_id, settings, "sign_in", source_ip)
        if check.match is not None:
            await self._flag(user_id, ChangeReason.WATCH_LIST, policy, source_ip, check.match)
        # Re-evaluation (PW11): tier and expiry counted from when the password was set.
        evaluation = evaluate(password, settings.rules, context)
        set_at = None if state is None else state.password_set_at
        expires_at = self.expiry(policy, evaluation.tier, set_at or now)
        if (
            state is None
            or set_at is None
            or state.tier != evaluation.tier
            or state.expires_at != expires_at
        ):
            await self._states.set_tier(
                user_id,
                tier=evaluation.tier,
                expires_at=expires_at,
                set_at=now if set_at is None else None,
            )
        if not evaluation.ok and settings.enforce_on_sign_in:
            await self._flag(user_id, ChangeReason.POLICY, policy, source_ip)
        if (
            settings.fingerprint_enabled
            and self._fingerprints.available
            and (state is None or not state.has_fingerprint)
        ):
            await self._states.store_fingerprint(
                user_id, self._fingerprints.seal(user_id, password)
            )
        if (
            expires_at is not None
            and expires_at <= now
            and await self._flag(user_id, ChangeReason.EXPIRED, policy, source_ip)
        ):
            await record_audit(
                AuditEvent(
                    action="warden.identity.password.expired",
                    outcome="success",
                    actor=None,
                    resource_type="user",
                    resource_id=str(user_id),
                    source_ip=source_ip,
                    details={"policy_id": str(policy.id), "tier": evaluation.tier},
                )
            )

    async def _flag(
        self,
        user_id: uuid.UUID,
        reason: ChangeReason,
        policy: PasswordPolicy,
        source_ip: SourceIp,
        match: WatchListMatch | None = None,
    ) -> bool:
        """Require a change (the first reason stands) and audit it; whether newly required."""
        async with self._db.transaction() as tx:
            flagged = await self._states.require_change(user_id, reason, match=match, conn=tx)
            await record_audit(
                AuditEvent(
                    action="warden.identity.password.change_required",
                    outcome="success",
                    actor=None,
                    resource_type="user",
                    resource_id=str(user_id),
                    source_ip=source_ip,
                    details={
                        "reason": reason.value,
                        "trigger": "sign_in",
                        "policy_id": str(policy.id),
                        "already_required": not flagged,
                        **_match_details(match),
                    },
                ),
                conn=tx,
            )
        return flagged

    async def pending(self, conn: AsyncConnection[Any], user_id: uuid.UUID) -> PendingChange | None:
        """The change the user must make before a session is issued, read in ``conn``."""
        state = await self._states.get(user_id, conn=conn)
        if state is None or state.change_reason is None:
            return None
        match = None
        if state.change_reason is ChangeReason.WATCH_LIST and state.watch_list_source is not None:
            # The reason text is filled in later (``reason_text``), outside the transaction.
            match = WatchListMatch(state.watch_list_source, state.watch_list_id, "")
        return PendingChange(state.change_reason, match)

    async def reason_text(self, source: WatchListSource | None, list_id: uuid.UUID | None) -> str:
        """The user-facing reason of the list a password matched."""
        if source is WatchListSource.BUILTIN:
            return BUILTIN_REASON
        if source is WatchListSource.HIBP:
            return HIBP_REASON
        if list_id is not None:
            try:
                return (await self._watch_lists.get(list_id)).reason
            except WatchListNotFound:
                pass
        return LISTED_MESSAGE

    async def expiry_warning(self, user_id: uuid.UUID) -> int | None:
        """Days until the password expires, within the policy's warning window; else None."""
        state = await self._states.get(user_id)
        if state is None or state.expires_at is None:
            return None
        policy = await self.policy_for(user_id)
        remaining = state.expires_at - self.now()
        window = timedelta(days=policy.settings.rules.warning_days)
        if remaining <= timedelta(0) or remaining > window:
            return None
        return max(1, math.ceil(remaining / timedelta(days=1)))

    # Live feedback (PW10)

    async def feedback(
        self, password: str, policy: PasswordPolicy, context: UserContext
    ) -> PasswordFeedback:
        """Each rule's result and any watch-list match. Never history; stores and audits nothing."""
        settings = policy.settings
        evaluation = evaluate(password, settings.rules, context)
        check = await self._watch_lists.match(password, settings)
        return PasswordFeedback(
            rules=settings.rules,
            results=evaluation.results,
            passphrase=evaluation.passphrase,
            tier=evaluation.tier,
            watch_list=check.match,
            watch_list_unavailable=check.hibp_unavailable,
            blocked=check.blocked(settings),
        )
