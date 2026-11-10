"""Password policy and watch list administration (rulings PW1, PW2, PW3 to PW8, PW11).

Mounted by ``admin_router`` under the product's admin prefix, every route
behind one permission. Every change goes through the password policy
stores, which audit it under ``warden.identity.password_policy.*``,
``warden.identity.watch_list.*`` or ``warden.identity.password.*`` with the
administrator as actor, in the change's own transaction.

Nothing here returns a secret. No route returns a watch list's entries,
terms or hashes: an exact entry arrives as plaintext over TLS, is hashed to
SHA-1 by the store at once and never stored, logged, echoed or audited.
Bodies are parsed here and never echoed back; a refused policy names each
field at fault with a fixed message.

| Route | Body | Success |
|---|---|---|
| ``GET /password-policies`` | | ``{"policies": [...]}`` |
| ``POST /password-policies`` | settings and ``priority`` | 201 ``{"policy"}`` |
| ``GET /password-policies/{id}`` | | ``{"policy"}`` |
| ``PUT /password-policies/{id}`` | ``version`` and settings to change | ``{"policy"}`` |
| ``DELETE /password-policies/{id}`` | | 204 |
| ``PUT /password-policies/{id}/priority`` | ``priority`` | ``{"policy"}`` |
| ``PUT /password-policy-order`` | ``policy_ids`` | ``{"policies": [...]}`` |
| ``PUT /password-policies/{id}/builtin-list`` | ``include`` | ``{"policy"}`` |
| ``PUT /password-policies/{id}/watch-lists/{list}`` | | ``{"policy"}`` |
| ``DELETE /password-policies/{id}/watch-lists/{list}`` | | ``{"policy"}`` |
| ``GET /password-policies/{id}/affected-users`` | | ``{"affected_users"}`` |
| ``POST /password-policies/affected-users`` | a proposal | ``{"current", "proposed"}`` |
| ``PUT /password-policy-roles/{role}`` | ``policy_id`` | 204 |
| ``DELETE /password-policy-roles/{role}`` | | 204 |
| ``GET /users/{id}/password-policy`` | | the user's password status |
| ``PUT /users/{id}/password-policy`` | ``policy_id`` | the user's password status |
| ``DELETE /users/{id}/password-policy`` | | 204 |
| ``PUT /users/{id}/password-change-required`` | | ``{"change_required", "change_reason"}`` |
| ``DELETE /users/{id}/password-change-required`` | | 204 (404 if none was required) |
| ``GET /watch-lists`` | | ``{"watch_lists": [...]}`` |
| ``POST /watch-lists`` | ``name``, ``reason``, ``kind`` | 201 ``{"watch_list"}`` |
| ``GET /watch-lists/{id}`` | | ``{"watch_list"}`` |
| ``PUT /watch-lists/{id}`` | ``name`` and or ``reason`` | ``{"watch_list"}`` |
| ``DELETE /watch-lists/{id}`` | | 204 |
| ``POST /watch-lists/{id}/entries`` | ``passwords`` | ``{"added"}`` |
| ``POST /watch-lists/{id}/entries/removal`` | ``passwords`` | ``{"removed"}`` |
| ``POST /watch-lists/{id}/terms`` | ``terms`` | ``{"added"}`` |
| ``POST /watch-lists/{id}/terms/removal`` | ``terms`` | ``{"removed"}`` |
| ``GET /password-exposures[?limit=&after=]`` | | the exposure report |
"""

import dataclasses
import re
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from psycopg import sql

from warden.audit import AuditEvent, record_audit
from warden.db import (
    PASSWORD_POLICIES,
    PASSWORD_POLICY_PINS,
    PASSWORD_POLICY_ROLES,
    PASSWORD_POLICY_WATCH_LISTS,
    PASSWORD_STATES,
    schema,
    table,
)
from warden.identity.dependencies import Principal, require_permission
from warden.identity.http import NO_STORE, json_response, read_object
from warden.identity.password_policy import (
    ChangeReason,
    PassphraseRule,
    PasswordPolicy,
    PasswordPolicyConflict,
    PasswordPolicyError,
    PasswordPolicyNotFound,
    PasswordRules,
    PolicySettings,
    Tier,
    WatchList,
    WatchListConflict,
    WatchListError,
    WatchListKind,
    WatchListNotFound,
)
from warden.identity.password_policy.store import EFFECTIVE_SQL
from warden.identity.passwords import MAX_PASSWORD_LENGTH
from warden.identity.routers.contract import (
    FORBIDDEN,
    REFUSED,
    AffectedUsersProposalBody,
    BuiltinListBody,
    PasswordPolicyCreateBody,
    PasswordPolicyOrderBody,
    PasswordPolicyPinBody,
    PasswordPolicyPriorityBody,
    PasswordPolicyRoleBody,
    PasswordPolicyUpdateBody,
    WardenAffectedUsers,
    WardenAffectedUsersProposal,
    WardenChangeRequired,
    WardenPasswordExposures,
    WardenPasswordPolicyEnvelope,
    WardenPasswordPolicyInvalid,
    WardenPasswordPolicyList,
    WardenUserPasswordStatus,
    WardenWatchListCount,
    WardenWatchListEnvelope,
    WardenWatchListList,
    WatchListCreateBody,
    WatchListEntriesBody,
    WatchListTermsBody,
    WatchListUpdateBody,
    detail,
    json_body,
    no_store,
)
from warden.identity.users import SignInMethod, User

if TYPE_CHECKING:
    from warden.identity.service import Identity

__all__ = ["build_password_admin_router", "password_status"]

MAX_ENTRIES = 100
"""Exact passwords or terms in one request."""
MAX_ENTRY_LENGTH = 1024

_MAX_PAGE = 1000
_PAGE_SIZE = re.compile(r"[1-9][0-9]{0,3}")
_INVALID_POLICY = "the password policy is not valid"
_SIGNS_IN_OTHERWISE = "the user does not sign in with a password"

_POLICIES = table(PASSWORD_POLICIES)
_ROLES = table(PASSWORD_POLICY_ROLES)
_PINS = table(PASSWORD_POLICY_PINS)
_ATTACHED = table(PASSWORD_POLICY_WATCH_LISTS)
_STATES = table(PASSWORD_STATES)
_USERS = table(schema.USERS)
_ASSIGNMENTS = table(schema.ROLE_ASSIGNMENTS)

# Settings an administrator sends, with the type each must have. ``rules``
# fields are flat in the body. Whole numbers are checked as such (``True``
# is not one), and ``max_repeat`` may be null.
_INTS = (
    "min_length",
    "max_length",
    "min_classes",
    "warning_days",
    "history_count",
    "min_age_hours",
)
_BOOLS = (
    "forbid_user_details",
    "include_builtin",
    "hibp_enabled",
    "fingerprint_enabled",
    "end_sessions_on_match",
    "enforce_on_sign_in",
)
_TEXTS = ("name", "description", "hibp_on_unavailable")
_OTHERS = ("max_repeat", "passphrase", "tiers", "watch_list_ids")
_SETTINGS = frozenset((*_INTS, *_BOOLS, *_TEXTS, *_OTHERS))
_FIELD = re.compile(r"[a-z_]+(?:\[[0-9]+\])?(?:\.[a-z_]+)?")


class _Invalid(Exception):
    """A policy body refused, with each field at fault and a fixed message."""

    def __init__(self, errors: list[tuple[str | None, str]]) -> None:
        super().__init__("invalid")
        self.errors = errors


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat()


def _id(text: object) -> uuid.UUID | None:
    if not isinstance(text, str) or len(text) != 36:
        return None
    try:
        return uuid.UUID(text)
    except ValueError:
        return None


def _detail(message: str, status_code: int) -> Response:
    return json_response({"detail": message}, status_code)


def _not_found() -> Response:
    return _detail("not found", 404)


def _invalid_request() -> Response:
    return _detail("the request is not valid", 400)


def _no_content() -> Response:
    return Response(status_code=204, headers=NO_STORE)


def _whole(value: object) -> bool:
    return type(value) is int


def _priority(value: object) -> int | None:
    """A priority from a body: a whole number from 1 to 10000, else None."""
    return value if type(value) is int and 1 <= value <= 10000 else None


# Policies: the view and the body


def _policy(policy: PasswordPolicy) -> dict[str, Any]:
    settings = policy.settings
    rules = settings.rules
    phrase = rules.passphrase
    return {
        "id": str(policy.id),
        "name": settings.name,
        "description": settings.description,
        "priority": policy.priority,
        "is_default": policy.is_default,
        "version": policy.version,
        "roles": list(policy.roles),
        "min_length": rules.min_length,
        "max_length": rules.max_length,
        "min_classes": rules.min_classes,
        "max_repeat": rules.max_repeat,
        "forbid_user_details": rules.forbid_user_details,
        "passphrase": None
        if phrase is None
        else {
            "min_length": phrase.min_length,
            "min_words": phrase.min_words,
            "relaxes_classes": phrase.relaxes_classes,
        },
        "tiers": [
            {
                "name": t.name,
                "passphrase": t.passphrase,
                "min_length": t.min_length,
                "min_classes": t.min_classes,
                "max_age_days": t.max_age_days,
            }
            for t in rules.tiers
        ],
        "warning_days": rules.warning_days,
        "history_count": settings.history_count,
        "min_age_hours": settings.min_age_hours,
        "include_builtin": settings.include_builtin,
        "watch_list_ids": [str(i) for i in settings.watch_list_ids],
        "hibp_enabled": settings.hibp_enabled,
        "hibp_on_unavailable": settings.hibp_on_unavailable,
        "fingerprint_enabled": settings.fingerprint_enabled,
        "end_sessions_on_match": settings.end_sessions_on_match,
        "enforce_on_sign_in": settings.enforce_on_sign_in,
        "created_at": _iso(policy.created_at),
        "updated_at": _iso(policy.updated_at),
    }


def _passphrase(value: object, errors: list[tuple[str | None, str]]) -> PassphraseRule | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"min_length", "min_words", "relaxes_classes"}:
        errors.append(("passphrase", "passphrase must be null or an object of its rule"))
        return None
    length, words = value.get("min_length"), value.get("min_words")
    relaxes = value.get("relaxes_classes", False)
    if not _whole(length):
        errors.append(("passphrase.min_length", "passphrase.min_length must be a whole number"))
    if not _whole(words):
        errors.append(("passphrase.min_words", "passphrase.min_words must be a whole number"))
    if type(relaxes) is not bool:
        errors.append(
            ("passphrase.relaxes_classes", "passphrase.relaxes_classes must be true or false")
        )
    if type(length) is not int or type(words) is not int or type(relaxes) is not bool:
        return None
    return PassphraseRule(min_length=length, min_words=words, relaxes_classes=relaxes)


_TIER_KEYS = frozenset({"name", "passphrase", "min_length", "min_classes", "max_age_days"})


def _tiers(value: object, errors: list[tuple[str | None, str]]) -> tuple[Tier, ...]:
    if not isinstance(value, list) or len(value) > 64:
        errors.append(("tiers", "tiers must be a list of tiers"))
        return ()
    tiers: list[Tier] = []
    for index, raw in enumerate(value):
        where = f"tiers[{index}]"
        if not isinstance(raw, dict) or set(raw) - _TIER_KEYS:
            errors.append((where, f"{where} must be an object of a tier's fields"))
            continue
        name, phrase = raw.get("name"), raw.get("passphrase", False)
        length, classes = raw.get("min_length", 0), raw.get("min_classes", 0)
        age = raw.get("max_age_days")
        bad = False
        for field, ok, message in (
            ("name", isinstance(name, str), "must be text"),
            ("passphrase", type(phrase) is bool, "must be true or false"),
            ("min_length", _whole(length), "must be a whole number"),
            ("min_classes", _whole(classes), "must be a whole number"),
            ("max_age_days", age is None or _whole(age), "must be a whole number or null"),
        ):
            if not ok:
                errors.append((f"{where}.{field}", f"{where}.{field} {message}"))
                bad = True
        if not bad:
            tiers.append(Tier(str(name), phrase, length, classes, age))
    return tuple(tiers)


def _settings(
    body: Mapping[str, Any], base: PolicySettings | None
) -> tuple[PolicySettings, list[tuple[str | None, str]]]:
    """Settings from a body, over ``base`` (an update) or the defaults (a create)."""
    errors: list[tuple[str | None, str]] = []
    for name in _INTS:
        if name in body and not _whole(body[name]):
            errors.append((name, f"{name} must be a whole number"))
    for name in _BOOLS:
        if name in body and type(body[name]) is not bool:
            errors.append((name, f"{name} must be true or false"))
    for name in _TEXTS:
        if name in body and not isinstance(body[name], str):
            errors.append((name, f"{name} must be text"))
    if "max_repeat" in body and not (body["max_repeat"] is None or _whole(body["max_repeat"])):
        errors.append(("max_repeat", "max_repeat must be a whole number or null"))
    lists: tuple[uuid.UUID, ...] = () if base is None else base.watch_list_ids
    if "watch_list_ids" in body:
        raw = body["watch_list_ids"]
        parsed = [_id(i) for i in raw] if isinstance(raw, list) and len(raw) <= 64 else [None]
        if any(i is None for i in parsed):
            errors.append(("watch_list_ids", "watch_list_ids must be a list of watch list ids"))
        else:
            lists = tuple(i for i in parsed if i is not None)
    if base is None and "min_length" not in body:
        errors.append(("min_length", "min_length is required"))
    if base is None and "name" not in body:
        errors.append(("name", "name is required"))
    old = None if base is None else base.rules
    phrase = old.passphrase if old is not None else None
    if "passphrase" in body:
        phrase = _passphrase(body["passphrase"], errors)
    tiers = old.tiers if old is not None else ()
    if "tiers" in body:
        tiers = _tiers(body["tiers"], errors)
    if errors:
        return PolicySettings(name="", rules=PasswordRules(min_length=8)), errors

    def pick(name: str, default: Any) -> Any:
        return body.get(name, default)

    rules = PasswordRules(
        min_length=pick("min_length", None if old is None else old.min_length),
        max_length=pick("max_length", MAX_PASSWORD_LENGTH if old is None else old.max_length),
        min_classes=pick("min_classes", 0 if old is None else old.min_classes),
        max_repeat=pick("max_repeat", None if old is None else old.max_repeat),
        forbid_user_details=pick(
            "forbid_user_details", False if old is None else old.forbid_user_details
        ),
        passphrase=phrase,
        tiers=tiers,
        warning_days=pick("warning_days", 14 if old is None else old.warning_days),
    )
    start = base if base is not None else PolicySettings(name="", rules=rules)
    changes = {
        name: body[name]
        for name in (*_TEXTS, *_BOOLS, "history_count", "min_age_hours")
        if name in body
    }
    return dataclasses.replace(start, rules=rules, watch_list_ids=lists, **changes), errors


def _field_of(problem: str) -> str | None:
    head = problem.split(" ", 1)[0]
    if head == "the":  # "the last tier must be met by every password ..."
        return "tiers"
    return head if _FIELD.fullmatch(head) else None


def _refused(errors: list[tuple[str | None, str]]) -> Response:
    return json_response(
        {
            "detail": _INVALID_POLICY,
            "errors": [{"field": field, "message": message} for field, message in errors],
        },
        400,
    )


def _check(identity: "Identity", settings: PolicySettings) -> list[tuple[str | None, str]]:
    problems = settings.problems(
        fingerprint_available=identity.password_policies.fingerprint_available
    )
    return [(_field_of(p), p) for p in _split(problems)]


def _split(problems: list[str]) -> list[str]:
    # PasswordRules.validate() joins its problems with "; " into one; split them back.
    found: list[str] = []
    for problem in problems:
        found.extend(part for part in problem.split("; ") if part)
    return found


# Users


async def password_status(identity: "Identity", user: User) -> dict[str, Any]:
    """A user's effective password policy, why it applies, their tier, expiry and change state.

    Identifiers, names and times only. Policies apply only to users who sign
    in with a password (``password_and_sso``): for anyone else ``applies`` is
    false and the policy fields are null.
    """
    applies = user.sign_in_method is SignInMethod.PASSWORD_AND_SSO
    state = await identity.password_states.get(user.id)
    view: dict[str, Any] = {
        "applies": applies,
        "policy": None,
        "source": None,
        "role": None,
        "tier": None if state is None else state.tier,
        "password_set_at": None if state is None else _iso(state.password_set_at),
        "expires_at": None if state is None else _iso(state.expires_at),
        "change_required": state is not None and state.change_reason is not None,
        "change_reason": None
        if state is None or state.change_reason is None
        else state.change_reason.value,
        "watch_list_source": None
        if state is None or state.watch_list_source is None
        else state.watch_list_source.value,
        "watch_list_id": None
        if state is None or state.watch_list_id is None
        else str(state.watch_list_id),
    }
    if applies:
        effective = await identity.password_policies.effective(user.id)
        view["policy"] = {"id": str(effective.policy.id), "name": effective.policy.name}
        view["source"] = effective.source
        view["role"] = effective.role
    return view


# Watch lists


def _watch_list(listed: WatchList, policies: list[str]) -> dict[str, Any]:
    return {
        "id": str(listed.id),
        "name": listed.name,
        "reason": listed.reason,
        "kind": listed.kind.value,
        "entry_count": listed.entry_count,
        "term_count": len(listed.terms),
        "import_threshold": listed.import_threshold,
        "last_imported_at": _iso(listed.last_imported_at),
        "policy_ids": policies,
        "created_at": _iso(listed.created_at),
        "updated_at": _iso(listed.updated_at),
    }


def _texts(value: object, *, longest: int) -> list[str] | None:
    """A non-empty list of at most ``MAX_ENTRIES`` strings, each 1 to ``longest`` long."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ENTRIES:
        return None
    if not all(isinstance(v, str) and 1 <= len(v) <= longest for v in value):
        return None
    return value


# Affected users


_PROPOSED_SQL = sql.SQL(
    """
    WITH prio AS (
        SELECT id, CASE WHEN id = %(target)s THEN %(priority)s::int ELSE priority END AS priority
        FROM {policies}
        UNION ALL
        SELECT %(target)s, %(priority)s::int
        WHERE NOT EXISTS (SELECT 1 FROM {policies} WHERE id = %(target)s)
    ),
    rmap AS (
        SELECT role, policy_id FROM {roles}
        WHERE policy_id <> %(target)s AND NOT (role = ANY(%(roles)s::text[]))
        UNION ALL
        SELECT r, %(target)s FROM unnest(%(roles)s::text[]) AS r
    ),
    mapped AS (
        SELECT a.user_id, p.id AS policy_id,
               row_number() OVER (PARTITION BY a.user_id ORDER BY p.priority, a.role) AS rank
        FROM {assignments} a
        JOIN rmap r ON r.role = a.role
        JOIN prio p ON p.id = r.policy_id
        WHERE (a.expires_at IS NULL OR a.expires_at > now())
          AND a.role = ANY(%(declared)s::text[]) AND p.priority IS NOT NULL
    )
    SELECT count(*)
    FROM {users} u
    LEFT JOIN {pins} pin ON pin.user_id = u.id
    LEFT JOIN mapped m ON m.user_id = u.id AND m.rank = 1
    WHERE u.sign_in_method = 'password_and_sso'
      AND COALESCE(pin.policy_id, m.policy_id,
                   (SELECT id FROM {policies} WHERE is_default)) = %(target)s
    """
).format(policies=_POLICIES, roles=_ROLES, assignments=_ASSIGNMENTS, users=_USERS, pins=_PINS)


async def _proposed_count(
    identity: "Identity", target: uuid.UUID, priority: int | None, roles: list[str]
) -> int:
    async with identity.db.connection() as conn:
        cur = await conn.execute(
            _PROPOSED_SQL,
            {
                "target": target,
                "priority": priority,
                "roles": roles,
                "declared": identity.password_policies.declared_roles(),
            },
        )
        row = await cur.fetchone()
    return 0 if row is None else int(row[0])


# The exposure report


_EXPOSED_SQL = sql.SQL(
    """
    SELECT s.user_id, s.watch_list_source, s.watch_list_id, e.policy_id
    FROM {states} s
    LEFT JOIN ({effective}) e ON e.user_id = s.user_id
    WHERE s.change_reason = 'watch_list'
      AND (%(after)s::uuid IS NULL OR s.user_id > %(after)s::uuid)
    ORDER BY s.user_id
    LIMIT %(limit)s
    """
).format(states=_STATES, effective=EFFECTIVE_SQL)

_EXPOSED_COUNTS_SQL = sql.SQL(
    """
    SELECT s.watch_list_source, s.watch_list_id, e.policy_id, count(*)
    FROM {states} s
    LEFT JOIN ({effective}) e ON e.user_id = s.user_id
    WHERE s.change_reason = 'watch_list'
    GROUP BY s.watch_list_source, s.watch_list_id, e.policy_id
    """
).format(states=_STATES, effective=EFFECTIVE_SQL)


def _opt(value: uuid.UUID | None) -> str | None:
    return None if value is None else str(value)


async def _exposures(
    identity: "Identity", *, limit: int | None, after: uuid.UUID | None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    declared = identity.password_policies.declared_roles()
    await identity.password_policies.default()  # seeds the default before counting under it
    async with identity.db.connection() as conn:
        cur = await conn.execute(
            _EXPOSED_SQL, {"declared": declared, "after": after, "limit": limit}
        )
        rows = await cur.fetchall()
        cur = await conn.execute(_EXPOSED_COUNTS_SQL, {"declared": declared})
        groups = await cur.fetchall()
    users = [
        {
            "user_id": str(user_id),
            "source": source,
            "watch_list_id": _opt(list_id),
            "policy_id": _opt(policy_id),
        }
        for user_id, source, list_id, policy_id in rows
    ]
    by_list: dict[tuple[str, str | None], int] = {}
    by_policy: dict[str | None, int] = {}
    total = 0
    for source, list_id, policy_id, count in groups:
        key = (source, _opt(list_id))
        by_list[key] = by_list.get(key, 0) + int(count)
        by_policy[_opt(policy_id)] = by_policy.get(_opt(policy_id), 0) + int(count)
        total += int(count)
    summary = {
        "by_list": [
            {"source": s, "watch_list_id": i, "users": n}
            for (s, i), n in sorted(by_list.items(), key=lambda kv: (kv[0][0], kv[0][1] or ""))
        ],
        "by_policy": [
            {"policy_id": p, "users": n}
            for p, n in sorted(by_policy.items(), key=lambda kv: kv[0] or "")
        ],
        "total": total,
    }
    return users, summary


# The router


def build_password_admin_router(identity: "Identity", *, permission: str) -> APIRouter:
    """Password policy, watch list and exposure routes, behind ``permission``."""
    router = APIRouter(tags=["warden: password policies"])
    admin = require_permission(permission)
    policies = identity.password_policies
    lists = identity.watch_lists
    Admin = Annotated[Principal, Depends(admin)]

    def actor(principal: Principal) -> str:
        return str(principal.user_id)

    async def attached_to(list_id: uuid.UUID) -> list[str]:
        return [str(p.id) for p in await policies.list() if list_id in p.settings.watch_list_ids]

    async def policy_or_none(policy_id: str) -> PasswordPolicy | None:
        pid = _id(policy_id)
        if pid is None:
            return None
        try:
            return await policies.get(pid)
        except PasswordPolicyNotFound:
            return None

    def conflict(exc: PasswordPolicyError | WatchListError) -> Response:
        return _detail(str(exc), 409)

    # Policies

    @router.get(
        "/password-policies",
        summary="List password policies",
        description=(
            "Every password policy, highest priority (1) first, then the default. A policy "
            "applies to users who sign in with a password (`password_and_sso`): their pin, "
            "else the highest-priority policy mapped from a role they hold, else the default."
        ),
        responses={
            200: {"model": WardenPasswordPolicyList, "description": "The policies."},
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def list_policies(principal: Admin) -> Response:
        return json_response({"policies": [_policy(p) for p in await policies.list()]})

    @router.post(
        "/password-policies",
        status_code=201,
        summary="Create a password policy",
        description=(
            "A new policy at `priority` (1 is the highest, unique), applying to no one until "
            "a role is mapped to it or it is pinned on a user. Omitted settings take their "
            "defaults (no class rule, no tiers, no history, the built-in list checked). "
            "Inconsistent settings are refused (400) with each field at fault."
        ),
        responses={
            201: {"model": WardenPasswordPolicyEnvelope, "description": "Created."},
            400: {
                "model": WardenPasswordPolicyInvalid,
                "description": "The settings are not valid; `errors` names each field.",
                "headers": no_store(),
            },
            409: detail(
                "The name or priority is in use.", "that name or priority is already in use"
            ),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(PasswordPolicyCreateBody),
    )
    async def create_policy(request: Request, principal: Admin) -> Response:
        body = await read_object(request)
        if body is None or set(body) - _SETTINGS - {"priority"}:
            return _invalid_request()
        priority = _priority(body.get("priority"))
        settings, errors = _settings(body, None)
        if priority is None:
            errors.append(("priority", "priority must be between 1 and 10000"))
        if not errors:
            errors = _check(identity, settings)
        if errors or priority is None:
            return _refused(errors)
        try:
            policy = await policies.create(settings, priority=priority, actor=actor(principal))
        except WatchListNotFound:
            return _refused([("watch_list_ids", "a watch list to attach does not exist")])
        except PasswordPolicyConflict as exc:
            return conflict(exc)
        return json_response({"policy": _policy(policy)}, 201)

    @router.post(
        "/password-policies/affected-users",
        summary="Count the users a proposed change would put under a policy",
        description=(
            "For an existing policy (`policy_id`) or a new one (no `policy_id`): how many "
            "users who sign in with a password it applies to now (`current`) and would apply "
            "to (`proposed`) if it had `priority` and exactly the mapped `roles`. Either may "
            "be left out to keep the policy's own. Nothing is changed or audited."
        ),
        responses={
            200: {"model": WardenAffectedUsersProposal, "description": "The counts."},
            400: detail("The proposal is not valid.", "the request is not valid"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(AffectedUsersProposalBody),
    )
    async def propose(request: Request, principal: Admin) -> Response:
        body = await read_object(request)
        if body is None or set(body) - {"policy_id", "priority", "roles"}:
            return _invalid_request()
        roles = body.get("roles")
        priority = _priority(body.get("priority"))
        if body.get("priority") is not None and priority is None:
            return _invalid_request()
        if roles is not None and (
            not isinstance(roles, list)
            or not all(isinstance(r, str) for r in roles)
            or not set(roles) <= set(policies.declared_roles())
        ):
            return _invalid_request()
        if body.get("policy_id") is None:
            if priority is None:
                return _invalid_request()
            target, current = uuid.uuid4(), 0
            proposed_roles: list[str] = sorted(set(roles or []))
        else:
            policy = await policy_or_none(body["policy_id"])
            if policy is None or (policy.is_default and (priority is not None or roles)):
                return _invalid_request()
            target = policy.id
            current = await policies.affected_users(target)
            priority = policy.priority if priority is None else priority
            proposed_roles = sorted(set(policy.roles if roles is None else roles))
        proposed = await _proposed_count(identity, target, priority, proposed_roles)
        return json_response({"current": current, "proposed": proposed})

    @router.get(
        "/password-policies/{policy_id}",
        summary="Show a password policy",
        description="`policy_id` is the policy's UUID; anything else is a 404.",
        responses={
            200: {"model": WardenPasswordPolicyEnvelope, "description": "The policy."},
            404: detail("No such policy.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def show_policy(policy_id: str, principal: Admin) -> Response:
        policy = await policy_or_none(policy_id)
        if policy is None:
            return _not_found()
        return json_response({"policy": _policy(policy)})

    @router.put(
        "/password-policies/{policy_id}",
        summary="Change a password policy",
        description=(
            "Changes the settings sent and keeps the rest, if the policy is still at "
            "`version` (the version read): otherwise 409, and nothing changes. The default "
            "can be changed too. Priorities change through `PUT .../priority`; users under "
            "the policy are re-evaluated at their next password sign-in (PW11)."
        ),
        responses={
            200: {"model": WardenPasswordPolicyEnvelope, "description": "The changed policy."},
            400: {
                "model": WardenPasswordPolicyInvalid,
                "description": "The settings are not valid; `errors` names each field.",
                "headers": no_store(),
            },
            404: detail("No such policy.", "not found"),
            409: detail(
                "The policy changed since it was read, or the name is in use.",
                "the policy changed since it was read",
                "that name is already in use",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(PasswordPolicyUpdateBody),
    )
    async def update_policy(policy_id: str, request: Request, principal: Admin) -> Response:
        policy = await policy_or_none(policy_id)
        if policy is None:
            return _not_found()
        body = await read_object(request)
        if body is None or set(body) - _SETTINGS - {"version"}:
            return _invalid_request()
        version = body.get("version")
        settings, errors = _settings(body, policy.settings)
        if type(version) is not int:
            errors.append(("version", "version is required: the version read"))
        if not errors:
            errors = _check(identity, settings)
        if errors or type(version) is not int:
            return _refused(errors)
        try:
            updated = await policies.update(
                policy.id, settings, expected_version=version, actor=actor(principal)
            )
        except PasswordPolicyNotFound:
            return _not_found()
        except WatchListNotFound:
            return _refused([("watch_list_ids", "a watch list to attach does not exist")])
        except PasswordPolicyConflict as exc:
            return conflict(exc)
        return json_response({"policy": _policy(updated)})

    @router.delete(
        "/password-policies/{policy_id}",
        status_code=204,
        summary="Delete a password policy",
        description=(
            "Its role mappings go with it, and its users return to another mapped policy or "
            "the default. Never the default (409), and never a policy pinned on a user (409): "
            "unpin them first."
        ),
        responses={
            204: {"description": "Deleted.", "headers": no_store()},
            404: detail("No such policy.", "not found"),
            409: detail(
                "The default policy, or a policy pinned on users.",
                "the default policy cannot be deleted",
                "the policy is pinned on 1 user; unpin them first",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def delete_policy(policy_id: str, principal: Admin) -> Response:
        pid = _id(policy_id)
        if pid is None:
            return _not_found()
        try:
            await policies.delete(pid, actor=actor(principal))
        except PasswordPolicyNotFound:
            return _not_found()
        except PasswordPolicyConflict as exc:
            return conflict(exc)
        return _no_content()

    @router.put(
        "/password-policies/{policy_id}/priority",
        summary="Move a password policy to another priority",
        description=(
            "1 is the highest. Each priority belongs to one policy at a time, even under "
            "concurrent requests: a priority in use is a 409. The default has none."
        ),
        responses={
            200: {"model": WardenPasswordPolicyEnvelope, "description": "The moved policy."},
            400: detail("Not a priority from 1 to 10000.", "the request is not valid"),
            404: detail("No such policy.", "not found"),
            409: detail(
                "The priority is in use, or the policy is the default.",
                "that priority is already in use",
                "the default policy has no priority",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(PasswordPolicyPriorityBody),
    )
    async def set_priority(policy_id: str, request: Request, principal: Admin) -> Response:
        pid = _id(policy_id)
        if pid is None:
            return _not_found()
        body = await read_object(request) or {}
        priority = _priority(body.get("priority"))
        if priority is None:
            return _invalid_request()
        try:
            moved = await policies.set_priority(pid, priority, actor=actor(principal))
        except PasswordPolicyNotFound:
            return _not_found()
        except PasswordPolicyConflict as exc:
            return conflict(exc)
        return json_response({"policy": _policy(moved)})

    @router.put(
        "/password-policy-order",
        summary="Reorder every password policy",
        description=(
            "`policy_ids` names every policy but the default once, highest first; they get "
            "priorities 1, 2, 3 and so on in one transaction."
        ),
        responses={
            200: {"model": WardenPasswordPolicyList, "description": "The reordered policies."},
            400: detail(
                "The list does not name every non-default policy once.",
                "the request is not valid",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(PasswordPolicyOrderBody),
    )
    async def reorder(request: Request, principal: Admin) -> Response:
        body = await read_object(request) or {}
        raw = body.get("policy_ids")
        ids = [_id(i) for i in raw] if isinstance(raw, list) and len(raw) <= 10000 else [None]
        if any(i is None for i in ids):
            return _invalid_request()
        try:
            ordered = await policies.reorder(
                [i for i in ids if i is not None], actor=actor(principal)
            )
        except PasswordPolicyError:
            return _invalid_request()
        return json_response({"policies": [_policy(p) for p in ordered]})

    @router.put(
        "/password-policies/{policy_id}/builtin-list",
        summary="Include or exclude the built-in common-password list",
        description=(
            "Whether the policy checks warden's bundled list of common passwords (PW12). "
            "Changed against the version read now; a concurrent change is a 409."
        ),
        responses={
            200: {"model": WardenPasswordPolicyEnvelope, "description": "The changed policy."},
            400: detail("`include` is not true or false.", "the request is not valid"),
            404: detail("No such policy.", "not found"),
            409: detail("The policy changed meanwhile.", "the policy changed since it was read"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(BuiltinListBody),
    )
    async def set_builtin(policy_id: str, request: Request, principal: Admin) -> Response:
        policy = await policy_or_none(policy_id)
        if policy is None:
            return _not_found()
        body = await read_object(request) or {}
        include = body.get("include")
        if type(include) is not bool:
            return _invalid_request()
        settings = dataclasses.replace(policy.settings, include_builtin=include)
        try:
            updated = await policies.update(
                policy.id, settings, expected_version=policy.version, actor=actor(principal)
            )
        except PasswordPolicyNotFound:
            return _not_found()
        except PasswordPolicyConflict as exc:
            return conflict(exc)
        return json_response({"policy": _policy(updated)})

    async def attachment(
        policy_id: str, list_id: str, principal: Principal, *, attach: bool
    ) -> Response:
        pid, lid = _id(policy_id), _id(list_id)
        if pid is None or lid is None:
            return _not_found()
        change: Callable[..., Any] = policies.attach if attach else policies.detach
        try:
            changed = await change(pid, lid, actor=actor(principal))
        except (PasswordPolicyNotFound, WatchListNotFound):
            return _not_found()
        return json_response({"policy": _policy(changed)})

    @router.put(
        "/password-policies/{policy_id}/watch-lists/{list_id}",
        summary="Attach a watch list to a password policy",
        description=(
            "The policy checks the list's entries and terms as well. Attaching a list already "
            "attached changes nothing."
        ),
        responses={
            200: {"model": WardenPasswordPolicyEnvelope, "description": "The policy."},
            404: detail("No such policy or watch list.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def attach_list(policy_id: str, list_id: str, principal: Admin) -> Response:
        return await attachment(policy_id, list_id, principal, attach=True)

    @router.delete(
        "/password-policies/{policy_id}/watch-lists/{list_id}",
        summary="Detach a watch list from a password policy",
        description="Detaching a list that is not attached changes nothing.",
        responses={
            200: {"model": WardenPasswordPolicyEnvelope, "description": "The policy."},
            404: detail("No such policy.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def detach_list(policy_id: str, list_id: str, principal: Admin) -> Response:
        return await attachment(policy_id, list_id, principal, attach=False)

    @router.get(
        "/password-policies/{policy_id}/affected-users",
        summary="Count the users a password policy applies to",
        description=(
            "How many users who sign in with a password the policy applies to now, by pin, "
            "role or as the default."
        ),
        responses={
            200: {"model": WardenAffectedUsers, "description": "The count."},
            404: detail("No such policy.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def affected(policy_id: str, principal: Admin) -> Response:
        policy = await policy_or_none(policy_id)
        if policy is None:
            return _not_found()
        return json_response({"affected_users": await policies.affected_users(policy.id)})

    # Role mappings

    @router.put(
        "/password-policy-roles/{role}",
        status_code=204,
        summary="Map a role to a password policy",
        description=(
            "Users holding `role` come under the policy, unless a higher-priority mapped role "
            "or a pin applies. Only a role the product declares can be mapped, and never to "
            "the default, which covers every unmapped role. Mapping replaces the role's "
            "earlier mapping."
        ),
        responses={
            204: {"description": "Mapped.", "headers": no_store()},
            400: detail(
                "Not a declared role, or not a policy.",
                "the product declares no such role",
                "the request is not valid",
            ),
            409: detail(
                "The policy is the default.",
                "the default applies to unmapped roles; map a role to another policy",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(PasswordPolicyRoleBody),
    )
    async def map_role(role: str, request: Request, principal: Admin) -> Response:
        body = await read_object(request) or {}
        pid = _id(body.get("policy_id"))
        if pid is None:
            return _invalid_request()
        try:
            await policies.map_role(role, pid, actor=actor(principal))
        except PasswordPolicyNotFound:
            return _invalid_request()
        except PasswordPolicyConflict as exc:
            return conflict(exc)
        except PasswordPolicyError as exc:
            return _detail(str(exc), 400)
        return _no_content()

    @router.delete(
        "/password-policy-roles/{role}",
        status_code=204,
        summary="Remove a role's password policy mapping",
        description="Its users return to another mapped policy or the default.",
        responses={
            204: {"description": "Unmapped.", "headers": no_store()},
            400: detail("Not a declared role.", "the product declares no such role"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def unmap_role(role: str, principal: Admin) -> Response:
        try:
            await policies.map_role(role, None, actor=actor(principal))
        except PasswordPolicyError as exc:
            return _detail(str(exc), 400)
        return _no_content()

    # Users

    async def user_or_none(user_id: str) -> User | None:
        uid = _id(user_id)
        return None if uid is None else await identity.users.get(uid)

    @router.get(
        "/users/{user_id}/password-policy",
        summary="Show a user's password policy and password state",
        description=(
            "The policy that applies and why (`pin`, `role` with the role, or `default`), the "
            "tier the password met, when it was set and expires, and whether a change is "
            "required and why. For a user who does not sign in with a password, `applies` "
            "is false and the policy fields are null."
        ),
        responses={
            200: {"model": WardenUserPasswordStatus, "description": "The status."},
            404: detail("No such user.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def show_status(user_id: str, principal: Admin) -> Response:
        user = await user_or_none(user_id)
        if user is None:
            return _not_found()
        return json_response(await password_status(identity, user))

    @router.put(
        "/users/{user_id}/password-policy",
        summary="Pin a password policy on a user",
        description="The pin overrides the user's role mappings until it is removed.",
        responses={
            200: {"model": WardenUserPasswordStatus, "description": "The user's new status."},
            400: detail("Not a policy.", "the request is not valid"),
            404: detail("No such user.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(PasswordPolicyPinBody),
    )
    async def pin(user_id: str, request: Request, principal: Admin) -> Response:
        user = await user_or_none(user_id)
        if user is None:
            return _not_found()
        body = await read_object(request) or {}
        pid = _id(body.get("policy_id"))
        if pid is None:
            return _invalid_request()
        try:
            await policies.pin(user.id, pid, actor=actor(principal))
        except PasswordPolicyNotFound:
            return _invalid_request()
        except PasswordPolicyError:
            return _not_found()
        return json_response(await password_status(identity, user))

    @router.delete(
        "/users/{user_id}/password-policy",
        status_code=204,
        summary="Remove a user's pinned password policy",
        description="The user returns to their role mappings or the default.",
        responses={
            204: {"description": "Unpinned.", "headers": no_store()},
            404: detail("No such user, or no pin.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def unpin(user_id: str, principal: Admin) -> Response:
        uid = _id(user_id)
        if uid is None or not await policies.unpin(uid, actor=actor(principal)):
            return _not_found()
        return _no_content()

    @router.put(
        "/users/{user_id}/password-change-required",
        summary="Require a user to change their password at next sign-in",
        description=(
            "At their next password sign-in, after the second factor, the user is answered "
            "`password_change_required` with the reason `administrator` and must set a new "
            "password before a session is issued. If a change is already required, the "
            "earlier reason stands and is answered. Refused (409) for a user who does not "
            "sign in with a password."
        ),
        responses={
            200: {"model": WardenChangeRequired, "description": "Required."},
            404: detail("No such user.", "not found"),
            409: detail("The user does not sign in with a password.", _SIGNS_IN_OTHERWISE),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def require_change(user_id: str, principal: Admin) -> Response:
        user = await user_or_none(user_id)
        if user is None:
            return _not_found()
        if user.sign_in_method is not SignInMethod.PASSWORD_AND_SSO or not user.has_password:
            return _detail(_SIGNS_IN_OTHERWISE, 409)
        async with identity.db.transaction() as tx:
            flagged = await identity.password_states.require_change(
                user.id, ChangeReason.ADMINISTRATOR, conn=tx
            )
            await record_audit(
                AuditEvent(
                    action="warden.identity.password.change_required",
                    outcome="success",
                    actor=actor(principal),
                    resource_type="user",
                    resource_id=str(user.id),
                    details={
                        "reason": ChangeReason.ADMINISTRATOR.value,
                        "trigger": "administrator",
                        "already_required": not flagged,
                    },
                ),
                conn=tx,
            )
        state = await identity.password_states.get(user.id)
        reason = None if state is None or state.change_reason is None else state.change_reason
        return json_response(
            {"change_required": reason is not None, "change_reason": reason and reason.value}
        )

    @router.delete(
        "/users/{user_id}/password-change-required",
        status_code=204,
        summary="Clear a user's required password change",
        description=(
            "Whatever its reason (`expired`, `watch_list`, `administrator` or `policy`), the "
            "user is no longer required to change their password at next sign-in. Audited as "
            "`warden.identity.password.change_cleared` with the reason cleared. A user with "
            "no required change is a 404. A reason that still holds (an expired password, or "
            "a password that fails an enforced policy) is found again at their next sign-in."
        ),
        responses={
            204: {"description": "Cleared.", "headers": no_store()},
            404: detail("No such user, or no change required.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def clear_change(user_id: str, principal: Admin) -> Response:
        uid = _id(user_id)
        if uid is None:
            return _not_found()
        async with identity.db.transaction() as tx:
            # The row lock makes reading the reason and clearing it one step.
            cur = await tx.execute(
                sql.SQL(
                    "SELECT change_reason FROM {}"
                    " WHERE user_id = %s AND change_reason IS NOT NULL FOR UPDATE"
                ).format(_STATES),
                (uid,),
            )
            row = await cur.fetchone()
            if row is None:
                return _not_found()
            await identity.password_states.clear_change(uid, conn=tx)
            await record_audit(
                AuditEvent(
                    action="warden.identity.password.change_cleared",
                    outcome="success",
                    actor=actor(principal),
                    resource_type="user",
                    resource_id=str(uid),
                    details={"reason": row[0]},
                ),
                conn=tx,
            )
        return _no_content()

    # Watch lists

    async def list_or_none(list_id: str) -> WatchList | None:
        lid = _id(list_id)
        if lid is None:
            return None
        try:
            return await lists.get(lid)
        except WatchListNotFound:
            return None

    async def list_view(listed: WatchList) -> dict[str, Any]:
        return {"watch_list": _watch_list(listed, await attached_to(listed.id))}

    @router.get(
        "/watch-lists",
        summary="List watch lists",
        description=(
            "Each list's name, the reason a user is shown, its kind, how many entries and "
            "terms it holds, its last import and threshold, and the policies that check it. "
            "Never its entries, terms or hashes."
        ),
        responses={
            200: {"model": WardenWatchListList, "description": "The lists."},
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def list_lists(principal: Admin) -> Response:
        everything = await policies.list()
        found = [
            _watch_list(w, [str(p.id) for p in everything if w.id in p.settings.watch_list_ids])
            for w in await lists.list()
        ]
        return json_response({"watch_lists": found})

    @router.post(
        "/watch-lists",
        status_code=201,
        summary="Create a watch list",
        description=(
            "`kind` is `manual` (exact passwords and terms an administrator adds) or "
            "`imported` (filled by `warden passwords import` from a file in Have I Been "
            "Pwned's downloader format). `reason` is what a user is shown when their "
            "password is on it."
        ),
        responses={
            201: {"model": WardenWatchListEnvelope, "description": "Created."},
            400: detail("The request is not valid.", "the request is not valid"),
            409: detail("The name is in use.", "a watch list with that name already exists"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(WatchListCreateBody),
    )
    async def create_list(request: Request, principal: Admin) -> Response:
        body = await read_object(request) or {}
        name, reason = body.get("name"), body.get("reason")
        try:
            kind = WatchListKind(str(body.get("kind")))
        except ValueError:
            return _invalid_request()
        if not isinstance(name, str) or not isinstance(reason, str):
            return _invalid_request()
        try:
            created = await lists.create(name, reason, kind, actor=actor(principal))
        except WatchListError as exc:
            if "already exists" in str(exc):
                return conflict(exc)
            return _invalid_request()
        return json_response(await list_view(created), 201)

    @router.get(
        "/watch-lists/{list_id}",
        summary="Show a watch list",
        description="Counts, the last import and the threshold; never the entries or terms.",
        responses={
            200: {"model": WardenWatchListEnvelope, "description": "The list."},
            404: detail("No such list.", "not found"),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def show_list(list_id: str, principal: Admin) -> Response:
        listed = await list_or_none(list_id)
        if listed is None:
            return _not_found()
        return json_response(await list_view(listed))

    @router.put(
        "/watch-lists/{list_id}",
        summary="Rename a watch list or change its reason",
        description="Send `name`, `reason` or both; what is left out is kept.",
        responses={
            200: {"model": WardenWatchListEnvelope, "description": "The changed list."},
            400: detail("The request is not valid.", "the request is not valid"),
            404: detail("No such list.", "not found"),
            409: detail("The name is in use.", "a watch list with that name already exists"),
            **REFUSED,
            **FORBIDDEN,
        },
        openapi_extra=json_body(WatchListUpdateBody),
    )
    async def update_list(list_id: str, request: Request, principal: Admin) -> Response:
        lid = _id(list_id)
        if lid is None:
            return _not_found()
        body = await read_object(request) or {}
        name, reason = body.get("name"), body.get("reason")
        if (name is None and reason is None) or set(body) - {"name", "reason"}:
            return _invalid_request()
        if not (name is None or isinstance(name, str)) or not (
            reason is None or isinstance(reason, str)
        ):
            return _invalid_request()
        try:
            changed = await lists.update(lid, name=name, reason=reason, actor=actor(principal))
        except WatchListNotFound:
            return _not_found()
        except WatchListError as exc:
            if "already exists" in str(exc):
                return conflict(exc)
            return _invalid_request()
        return json_response(await list_view(changed))

    @router.delete(
        "/watch-lists/{list_id}",
        status_code=204,
        summary="Delete a watch list",
        description="Refused (409) while any policy checks it: detach it first.",
        responses={
            204: {"description": "Deleted.", "headers": no_store()},
            404: detail("No such list.", "not found"),
            409: detail(
                "The list is attached to a policy.",
                "the watch list is attached to 1 password policy; detach it first",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def delete_list(list_id: str, principal: Admin) -> Response:
        lid = _id(list_id)
        if lid is None:
            return _not_found()
        try:
            await lists.delete(lid, actor=actor(principal))
        except WatchListNotFound:
            return _not_found()
        except WatchListConflict as exc:
            return conflict(exc)
        return _no_content()

    async def change(
        list_id: str,
        request: Request,
        principal: Principal,
        *,
        field: str,
        longest: int,
        added: bool,
    ) -> Response:
        lid = _id(list_id)
        if lid is None:
            return _not_found()
        body = await read_object(request) or {}
        values = _texts(body.get(field), longest=longest)
        if values is None:
            return _invalid_request()
        method = {
            ("passwords", True): lists.add_entries,
            ("passwords", False): lists.remove_entries,
            ("terms", True): lists.add_terms,
            ("terms", False): lists.remove_terms,
        }[(field, added)]
        try:
            count = await method(lid, values, actor=actor(principal))
        except WatchListNotFound:
            return _not_found()
        except WatchListError as exc:
            if "only a manual" in str(exc):
                return conflict(exc)
            return _invalid_request()
        return json_response({"added" if added else "removed": count})

    _ENTRY_RESPONSES: dict[int | str, dict[str, Any]] = {
        400: detail("The request is not valid.", "the request is not valid"),
        404: detail("No such list.", "not found"),
        409: detail(
            "The list is imported, not manual.", "only a manual watch list takes entries and terms"
        ),
        **REFUSED,
        **FORBIDDEN,
    }
    _ENTRIES = (
        f"`passwords` is a list of 1 to {MAX_ENTRIES} exact passwords, each 1 to "
        f"{MAX_ENTRY_LENGTH} characters, sent over TLS. Each is hashed to SHA-1 of its NFC "
        "form at once; the plaintext is never stored, logged, echoed or audited, and no "
        "route returns an entry or its hash."
    )

    @router.post(
        "/watch-lists/{list_id}/entries",
        summary="Add exact passwords to a manual watch list",
        description=f"{_ENTRIES} Answers how many were new.",
        responses={
            200: {"model": WardenWatchListCount, "description": "How many were added."},
            **_ENTRY_RESPONSES,
        },
        openapi_extra=json_body(WatchListEntriesBody),
    )
    async def add_entries(list_id: str, request: Request, principal: Admin) -> Response:
        return await change(
            list_id, request, principal, field="passwords", longest=MAX_ENTRY_LENGTH, added=True
        )

    @router.post(
        "/watch-lists/{list_id}/entries/removal",
        summary="Remove exact passwords from a manual watch list",
        description=f"{_ENTRIES} Answers how many were removed.",
        responses={
            200: {"model": WardenWatchListCount, "description": "How many were removed."},
            **_ENTRY_RESPONSES,
        },
        openapi_extra=json_body(WatchListEntriesBody),
    )
    async def remove_entries(list_id: str, request: Request, principal: Admin) -> Response:
        return await change(
            list_id, request, principal, field="passwords", longest=MAX_ENTRY_LENGTH, added=False
        )

    _TERMS = (
        f"`terms` is a list of 1 to {MAX_ENTRIES} terms, each 3 to 64 characters after NFC "
        "and case folding, matched anywhere in a password without regard to case at sign-in "
        "and when a password is set. No route returns a term."
    )

    @router.post(
        "/watch-lists/{list_id}/terms",
        summary="Add contained terms to a manual watch list",
        description=f"{_TERMS} Answers how many were new.",
        responses={
            200: {"model": WardenWatchListCount, "description": "How many were added."},
            **_ENTRY_RESPONSES,
        },
        openapi_extra=json_body(WatchListTermsBody),
    )
    async def add_terms(list_id: str, request: Request, principal: Admin) -> Response:
        return await change(list_id, request, principal, field="terms", longest=256, added=True)

    @router.post(
        "/watch-lists/{list_id}/terms/removal",
        summary="Remove contained terms from a manual watch list",
        description=f"{_TERMS} Answers how many were removed.",
        responses={
            200: {"model": WardenWatchListCount, "description": "How many were removed."},
            **_ENTRY_RESPONSES,
        },
        openapi_extra=json_body(WatchListTermsBody),
    )
    async def remove_terms(list_id: str, request: Request, principal: Admin) -> Response:
        return await change(list_id, request, principal, field="terms", longest=256, added=False)

    # The exposure report

    @router.get(
        "/password-exposures",
        summary="Users whose password was found on a watch list",
        description=(
            "Every user required to change their password because it was found on a watch "
            "list, by the latest recheck (`warden passwords recheck`) or at a sign-in, until "
            "they change it: their id, where it was found (`builtin`, `list`, `term` or "
            "`hibp`), the list's id, and the policy that applies to them; with counts by list "
            "and by policy over every such user. Identifiers and counts only. Users in id "
            "order; without `limit` or `after` the body holds every user, and with either it "
            "also carries `next`, as `GET /users` does."
        ),
        responses={
            200: {"model": WardenPasswordExposures, "description": "The report."},
            400: detail(
                "`limit` is not 1 to 1000, or `after` is not a cursor this route returned.",
                "the request is not valid",
            ),
            **REFUSED,
            **FORBIDDEN,
        },
    )
    async def exposures(
        principal: Admin,
        limit: Annotated[
            str | None, Query(description="Page size, a whole number from 1 to 1000.")
        ] = None,
        after: Annotated[
            str | None, Query(description="The `next` cursor from the previous page.")
        ] = None,
    ) -> Response:
        size: int | None = None
        if limit is not None:
            if _PAGE_SIZE.fullmatch(limit) is None or int(limit) > _MAX_PAGE:
                return _invalid_request()
            size = int(limit)
        cursor = None if after is None else _id(after)
        if after is not None and cursor is None:
            return _invalid_request()
        users, summary = await _exposures(
            identity, limit=None if size is None else size + 1, after=cursor
        )
        if limit is None and after is None:
            return json_response({"users": users, **summary})
        more = size is not None and len(users) > size
        page = users[:size] if more else users
        following = page[-1]["user_id"] if more else None
        return json_response({"users": page, **summary, "next": following})

    return router
