"""Watch lists (ruling PW7) and the built-in list (PW12).

A watch list is a named list with a reason a user is shown. A ``manual``
list holds exact passwords an administrator adds (stored as SHA-1 digests of
their NFC form) and a few contained terms (stored after NFC and case
folding); an ``imported`` list holds digests imported from a file in Have I
Been Pwned's downloader format (``HASH:count``), replaced in place by each
import.

``match(password, policy)`` checks, in order, the built-in list, the
policy's attached lists' entries, their terms, and, when the policy enables
it, the Pwned Passwords range API. It returns the first match with its
reason. It never stores, logs or audits the password or its digest.

An import streams its digests into a staging table with ``COPY`` and swaps
them into the list in the same transaction, under the list's lock: a match
running meanwhile sees the old list or the new one, never a mix, and a
failed import leaves the list as it was.
"""

from __future__ import annotations

import builtins
import hashlib
import re
import unicodedata
import uuid
from collections.abc import AsyncIterable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import psycopg
from psycopg import AsyncConnection, sql

from warden.audit import AuditEvent, record_audit
from warden.db import (
    PASSWORD_POLICY_WATCH_LISTS,
    WATCH_LIST_ENTRIES,
    WATCH_LIST_LOCK_KEY,
    WATCH_LIST_STAGING,
    WATCH_LIST_TERMS,
    WATCH_LISTS,
    Database,
    table,
)
from warden.identity.password_policy.builtin import BUILTIN_REASON, BuiltinList
from warden.identity.password_policy.errors import (
    HibpUnavailable,
    WatchListConflict,
    WatchListError,
    WatchListImportError,
    WatchListNotFound,
)
from warden.identity.password_policy.fingerprint import password_digest
from warden.identity.password_policy.hibp import HibpRangeClient, RangeCache
from warden.identity.password_policy.rules import normalise

if TYPE_CHECKING:
    from warden.identity.password_policy.store import (
        PasswordPolicies,
        PasswordPolicy,
        PolicySettings,
    )

__all__ = [
    "HIBP_REASON",
    "ImportResult",
    "WatchList",
    "WatchListCheck",
    "WatchListKind",
    "WatchListMatch",
    "WatchListSource",
    "WatchLists",
]

HIBP_REASON = "This password has appeared in a data breach"
MIN_TERM = 3
MAX_TERM = 64

_LISTS = table(WATCH_LISTS)
_ENTRIES = table(WATCH_LIST_ENTRIES)
_TERMS = table(WATCH_LIST_TERMS)
_STAGING = table(WATCH_LIST_STAGING)
_ATTACHED = table(PASSWORD_POLICY_WATCH_LISTS)
_HIBP_LINE = re.compile(r"([0-9A-Fa-f]{40})(?::([0-9]{1,12}))?")
_COPY_BATCH = 5_000


class WatchListSource(StrEnum):
    """Where a match came from."""

    BUILTIN = "builtin"
    LIST = "list"
    TERM = "term"
    HIBP = "hibp"


class WatchListKind(StrEnum):
    MANUAL = "manual"
    """Exact passwords and terms an administrator adds."""
    IMPORTED = "imported"
    """Digests imported in HIBP's downloader format, replaced by each import."""


@dataclass(frozen=True, slots=True)
class WatchListMatch:
    """A password found on a watch list: where, which list (by id) and the user-facing reason."""

    source: WatchListSource
    list_id: uuid.UUID | None
    reason: str


@dataclass(frozen=True, slots=True)
class WatchListCheck:
    """The outcome of ``match``: the first match, and whether the range API could not answer."""

    match: WatchListMatch | None
    hibp_unavailable: bool = False

    def blocked(self, policy: PolicySettings) -> bool:
        """Whether the password is refused: a match, or an unreachable API the policy refuses on."""
        if self.match is not None:
            return True
        return self.hibp_unavailable and policy.hibp_on_unavailable == "refuse"


@dataclass(frozen=True, slots=True)
class WatchList:
    id: uuid.UUID
    name: str
    reason: str
    kind: WatchListKind
    entry_count: int
    terms: tuple[str, ...]
    import_threshold: int | None
    last_imported_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ImportResult:
    """Counts only: how many digests the list now holds, and what was skipped."""

    imported: int
    below_threshold: int
    lines: int


def term_form(term: str) -> str:
    """How a term is stored and compared: NFC, then case folded."""
    return normalise(term).casefold()


def _entry_digest(password: str) -> bytes:
    return hashlib.sha1(normalise(password).encode("utf-8", "surrogatepass")).digest()  # noqa: S324


def _candidates(password: str) -> list[bytes]:
    """The digests a password may be listed under: as typed and in NFC."""
    raw = password_digest(password)
    nfc = _entry_digest(password)
    return [raw] if raw == nfc else [raw, nfc]


def _check_label(value: object, field: str, longest: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > longest:
        raise WatchListError(f"{field} must be 1 to {longest} characters")
    if any(unicodedata.category(c)[0] == "C" for c in value):
        raise WatchListError(f"{field} must not contain control characters")
    return value


def _settings_of(policy: PasswordPolicy | PolicySettings) -> PolicySettings:
    from warden.identity.password_policy.store import PasswordPolicy

    return policy.settings if isinstance(policy, PasswordPolicy) else policy


class WatchLists:
    """Watch lists, their entries and terms, imports, and matching."""

    def __init__(
        self,
        db: Database,
        policies: PasswordPolicies,
        *,
        builtin: BuiltinList,
        hibp: HibpRangeClient,
    ) -> None:
        self._db = db
        self._policies = policies
        self.builtin = builtin
        self.hibp = hibp

    # Reading

    async def get(self, list_id: uuid.UUID) -> WatchList:
        async with self._db.connection() as conn:
            found = await self._fetch(conn, list_id)
        if found is None:
            raise WatchListNotFound(f"no watch list {list_id}")
        return found

    async def list(self) -> builtins.list[WatchList]:
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL("SELECT id FROM {} ORDER BY lower(name)").format(_LISTS)
            )
            ids = [r[0] for r in await cur.fetchall()]
            found = [await self._fetch(conn, i) for i in ids]
        return [w for w in found if w is not None]

    async def _fetch(self, conn: AsyncConnection[Any], list_id: uuid.UUID) -> WatchList | None:
        cur = await conn.execute(
            sql.SQL(
                "SELECT id, name, reason, kind, entry_count, import_threshold, last_imported_at,"
                " created_at, updated_at FROM {} WHERE id = %s"
            ).format(_LISTS),
            (list_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        cur = await conn.execute(
            sql.SQL("SELECT term FROM {} WHERE list_id = %s ORDER BY term").format(_TERMS),
            (list_id,),
        )
        terms = tuple(r[0] for r in await cur.fetchall())
        return WatchList(
            id=row[0],
            name=row[1],
            reason=row[2],
            kind=WatchListKind(row[3]),
            entry_count=row[4],
            terms=terms,
            import_threshold=row[5],
            last_imported_at=row[6],
            created_at=row[7],
            updated_at=row[8],
        )

    # Changing

    async def _lock(self, tx: AsyncConnection[Any], list_id: uuid.UUID) -> WatchList:
        await tx.execute("SELECT pg_advisory_xact_lock(%s)", (WATCH_LIST_LOCK_KEY,))
        cur = await tx.execute(
            sql.SQL("SELECT 1 FROM {} WHERE id = %s FOR UPDATE").format(_LISTS), (list_id,)
        )
        if await cur.fetchone() is None:
            raise WatchListNotFound(f"no watch list {list_id}")
        found = await self._fetch(tx, list_id)
        if found is None:
            raise WatchListNotFound(f"no watch list {list_id}")
        return found

    async def _audit(
        self,
        tx: AsyncConnection[Any] | None,
        action: str,
        list_id: uuid.UUID,
        *,
        actor: str | None,
        details: dict[str, Any],
        outcome: str = "success",
    ) -> None:
        await record_audit(
            AuditEvent(
                action=f"warden.identity.watch_list.{action}",
                outcome=outcome,  # type: ignore[arg-type]
                actor=actor,
                resource_type="watch_list",
                resource_id=str(list_id),
                details=details,
            ),
            conn=tx,
        )

    async def create(
        self, name: str, reason: str, kind: WatchListKind, *, actor: str | None
    ) -> WatchList:
        _check_label(name, "name", 64)
        _check_label(reason, "reason", 200)
        kind = WatchListKind(kind)
        try:
            async with self._db.transaction() as tx:
                await tx.execute("SELECT pg_advisory_xact_lock(%s)", (WATCH_LIST_LOCK_KEY,))
                cur = await tx.execute(
                    sql.SQL(
                        "INSERT INTO {} (name, reason, kind) VALUES (%s, %s, %s) RETURNING id"
                    ).format(_LISTS),
                    (name, reason, kind.value),
                )
                row = await cur.fetchone()
                if row is None:
                    raise WatchListError("the watch list was not recorded")
                created = await self._fetch(tx, row[0])
                await self._audit(tx, "created", row[0], actor=actor, details={"kind": kind.value})
        except psycopg.errors.UniqueViolation:
            raise WatchListError("a watch list with that name already exists") from None
        if created is None:
            raise WatchListError("the watch list was not recorded")
        return created

    async def update(
        self,
        list_id: uuid.UUID,
        *,
        name: str | None = None,
        reason: str | None = None,
        actor: str | None,
    ) -> WatchList:
        """Rename a list or change the reason users are shown."""
        if name is not None:
            _check_label(name, "name", 64)
        if reason is not None:
            _check_label(reason, "reason", 200)
        try:
            async with self._db.transaction() as tx:
                before = await self._lock(tx, list_id)
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET name = %s, reason = %s, updated_at = now() WHERE id = %s"
                    ).format(_LISTS),
                    (name or before.name, reason or before.reason, list_id),
                )
                fields = [f for f, v in (("name", name), ("reason", reason)) if v is not None]
                await self._audit(tx, "updated", list_id, actor=actor, details={"fields": fields})
                after = await self._fetch(tx, list_id)
        except psycopg.errors.UniqueViolation:
            raise WatchListError("a watch list with that name already exists") from None
        if after is None:
            raise WatchListNotFound(f"no watch list {list_id}")
        return after

    async def delete(self, list_id: uuid.UUID, *, actor: str | None) -> None:
        """Remove a list. Refused while any policy checks it: detach it first."""
        from warden.identity.password_policy.store import lock_policies, notify_policies

        try:
            async with self._db.transaction() as tx:
                await lock_policies(tx)
                await self._lock(tx, list_id)
                cur = await tx.execute(
                    sql.SQL("SELECT count(*) FROM {} WHERE list_id = %s").format(_ATTACHED),
                    (list_id,),
                )
                row = await cur.fetchone()
                attached = 0 if row is None else int(row[0])
                if attached:
                    policies = "policy" if attached == 1 else "policies"
                    raise WatchListConflict(
                        f"the watch list is attached to {attached} password {policies};"
                        " detach it first"
                    )
                await tx.execute(sql.SQL("DELETE FROM {} WHERE id = %s").format(_LISTS), (list_id,))
                await self._audit(
                    tx,
                    "deleted",
                    list_id,
                    actor=actor,
                    details={"policies_detached": attached},
                )
                await notify_policies(tx)
        finally:
            self._policies.invalidate()

    async def _change_entries(
        self,
        list_id: uuid.UUID,
        statement: sql.Composed,
        values: Sequence[Any],
        *,
        added: bool,
        what: str,
        actor: str | None,
    ) -> int:
        async with self._db.transaction() as tx:
            listed = await self._lock(tx, list_id)
            if listed.kind is not WatchListKind.MANUAL:
                raise WatchListError("only a manual watch list takes entries and terms")
            changed = 0
            for value in values:
                cur = await tx.execute(statement, (list_id, value))
                changed += cur.rowcount
            await tx.execute(
                sql.SQL(
                    "UPDATE {} SET entry_count = (SELECT count(*) FROM {} WHERE list_id = %s),"
                    " updated_at = now() WHERE id = %s"
                ).format(_LISTS, _ENTRIES),
                (list_id, list_id),
            )
            details = {
                f"{what}_added": changed if added else 0,
                f"{what}_removed": 0 if added else changed,
            }
            await self._audit(tx, "entries_changed", list_id, actor=actor, details=details)
        return changed

    async def add_entries(
        self, list_id: uuid.UUID, passwords: Iterable[str], *, actor: str | None
    ) -> int:
        """Add exact passwords (kept as SHA-1 digests); returns how many were new."""
        digests = list(dict.fromkeys(_entry_digest(p) for p in passwords))
        return await self._change_entries(
            list_id,
            sql.SQL("INSERT INTO {} (list_id, hash) VALUES (%s, %s) ON CONFLICT DO NOTHING").format(
                _ENTRIES
            ),
            digests,
            added=True,
            what="entries",
            actor=actor,
        )

    async def remove_entries(
        self, list_id: uuid.UUID, passwords: Iterable[str], *, actor: str | None
    ) -> int:
        digests = list(dict.fromkeys(_entry_digest(p) for p in passwords))
        return await self._change_entries(
            list_id,
            sql.SQL("DELETE FROM {} WHERE list_id = %s AND hash = %s").format(_ENTRIES),
            digests,
            added=False,
            what="entries",
            actor=actor,
        )

    def _terms(self, terms: Iterable[str]) -> builtins.list[str]:
        forms: builtins.list[str] = []
        for term in terms:
            if not isinstance(term, str):
                raise WatchListError("each term must be text")
            form = term_form(term)
            if not MIN_TERM <= len(form) <= MAX_TERM:
                raise WatchListError(f"each term must be {MIN_TERM} to {MAX_TERM} characters")
            if any(unicodedata.category(c)[0] == "C" for c in form):
                raise WatchListError("a term must not contain control characters")
            forms.append(form)
        return builtins.list(dict.fromkeys(forms))

    async def add_terms(
        self, list_id: uuid.UUID, terms: Iterable[str], *, actor: str | None
    ) -> int:
        """Add contained terms, matched without regard to case; returns how many were new."""
        return await self._change_entries(
            list_id,
            sql.SQL("INSERT INTO {} (list_id, term) VALUES (%s, %s) ON CONFLICT DO NOTHING").format(
                _TERMS
            ),
            self._terms(terms),
            added=True,
            what="terms",
            actor=actor,
        )

    async def remove_terms(
        self, list_id: uuid.UUID, terms: Iterable[str], *, actor: str | None
    ) -> int:
        return await self._change_entries(
            list_id,
            sql.SQL("DELETE FROM {} WHERE list_id = %s AND term = %s").format(_TERMS),
            self._terms(terms),
            added=False,
            what="terms",
            actor=actor,
        )

    # Importing

    async def import_hibp(
        self,
        list_id: uuid.UUID,
        lines: Iterable[str | bytes] | AsyncIterable[str | bytes],
        *,
        threshold: int | None = None,
        actor: str | None,
    ) -> ImportResult:
        """Replace an imported list's digests from HIBP downloader lines (``HASH:count``).

        With ``threshold``, only hashes seen at least that many times are kept,
        and every line must carry a count. Streams with ``COPY`` into staging
        and swaps in one transaction; on any failure the list is unchanged.
        """
        if threshold is not None and (type(threshold) is not int or threshold < 1):
            raise WatchListImportError("the threshold must be a whole number of at least 1")
        import_id = uuid.uuid4()
        try:
            async with self._db.transaction() as tx:
                listed = await self._fetch(tx, list_id)
                if listed is None:
                    raise WatchListNotFound(f"no watch list {list_id}")
                if listed.kind is not WatchListKind.IMPORTED:
                    raise WatchListError("only an imported watch list takes imports")
                counted, below = await self._stage(tx, import_id, lines, threshold)
                await self._lock(tx, list_id)
                await tx.execute(
                    sql.SQL("DELETE FROM {} WHERE list_id = %s").format(_ENTRIES), (list_id,)
                )
                cur = await tx.execute(
                    sql.SQL(
                        "INSERT INTO {} (list_id, hash) SELECT DISTINCT %s::uuid, hash FROM {}"
                        " WHERE import_id = %s"
                    ).format(_ENTRIES, _STAGING),
                    (list_id, import_id),
                )
                imported = cur.rowcount
                await tx.execute(
                    sql.SQL("DELETE FROM {} WHERE import_id = %s").format(_STAGING), (import_id,)
                )
                await tx.execute(
                    sql.SQL(
                        "UPDATE {} SET entry_count = %s, import_threshold = %s,"
                        " last_imported_at = now(), updated_at = now() WHERE id = %s"
                    ).format(_LISTS),
                    (imported, threshold, list_id),
                )
                await self._audit(
                    tx,
                    "imported",
                    list_id,
                    actor=actor,
                    details={
                        "imported": imported,
                        "below_threshold": below,
                        "lines": counted,
                        "threshold": threshold,
                    },
                )
        except WatchListImportError as exc:
            await self._audit(
                None,
                "imported",
                list_id,
                actor=actor,
                details={} if exc.line is None else {"line": exc.line},
                outcome="failure",
            )
            raise
        return ImportResult(imported=imported, below_threshold=below, lines=counted)

    async def _stage(
        self,
        tx: AsyncConnection[Any],
        import_id: uuid.UUID,
        lines: Iterable[str | bytes] | AsyncIterable[str | bytes],
        threshold: int | None,
    ) -> tuple[int, int]:
        counted = below = 0
        number = 0
        batch: list[bytes] = []
        cur = tx.cursor()
        async with cur.copy(
            sql.SQL("COPY {} (import_id, hash) FROM STDIN").format(_STAGING)
        ) as copy:
            async for raw in _iterate(lines):
                number += 1
                digest, count = _parse_line(raw, number, threshold)
                if digest is None:
                    continue
                counted += 1
                if threshold is not None and (count is None or count < threshold):
                    below += 1
                    continue
                batch.append(digest)
                if len(batch) >= _COPY_BATCH:
                    for item in batch:
                        await copy.write_row((import_id, item))
                    batch.clear()
            for item in batch:
                await copy.write_row((import_id, item))
        return counted, below

    # Matching

    async def match(
        self,
        password: str,
        policy: PasswordPolicy | PolicySettings,
        *,
        cache: RangeCache | None = None,
    ) -> WatchListCheck:
        """The first watch list ``password`` is on under ``policy``; whether the API answered."""
        settings = _settings_of(policy)
        digests = _candidates(password)
        found = self._builtin(digests, settings)
        if found is None and settings.watch_list_ids:
            found = await self._local(digests, normalise(password).casefold(), settings)
        if found is not None:
            return WatchListCheck(found)
        return await self._range(digests[0], settings, cache)

    async def match_digest(
        self,
        digest: bytes,
        policy: PasswordPolicy | PolicySettings,
        *,
        cache: RangeCache | None = None,
    ) -> WatchListCheck:
        """As ``match``, for a fingerprint's digest: every check but terms, which need the text."""
        settings = _settings_of(policy)
        found = self._builtin([digest], settings)
        if found is None and settings.watch_list_ids:
            found = await self._local([digest], None, settings)
        if found is not None:
            return WatchListCheck(found)
        return await self._range(digest, settings, cache)

    def _builtin(self, digests: Sequence[bytes], settings: PolicySettings) -> WatchListMatch | None:
        if settings.include_builtin and any(self.builtin.contains(d) for d in digests):
            return WatchListMatch(WatchListSource.BUILTIN, None, BUILTIN_REASON)
        return None

    async def _local(
        self, digests: Sequence[bytes], text: str | None, settings: PolicySettings
    ) -> WatchListMatch | None:
        lists = builtins.list(settings.watch_list_ids)
        async with self._db.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "SELECT l.id, l.reason FROM {} l WHERE l.id = ANY(%s) AND EXISTS"
                    " (SELECT 1 FROM {} e WHERE e.list_id = l.id AND e.hash = ANY(%s))"
                    " ORDER BY lower(l.name), l.id LIMIT 1"
                ).format(_LISTS, _ENTRIES),
                (lists, builtins.list(digests)),
            )
            row = await cur.fetchone()
            if row is not None:
                return WatchListMatch(WatchListSource.LIST, row[0], row[1])
            if text is None:
                return None
            cur = await conn.execute(
                sql.SQL(
                    "SELECT l.id, l.reason, t.term FROM {} t JOIN {} l ON l.id = t.list_id"
                    " WHERE t.list_id = ANY(%s) ORDER BY lower(l.name), l.id, t.term"
                ).format(_TERMS, _LISTS),
                (lists,),
            )
            for list_id, reason, term in await cur.fetchall():
                if term in text:
                    return WatchListMatch(WatchListSource.TERM, list_id, reason)
        return None

    async def _range(
        self, digest: bytes, settings: PolicySettings, cache: RangeCache | None
    ) -> WatchListCheck:
        if not settings.hibp_enabled:
            return WatchListCheck(None)
        try:
            listed = await self.hibp.contains(digest, cache=cache)
        except HibpUnavailable:
            return WatchListCheck(None, hibp_unavailable=True)
        if listed:
            return WatchListCheck(WatchListMatch(WatchListSource.HIBP, None, HIBP_REASON))
        return WatchListCheck(None)


async def _iterate(
    lines: Iterable[str | bytes] | AsyncIterable[str | bytes],
) -> AsyncIterable[str | bytes]:
    if isinstance(lines, AsyncIterable):
        async for line in lines:
            yield line
    else:
        for line in lines:
            yield line


def _parse_line(
    raw: str | bytes, number: int, threshold: int | None
) -> tuple[bytes | None, int | None]:
    try:
        text = raw.decode("ascii") if isinstance(raw, bytes) else raw
    except UnicodeDecodeError:
        raise WatchListImportError(
            "a line is not in HIBP's downloader format", line=number
        ) from None
    text = text.strip()
    if not text:
        return None, None
    match = _HIBP_LINE.fullmatch(text)
    if match is None:
        raise WatchListImportError("a line is not in HIBP's downloader format", line=number)
    count = None if match.group(2) is None else int(match.group(2))
    if threshold is not None and count is None:
        raise WatchListImportError("a threshold needs a count on every line", line=number)
    return bytes.fromhex(match.group(1)), count
