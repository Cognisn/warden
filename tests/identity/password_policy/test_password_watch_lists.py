"""Watch lists (ruling PW7): exact entries, terms, HIBP-format imports and matching."""

from __future__ import annotations

import asyncio
import dataclasses
import gzip
import hashlib
from pathlib import Path
from typing import Any

import httpx
import pytest
from identity_support import audit_rows

from warden.config import PasswordsConfig
from warden.db import Database
from warden.identity import PermissionRegistry
from warden.identity.password_policy import (
    PasswordRules,
    WatchListError,
    WatchListImportError,
    WatchListNotFound,
)
from warden.identity.password_policy.builtin import BUILTIN_REASON, BuiltinList
from warden.identity.password_policy.hibp import HibpRangeClient
from warden.identity.password_policy.store import PasswordPolicies, PolicySettings
from warden.identity.password_policy.watchlists import (
    HIBP_REASON,
    WatchListKind,
    WatchLists,
    WatchListSource,
)

pytestmark = pytest.mark.db

COMMON = "synthetic-common-1"
LEAKED = "Synthetic Leaked 22"
SAFE = "an unremarkable synthetic passphrase"


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest().upper()  # noqa: S324


class Range:
    """A fake range endpoint: lists ``LEAKED`` only, or fails."""

    def __init__(self) -> None:
        self.requests = 0
        self.fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.fail:
            return httpx.Response(503)
        digest = _sha1(LEAKED)
        if request.url.path.endswith(digest[:5]):
            return httpx.Response(200, text=f"{digest[5:]}:42\r\n{'0' * 35}:0")
        return httpx.Response(200, text=f"{'1' * 35}:3")


@pytest.fixture
def range_api() -> Range:
    return Range()


@pytest.fixture
def builtin(tmp_path: Path) -> BuiltinList:
    digest = hashlib.sha1(COMMON.encode()).digest()  # noqa: S324
    path = tmp_path / "builtin.sha1.gz"
    path.write_bytes(gzip.compress(digest))
    return BuiltinList(path)


@pytest.fixture
def policies(db: Database, permissions: PermissionRegistry) -> PasswordPolicies:
    return PasswordPolicies(db, permissions, seed_min_length=12, fingerprint_available=False)


@pytest.fixture
def lists(
    db: Database, policies: PasswordPolicies, builtin: BuiltinList, range_api: Range
) -> WatchLists:
    hibp = HibpRangeClient(PasswordsConfig(), transport=httpx.MockTransport(range_api))
    return WatchLists(db, policies, builtin=builtin, hibp=hibp)


def _settings(**overrides: Any) -> PolicySettings:
    values: dict[str, Any] = {"name": "P", "rules": PasswordRules(min_length=12)}
    values.update(overrides)
    return PolicySettings(**values)


async def test_create_rename_and_delete(lists: WatchLists, db: Database) -> None:
    created = await lists.create(
        "Company words", "Too close to our name", WatchListKind.MANUAL, actor="a"
    )
    assert created.kind == WatchListKind.MANUAL and created.entry_count == 0
    renamed = await lists.update(created.id, name="Company terms", actor="a")
    assert renamed.name == "Company terms" and renamed.reason == "Too close to our name"
    assert (await lists.get(created.id)).name == "Company terms"
    assert [w.id for w in await lists.list()] == [created.id]
    await lists.delete(created.id, actor="a")
    with pytest.raises(WatchListNotFound):
        await lists.get(created.id)
    actions = [r["action"] for r in await audit_rows(db) if ".watch_list." in r["action"]]
    assert actions == [
        "warden.identity.watch_list.created",
        "warden.identity.watch_list.updated",
        "warden.identity.watch_list.deleted",
    ]


@pytest.mark.parametrize(
    ("name", "reason"),
    [("", "r"), ("x" * 65, "r"), ("ok", ""), ("ok", "x" * 201), ("bad\nname", "r")],
)
async def test_invalid_names_and_reasons_are_refused(
    lists: WatchLists, name: str, reason: str
) -> None:
    with pytest.raises(WatchListError):
        await lists.create(name, reason, WatchListKind.MANUAL, actor="a")


async def test_names_are_unique_without_regard_to_case(lists: WatchLists) -> None:
    await lists.create("Breaches", "r", WatchListKind.IMPORTED, actor="a")
    with pytest.raises(WatchListError):
        await lists.create("breaches", "r", WatchListKind.IMPORTED, actor="a")


async def test_exact_entries_are_stored_as_sha1_only(lists: WatchLists, db: Database) -> None:
    listed = await lists.create("Exact", "Not allowed here", WatchListKind.MANUAL, actor="a")
    assert (
        await lists.add_entries(listed.id, [LEAKED, LEAKED, "another synthetic one"], actor="a")
        == 2
    )
    assert (await lists.get(listed.id)).entry_count == 2
    async with db.connection() as conn:
        cur = await conn.execute("SELECT hash FROM warden.watch_list_entries")
        stored = {bytes(r[0]) for r in await cur.fetchall()}
    assert hashlib.sha1(LEAKED.encode()).digest() in stored  # noqa: S324
    assert all(len(h) == 20 for h in stored)
    assert await lists.remove_entries(listed.id, [LEAKED], actor="a") == 1
    assert (await lists.get(listed.id)).entry_count == 1
    rows = await audit_rows(db, "warden.identity.watch_list.entries_changed")
    assert [r["details"] for r in rows] == [
        {"entries_added": 2, "entries_removed": 0},
        {"entries_added": 0, "entries_removed": 1},
    ]


async def test_terms_are_normalised_and_bounded(lists: WatchLists) -> None:
    listed = await lists.create("Terms", "Too close to our name", WatchListKind.MANUAL, actor="a")
    assert await lists.add_terms(listed.id, ["Example", "EXAMPLE", "Stra\u00dfe"], actor="a") == 2
    assert (await lists.get(listed.id)).terms == ("example", "strasse")
    with pytest.raises(WatchListError):
        await lists.add_terms(listed.id, ["ab"], actor="a")
    with pytest.raises(WatchListError):
        await lists.add_terms(listed.id, ["x" * 65], actor="a")
    assert await lists.remove_terms(listed.id, ["EXAMPLE"], actor="a") == 1


async def test_an_imported_list_takes_imports_only_and_a_manual_list_never(
    lists: WatchLists,
) -> None:
    manual = await lists.create("Manual", "r", WatchListKind.MANUAL, actor="a")
    imported = await lists.create("Imported", "r", WatchListKind.IMPORTED, actor="a")
    with pytest.raises(WatchListError):
        await lists.add_entries(imported.id, [LEAKED], actor="a")
    with pytest.raises(WatchListError):
        await lists.add_terms(imported.id, ["example"], actor="a")
    with pytest.raises(WatchListError):
        await lists.import_hibp(manual.id, [f"{_sha1(LEAKED)}:1"], actor="a")


async def test_match_checks_builtin_then_lists_then_terms_then_the_range_api(
    lists: WatchLists, policies: PasswordPolicies, range_api: Range
) -> None:
    exact = await lists.create("Exact", "Banned here", WatchListKind.MANUAL, actor="a")
    await lists.add_entries(exact.id, [SAFE], actor="a")
    await lists.add_terms(exact.id, ["acme"], actor="a")
    nothing = _settings(include_builtin=False)
    everything = _settings(include_builtin=True, watch_list_ids=(exact.id,), hibp_enabled=True)

    found = await lists.match(COMMON, everything)
    assert found.match is not None and found.match.source == WatchListSource.BUILTIN
    assert found.match.reason == BUILTIN_REASON and found.match.list_id is None
    assert (await lists.match(COMMON, nothing)).match is None

    found = await lists.match(SAFE, everything)
    assert found.match is not None and found.match.source == WatchListSource.LIST
    assert found.match.list_id == exact.id and found.match.reason == "Banned here"

    found = await lists.match("my ACME password 2026", everything)
    assert found.match is not None and found.match.source == WatchListSource.TERM
    assert found.match.list_id == exact.id

    assert range_api.requests == 0, "nothing reached the range API before it was needed"
    found = await lists.match(LEAKED, everything)
    assert found.match is not None and found.match.source == WatchListSource.HIBP
    assert found.match.reason == HIBP_REASON
    assert range_api.requests == 1

    clean = await lists.match("an entirely different synthetic one", everything)
    assert clean.match is None and not clean.hibp_unavailable


async def test_the_default_policy_makes_no_outbound_request(
    lists: WatchLists, policies: PasswordPolicies, range_api: Range
) -> None:
    default = await policies.default()
    assert not default.settings.hibp_enabled
    await lists.match(LEAKED, default.settings)
    assert range_api.requests == 0


async def test_terms_match_after_nfc_and_casefold(lists: WatchLists) -> None:
    listed = await lists.create("Terms", "r", WatchListKind.MANUAL, actor="a")
    await lists.add_terms(listed.id, ["stra\u00dfe", "caf\u00e9"], actor="a")
    settings = _settings(include_builtin=False, watch_list_ids=(listed.id,))
    assert (await lists.match("MY STRASSE 12345", settings)).match is not None
    assert (await lists.match("great CAFE\u0301 here", settings)).match is not None
    assert (await lists.match("cafe without accent", settings)).match is None


async def test_an_exact_entry_matches_a_decomposed_spelling(lists: WatchLists) -> None:
    listed = await lists.create("Exact", "r", WatchListKind.MANUAL, actor="a")
    await lists.add_entries(listed.id, ["caf\u00e9 synthetic 2026"], actor="a")
    settings = _settings(include_builtin=False, watch_list_ids=(listed.id,))
    assert (await lists.match("cafe\u0301 synthetic 2026", settings)).match is not None


async def test_an_unattached_list_is_not_checked(lists: WatchLists) -> None:
    listed = await lists.create("Exact", "r", WatchListKind.MANUAL, actor="a")
    await lists.add_entries(listed.id, [SAFE], actor="a")
    await lists.add_terms(listed.id, ["unremarkable"], actor="a")
    assert (await lists.match(SAFE, _settings(include_builtin=False))).match is None
    # With another list attached, the unattached one is still not consulted.
    other = await lists.create("Other", "r", WatchListKind.MANUAL, actor="a")
    await lists.add_entries(other.id, ["something else entirely"], actor="a")
    attached = _settings(include_builtin=False, watch_list_ids=(other.id,))
    assert (await lists.match(SAFE, attached)).match is None


async def test_an_unavailable_range_api_is_reported_not_raised(
    lists: WatchLists, range_api: Range
) -> None:
    range_api.fail = True
    allow = _settings(include_builtin=False, hibp_enabled=True)
    refuse = dataclasses.replace(allow, hibp_on_unavailable="refuse")
    checked = await lists.match(LEAKED, allow)
    assert checked.match is None and checked.hibp_unavailable
    assert not checked.blocked(allow)
    assert checked.blocked(refuse)


async def test_attach_and_detach(
    lists: WatchLists, policies: PasswordPolicies, db: Database
) -> None:
    listed = await lists.create("Exact", "r", WatchListKind.MANUAL, actor="a")
    policy = await policies.create(_settings(name="Strict"), priority=1, actor="a")
    attached = await policies.attach(policy.id, listed.id, actor="a")
    assert attached.settings.watch_list_ids == (listed.id,)
    assert attached.version == policy.version + 1
    detached = await policies.detach(policy.id, listed.id, actor="a")
    assert detached.settings.watch_list_ids == ()
    with pytest.raises(WatchListNotFound):
        await policies.attach(policy.id, policy.id, actor="a")
    # Deleting a list detaches it everywhere.
    await policies.attach(policy.id, listed.id, actor="a")
    await lists.delete(listed.id, actor="a")
    assert (await policies.get(policy.id)).settings.watch_list_ids == ()
    (row,) = await audit_rows(db, "warden.identity.watch_list.deleted")
    assert row["details"] == {"policies_detached": 1}


def _lines(words: list[str], count: int = 5) -> list[str]:
    return [f"{_sha1(w)}:{count}" for w in words]


async def test_an_import_replaces_the_list_and_keeps_bookkeeping(
    lists: WatchLists, db: Database
) -> None:
    listed = await lists.create("Breaches", "Found in a breach", WatchListKind.IMPORTED, actor="a")
    settings = _settings(include_builtin=False, watch_list_ids=(listed.id,))
    result = await lists.import_hibp(listed.id, _lines(["old one 1", "old two 2"]), actor="a")
    assert result.imported == 2
    assert (await lists.match("old one 1", settings)).match is not None
    body = [
        f"{_sha1('new one 1')}:9\r\n".encode(),
        b"\n",
        f"{_sha1('at the threshold')}:3".encode(),
        f"{_sha1('rare one')}:2".encode(),
    ]
    result = await lists.import_hibp(listed.id, body, threshold=3, actor="a")
    assert (result.imported, result.below_threshold, result.lines) == (2, 1, 3)
    assert (await lists.match("old one 1", settings)).match is None
    assert (await lists.match("new one 1", settings)).match is not None
    assert (await lists.match("at the threshold", settings)).match is not None
    assert (await lists.match("rare one", settings)).match is None
    after = await lists.get(listed.id)
    assert after.entry_count == 2 and after.import_threshold == 3
    assert after.last_imported_at is not None
    rows = await audit_rows(db, "warden.identity.watch_list.imported")
    assert rows[-1]["details"] == {"imported": 2, "below_threshold": 1, "lines": 3, "threshold": 3}
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.watch_list_staging")
        assert await cur.fetchone() == (0,)


async def test_an_async_stream_is_imported(lists: WatchLists) -> None:
    listed = await lists.create("Breaches", "r", WatchListKind.IMPORTED, actor="a")

    async def stream() -> Any:
        for line in _lines([f"streamed {i}" for i in range(50)]):
            yield line.encode() + b"\n"

    assert (await lists.import_hibp(listed.id, stream(), actor="a")).imported == 50


@pytest.mark.parametrize(
    ("line", "threshold"),
    [
        ("not a hash:1", None),
        (f"{'G' * 40}:1", None),
        (f"{'A' * 39}:1", None),
        (f"{'A' * 40}:many", None),
        (f"{'A' * 40}", 2),  # a threshold needs counts
        (f"{'A' * 40}:1:2", None),
    ],
)
async def test_a_failed_import_leaves_the_list_as_it_was(
    lists: WatchLists, db: Database, line: str, threshold: int | None
) -> None:
    listed = await lists.create("Breaches", "r", WatchListKind.IMPORTED, actor="a")
    await lists.import_hibp(listed.id, _lines(["kept 1"]), actor="a")
    settings = _settings(include_builtin=False, watch_list_ids=(listed.id,))
    with pytest.raises(WatchListImportError) as caught:
        await lists.import_hibp(
            listed.id, [*_lines(["new 1"]), line], threshold=threshold, actor="a"
        )
    assert caught.value.line == 2
    assert line not in str(caught.value)
    assert (await lists.match("kept 1", settings)).match is not None
    assert (await lists.match("new 1", settings)).match is None
    assert (await lists.get(listed.id)).entry_count == 1
    async with db.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM warden.watch_list_staging")
        assert await cur.fetchone() == (0,)
    failed = [
        r
        for r in await audit_rows(db, "warden.identity.watch_list.imported")
        if r["outcome"] == "failure"
    ]
    assert failed and failed[-1]["details"] == {"line": 2}


async def test_an_import_racing_matches_sees_the_old_or_the_new_list_never_a_mix(
    lists: WatchLists, db: Database
) -> None:
    listed = await lists.create("Breaches", "r", WatchListKind.IMPORTED, actor="a")
    settings = _settings(include_builtin=False, watch_list_ids=(listed.id,))
    shared = "on both lists 1"
    old = [shared, *(f"old {i}" for i in range(2_000))]
    new = [shared, *(f"new {i}" for i in range(60_000))]
    await lists.import_hibp(listed.id, _lines(old), actor="a")
    sizes: set[int] = set()
    missing = 0
    reads = 0
    importing = asyncio.create_task(lists.import_hibp(listed.id, _lines(new), actor="a"))
    while not importing.done():
        checked = await lists.match(shared, settings)
        missing += checked.match is None
        async with db.connection() as conn:
            cur = await conn.execute(
                "SELECT count(*) FROM warden.watch_list_entries WHERE list_id = %s", (listed.id,)
            )
            row = await cur.fetchone()
        assert row is not None
        sizes.add(int(row[0]))
        reads += 1
    await importing
    assert reads > 5, "the reads did not overlap the import"
    assert missing == 0, "a password on both lists was missing during the swap"
    assert sizes <= {len(old), len(new)}, sizes
