"""No password, digest, digest prefix or fingerprint reaches the audit trail, a log or an error.

Every password policy and watch-list operation in this wave runs here with
logging at DEBUG; then the recorded audit details, the captured log text and
every error message are scanned for the test passwords and their SHA-1 in
every form (whole, upper and lower case, the five-character prefix and the
suffix).
"""

from __future__ import annotations

import hashlib
import json
import logging

import httpx
import pytest
from identity_support import FAST_HASHER, MemorySecrets, audit_rows

from warden.config import parse_config
from warden.db import Database
from warden.identity import Identity, PermissionRegistry
from warden.identity.crypto import TOTP_KEY_SECRET, new_totp_key
from warden.identity.password_policy import (
    ChangeReason,
    PasswordRules,
    PolicySettings,
    WatchListImportError,
    WatchListKind,
)
from warden.identity.password_policy.hibp import HibpRangeClient
from warden.keys import KeyStore

pytestmark = pytest.mark.db

# Each SHA-1 prefix holds a letter, so an upper-case prefix cannot occur by
# chance inside a lower-case UUID in the trail.
PASSWORDS = ["Leak Probe Alpha 7", "leak-probe-bravo-88", "Leak Probe Charlie 999"]


def _forms(password: str) -> list[str]:
    digest = hashlib.sha1(password.encode()).hexdigest()  # noqa: S324
    upper = digest.upper()
    return [password, password.lower(), digest, upper, upper[:5], upper[5:], digest[5:]]


def test_the_probes_have_lettered_prefixes() -> None:
    for password in PASSWORDS:
        prefix = hashlib.sha1(password.encode()).hexdigest().upper()[:5]  # noqa: S324
        assert any(c in "ABCDEF" for c in prefix), password


async def test_nothing_secret_is_recorded_logged_or_raised(
    db: Database, permissions: PermissionRegistry, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    secrets = MemorySecrets()
    secrets.set(TOTP_KEY_SECRET, new_totp_key())
    secrets.set("warden.fp", new_totp_key())
    config = parse_config(
        {
            "http": {
                "public_base_url": "https://app.example.com",
                "accept_invitation_link": "https://app.example.com/accept?t={token}",
                "reset_password_link": "https://app.example.com/reset?t={token}",
            },
            "identity": {"require_mfa": False},
            "passwords": {"fingerprint_key_secret": "warden.fp"},
        }
    )
    keys = KeyStore(db, secrets)
    await keys.rotate()
    identity = Identity(config, db, keys, permissions, secrets=secrets, hasher=FAST_HASHER)
    leaked = hashlib.sha1(PASSWORDS[2].encode()).hexdigest().upper()  # noqa: S324

    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"{leaked[5:]}:3")

    identity.watch_lists.hibp = HibpRangeClient(
        config.passwords, transport=httpx.MockTransport(answer)
    )
    errors: list[str] = []

    manual = await identity.watch_lists.create("Local", "Banned", WatchListKind.MANUAL, actor="a")
    imported = await identity.watch_lists.create(
        "Feed", "Breached", WatchListKind.IMPORTED, actor="a"
    )
    await identity.watch_lists.add_entries(manual.id, PASSWORDS[:1], actor="a")
    await identity.watch_lists.add_terms(manual.id, ["probe"], actor="a")
    await identity.watch_lists.import_hibp(
        imported.id,
        [f"{hashlib.sha1(PASSWORDS[1].encode()).hexdigest().upper()}:4"],  # noqa: S324
        actor="a",
    )
    try:
        await identity.watch_lists.import_hibp(imported.id, [PASSWORDS[1]], actor="a")
    except WatchListImportError as exc:
        errors.append(str(exc))
    policy = await identity.password_policies.create(
        PolicySettings(
            name="Strict",
            rules=PasswordRules(min_length=12),
            watch_list_ids=(manual.id, imported.id),
            hibp_enabled=True,
            fingerprint_enabled=True,
            history_count=3,
        ),
        priority=1,
        actor="a",
    )
    await identity.password_policies.map_role("viewer", policy.id, actor="a")
    for password in PASSWORDS:
        user = await identity.users.create(
            f"probe-{PASSWORDS.index(password)}@example.com", actor="a", password=password
        )
        await identity.roles.assign(user.id, "viewer", actor="a")
        await identity.password_history.record(user.id, await FAST_HASHER.hash(password))
        await identity.password_history.reused(user.id, password, count=3)
        await identity.password_states.store_fingerprint(
            user.id, identity.password_fingerprints.seal(user.id, password)
        )
        checked = await identity.watch_lists.match(password, policy)
        if checked.match is not None:
            await identity.password_states.require_change(
                user.id, ChangeReason.WATCH_LIST, match=checked.match
            )
    await identity.password_recheck.run(actor="scheduler")
    await identity.prune()

    rows = await audit_rows(db)
    trail = json.dumps(rows, default=str)
    logged = caplog.text
    for password in PASSWORDS:
        for form in _forms(password):
            assert form not in trail, f"audit trail holds a form of {password!r}"
            assert form not in logged, f"a log line holds a form of {password!r}"
            assert all(form not in e for e in errors)
    assert len(rows) > 10
    assert errors
