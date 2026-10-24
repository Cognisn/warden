"""Schema names other modules agree on: the audit channel, lock keys and setting keys."""

from __future__ import annotations

from warden import db


def test_audit_channel_is_the_agreed_name() -> None:
    # The syslog forwarder LISTENs on this name; the recorder NOTIFYs on it.
    assert db.AUDIT_CHANNEL == "warden_audit"


def test_advisory_lock_keys_are_distinct_signed_bigints() -> None:
    keys = [db.MIGRATION_LOCK_KEY, db.SYSLOG_FORWARDER_LOCK_KEY]
    assert len(set(keys)) == len(keys)
    for key in keys:
        assert -(2**63) <= key < 2**63


def test_syslog_cursor_setting_key() -> None:
    assert db.SYSLOG_CURSOR_SETTING == "syslog.cursor"
