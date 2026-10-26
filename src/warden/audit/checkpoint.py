"""Signed retention checkpoints.

A retention purge deletes a prefix of the chain, rows ``first_purged_id``
to ``through_id``, and first appends a checkpoint row. The row's action is
``PURGE_ACTION``, and its details carry the hash of the last purged row,
signed with warden's Ed25519 key. The first surviving row's ``prev_hash``
then links to a signed value instead of a missing row. A forged checkpoint
fails its signature, and a checkpoint signed by a revoked key is refused.

    message = b"warden.audit.checkpoint.v1\\n" + canonical_json(payload)

where ``payload`` is the checkpoint object without its ``signature``.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from warden.audit.actions import PURGE_ACTION
from warden.audit.chain import canonical_json

__all__ = [
    "CHECKPOINT_KEY",
    "PURGE_ACTION",
    "Checkpoint",
    "HistoricalVerifier",
    "MalformedCheckpoint",
]

CHECKPOINT_KEY = "checkpoint"
_VERSION = 1
_DOMAIN = b"warden.audit.checkpoint.v1\n"


class MalformedCheckpoint(ValueError):
    """A purge row's details do not hold a well-formed checkpoint."""


class HistoricalVerifier(Protocol):
    """What verification needs from the key store: ``KeyStore`` fits."""

    async def verify_historical(self, message: bytes, signature: bytes, key_id: str) -> bool: ...


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """What a purge removed, and the hash the surviving chain links to."""

    first_purged_id: int
    through_id: int
    through_hash: bytes
    purged_rows: int
    cutoff: datetime
    retention_days: int
    key_id: str
    signature: bytes = b""

    def payload(self) -> dict[str, Any]:
        return {
            "version": _VERSION,
            "first_purged_id": self.first_purged_id,
            "through_id": self.through_id,
            "through_hash": self.through_hash.hex(),
            "purged_rows": self.purged_rows,
            "cutoff": self.cutoff.isoformat(),
            "retention_days": self.retention_days,
            "key_id": self.key_id,
        }

    def message(self) -> bytes:
        """The bytes the signature covers."""
        return _DOMAIN + canonical_json(self.payload())

    def to_details(self) -> dict[str, Any]:
        return {CHECKPOINT_KEY: {**self.payload(), "signature": _b64url(self.signature)}}

    @classmethod
    def from_details(cls, details: Mapping[str, Any]) -> Checkpoint:
        """Parse a purge row's details; ``MalformedCheckpoint`` if they do not fit."""
        body = details.get(CHECKPOINT_KEY)
        try:
            if not isinstance(body, Mapping) or body.get("version") != _VERSION:
                raise MalformedCheckpoint("unknown checkpoint version")
            through_hash = bytes.fromhex(body["through_hash"])
            checkpoint = cls(
                first_purged_id=_int(body["first_purged_id"]),
                through_id=_int(body["through_id"]),
                through_hash=through_hash,
                purged_rows=_int(body["purged_rows"]),
                cutoff=datetime.fromisoformat(body["cutoff"]),
                retention_days=_int(body["retention_days"]),
                key_id=_str(body["key_id"]),
                signature=_b64url_decode(_str(body["signature"])),
            )
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            if isinstance(exc, MalformedCheckpoint):
                raise
            raise MalformedCheckpoint("checkpoint details are malformed") from None
        if len(through_hash) != 32 or checkpoint.through_id < checkpoint.first_purged_id:
            raise MalformedCheckpoint("checkpoint details are malformed")
        if checkpoint.payload() != {k: v for k, v in body.items() if k != "signature"}:
            raise MalformedCheckpoint("checkpoint details carry unexpected fields")
        return checkpoint


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedCheckpoint("expected an integer")
    return value


def _str(value: Any) -> str:
    if not isinstance(value, str):
        raise MalformedCheckpoint("expected a string")
    return value
