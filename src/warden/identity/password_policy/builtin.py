"""The built-in common-password list (ruling PW12).

A read-only list of common passwords bundled with warden as sorted SHA-1
digests (20 bytes each, optionally gzipped), updated with warden releases.
It is loaded the first time it is needed, once per process, and searched by
bisection without holding any password. Its source, provenance and licence
are recorded in ``data/README.md`` beside it.
"""

from __future__ import annotations

import gzip
import threading
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

__all__ = ["BUILTIN_DATA", "BUILTIN_REASON", "BuiltinList"]

BUILTIN_REASON = "This password is too common"
BUILTIN_DATA = "common-passwords.sha1.gz"
_DIGEST = 20


def _bundled() -> Traversable:
    return resources.files("warden.identity.password_policy").joinpath("data", BUILTIN_DATA)


class BuiltinList:
    """Sorted SHA-1 digests, loaded lazily and once. ``path`` None means the bundled file."""

    def __init__(self, path: Path | Traversable | None = None) -> None:
        self._path = path
        self._data: bytes | None = None
        self._lock = threading.Lock()

    @property
    def loaded(self) -> bool:
        return self._data is not None

    def _load(self) -> bytes:
        data = self._data
        if data is not None:
            return data
        with self._lock:
            if self._data is None:
                source = self._path if self._path is not None else _bundled()
                if self._path is None and not source.is_file():
                    # The bundled data has not shipped yet: the list is empty.
                    self._data = b""
                else:
                    self._data = _check(_read(source))
            return self._data

    def __len__(self) -> int:
        return len(self._load()) // _DIGEST

    def contains(self, digest: bytes) -> bool:
        data = self._load()
        if len(digest) != _DIGEST:
            return False
        low, high = 0, len(data) // _DIGEST
        while low < high:
            middle = (low + high) // 2
            entry = data[middle * _DIGEST : (middle + 1) * _DIGEST]
            if entry < digest:
                low = middle + 1
            elif entry > digest:
                high = middle
            else:
                return True
        return False


def _read(source: Path | Traversable) -> bytes:
    raw = source.read_bytes()
    return gzip.decompress(raw) if source.name.endswith(".gz") else raw


def _check(data: bytes) -> bytes:
    if len(data) % _DIGEST:
        raise ValueError("the built-in password list is not a whole number of SHA-1 digests")
    previous = b""
    for start in range(0, len(data), _DIGEST):
        entry = data[start : start + _DIGEST]
        if entry <= previous:
            raise ValueError("the built-in password list is not sorted without duplicates")
        previous = entry
    return data
