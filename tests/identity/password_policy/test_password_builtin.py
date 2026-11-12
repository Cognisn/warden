"""The built-in common-password list (ruling PW12): sorted SHA-1 digests, loaded once.

Most tests use a small synthetic file; the last ones check the bundled data,
SHA-1 digests of SecLists' top 100,000 passwords (Skuld question 33).
"""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from warden.identity.password_policy.builtin import BUILTIN_REASON, BuiltinList

WORDS = ["password", "123456", "qwerty", "letmein", "dragon"]


def _digests(words: list[str]) -> list[bytes]:
    return sorted(hashlib.sha1(w.encode()).digest() for w in words)  # noqa: S324


def _write(path: Path, digests: list[bytes], *, compress: bool) -> Path:
    data = b"".join(digests)
    path.write_bytes(gzip.compress(data) if compress else data)
    return path


@pytest.mark.parametrize("compress", [True, False])
def test_a_listed_digest_is_found_and_others_are_not(tmp_path: Path, compress: bool) -> None:
    name = "list.sha1.gz" if compress else "list.sha1"
    listed = BuiltinList(_write(tmp_path / name, _digests(WORDS), compress=compress))
    for word in WORDS:
        assert listed.contains(hashlib.sha1(word.encode()).digest())  # noqa: S324
    assert not listed.contains(hashlib.sha1(b"not on the list").digest())  # noqa: S324
    assert not listed.contains(b"\x00" * 20)
    assert not listed.contains(b"\xff" * 20)
    assert len(listed) == len(WORDS)


def test_the_file_is_read_once_and_only_when_first_needed(tmp_path: Path) -> None:
    path = _write(tmp_path / "list.sha1", _digests(WORDS), compress=False)
    listed = BuiltinList(path)
    assert not listed.loaded
    listed.contains(b"\x00" * 20)
    assert listed.loaded
    path.unlink()
    assert listed.contains(hashlib.sha1(b"dragon").digest())  # noqa: S324


@pytest.mark.parametrize(
    "data",
    [b"\x00" * 19, b"\x01" * 20 + b"\x00" * 20, b"\x01" * 40],
    ids=["ragged", "unsorted", "duplicate"],
)
def test_a_malformed_file_is_refused(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "list.sha1"
    path.write_bytes(data)
    with pytest.raises(ValueError, match="built-in"):
        BuiltinList(path).contains(b"\x00" * 20)


def test_the_reason_is_fixed() -> None:
    assert BUILTIN_REASON == "This password is too common"


def test_an_empty_list_matches_nothing(tmp_path: Path) -> None:
    listed = BuiltinList(_write(tmp_path / "list.sha1", [], compress=False))
    assert not listed.contains(hashlib.sha1(b"password").digest())  # noqa: S324
    assert len(listed) == 0


def test_the_bundled_list_ships() -> None:
    listed = BuiltinList()
    assert len(listed) == 99_999
    for word in (b"password", b"123456", b"qwerty"):
        assert listed.contains(hashlib.sha1(word).digest())  # noqa: S324
    assert not listed.contains(hashlib.sha1(b"an unremarkable synthetic passphrase").digest())  # noqa: S324


def test_one_bundled_list_is_shared_by_the_process() -> None:
    from warden.identity.password_policy.builtin import bundled_list

    assert bundled_list() is bundled_list()
