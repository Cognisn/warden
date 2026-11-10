"""Errors raised by password policies and watch lists.

Messages carry field names, identifiers and fixed reasons only: never a
password, a hash, a hash prefix, a fingerprint or a term a user typed.
"""

from __future__ import annotations

__all__ = [
    "HibpUnavailable",
    "PasswordPolicyConflict",
    "PasswordPolicyError",
    "PasswordPolicyNotFound",
    "WatchListError",
    "WatchListImportError",
    "WatchListNotFound",
]


class PasswordPolicyError(ValueError):
    """A password policy, or a change to one, was refused."""


class PasswordPolicyNotFound(PasswordPolicyError):
    """No password policy has that id."""


class PasswordPolicyConflict(PasswordPolicyError):
    """The change clashes with the stored state: a stale version, a name or
    priority already in use, or an attempt to remove the default."""


class WatchListError(ValueError):
    """A watch list, or a change to one, was refused."""


class WatchListNotFound(WatchListError):
    """No watch list has that id."""


class WatchListImportError(WatchListError):
    """An import was refused or failed; the list is left as it was.

    ``line`` is the 1-based number of the line that could not be read, when
    one could not; the line's content is never repeated.
    """

    def __init__(self, message: str, *, line: int | None = None) -> None:
        super().__init__(message if line is None else f"{message} (line {line})")
        self.line = line


class HibpUnavailable(Exception):
    """The breached-password range service could not be used.

    Always the same message: never the URL, the prefix or the cause.
    """

    def __init__(self) -> None:
        super().__init__("the breached-password range service is unavailable")
