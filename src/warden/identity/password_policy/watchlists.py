"""Watch lists (ruling PW7) and the built-in list (PW12).

A watch list is a named list with a reason a user is shown. A ``manual``
list holds exact passwords an administrator adds (stored as SHA-1 digests)
and a few contained terms (matched without regard to case); an ``imported``
list holds digests imported from a file in Have I Been Pwned's downloader
format, replaced in place by each import.

``match(password, policy)`` checks, in order, the built-in list, the
policy's attached lists' entries, their terms, and, when the policy enables
it, the Pwned Passwords range API. It returns the first match with its
reason, and never stores, logs or audits the password or its digest.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

__all__ = ["WatchListMatch", "WatchListSource"]


class WatchListSource(StrEnum):
    """Where a match came from."""

    BUILTIN = "builtin"
    LIST = "list"
    TERM = "term"
    HIBP = "hibp"


@dataclass(frozen=True, slots=True)
class WatchListMatch:
    """A password found on a watch list: where, which list (by id) and the user-facing reason."""

    source: WatchListSource
    list_id: uuid.UUID | None
    reason: str
