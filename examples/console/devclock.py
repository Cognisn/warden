"""A development clock for the sample: walk password expiry without waiting.

``Identity`` takes a ``clock`` (a callable returning seconds since the epoch)
and uses it for session lifetimes and password ages. ``serve --dev-clock``
builds the console with this clock, which reads the real time plus an offset
the console's development screen sets. It is for local development only and
is off unless asked for: the screen says so, and ``/api/dev/clock`` answers
404 when it is off.

Moving the clock forward ends sessions the way time would (their tokens
expire), so sign in again afterwards.
"""

from __future__ import annotations

import time

__all__ = ["MAX_OFFSET_DAYS", "DevClock"]

# Ten years either way; more would only show how far a float can stretch.
MAX_OFFSET_DAYS = 3650
SECONDS_PER_DAY = 86400


class DevClock:
    """The real time plus a settable whole-day offset."""

    def __init__(self) -> None:
        self._offset_days = 0

    @property
    def offset_days(self) -> int:
        return self._offset_days

    def set_days(self, days: object) -> None:
        if type(days) is not int or not -MAX_OFFSET_DAYS <= days <= MAX_OFFSET_DAYS:
            raise ValueError(f"days must be a whole number within {MAX_OFFSET_DAYS} of today")
        self._offset_days = days

    def __call__(self) -> float:
        return time.time() + self._offset_days * SECONDS_PER_DAY
