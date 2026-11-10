"""The Pwned Passwords range client (ruling PW7).

k-anonymity: only the first five hex characters of a password's SHA-1 leave
warden. The service answers with every suffix it knows under that prefix,
padded with zero-count entries when padding is asked for, and the suffix is
compared locally in constant time over the whole answer.

Nothing is cached between calls. A ``RangeCache`` holds the answers for one
run of the recheck only, so a run asks once per prefix. Any failure (a
transport error, a status other than 200, an answer that is not a range
list) raises ``HibpUnavailable``, whose message never names the URL, the
prefix or the cause; the policy's on-unavailable setting decides what
follows. No request is made unless a policy enables the range API.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field

import httpx

from warden.config import PasswordsConfig
from warden.identity.password_policy.errors import HibpUnavailable

__all__ = ["PREFIX_LENGTH", "HibpRangeClient", "RangeCache"]

PREFIX_LENGTH = 5
_SUFFIX_LENGTH = 40 - PREFIX_LENGTH
_LINE = re.compile(r"([0-9A-Fa-f]{35}):([0-9]{1,12})")
# A padded answer is tens of kilobytes; anything far larger is not a range answer.
_MAX_BODY = 4 * 1024 * 1024


@dataclass(slots=True)
class RangeCache:
    """Range answers for one recheck run, by prefix. Never kept beyond the run."""

    answers: dict[str, tuple[tuple[str, bool], ...]] = field(default_factory=dict)
    lookups: int = 0


class HibpRangeClient:
    """Asks a Pwned Passwords range endpoint whether a SHA-1 digest is known."""

    def __init__(
        self, config: PasswordsConfig, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._base = config.hibp_range_url.rstrip("/") + "/"
        self._timeout = config.hibp_timeout_seconds
        self._headers = {"User-Agent": config.hibp_user_agent}
        if config.hibp_padding:
            self._headers["Add-Padding"] = "true"
        self._transport = transport

    async def contains(self, digest: bytes, *, cache: RangeCache | None = None) -> bool:
        """Whether the service lists ``digest`` with a count above zero."""
        if len(digest) != 20:
            raise ValueError("a SHA-1 digest is 20 bytes")
        text = digest.hex().upper()
        prefix, suffix = text[:PREFIX_LENGTH], text[PREFIX_LENGTH:]
        entries = cache.answers.get(prefix) if cache is not None else None
        if entries is None:
            entries = await self._range(prefix)
            if cache is not None:
                cache.answers[prefix] = entries
                cache.lookups += 1
        found = False
        for listed, counted in entries:
            # Every entry is compared, so the time taken does not depend on where it is.
            found |= hmac.compare_digest(listed, suffix) & counted
        return found

    async def _range(self, prefix: str) -> tuple[tuple[str, bool], ...]:
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout, follow_redirects=False
            ) as client:
                response = await client.get(self._base + prefix, headers=self._headers)
            if response.status_code != 200 or len(response.content) > _MAX_BODY:
                raise HibpUnavailable()
            return _parse(response.text)
        except HibpUnavailable:
            raise
        except (httpx.HTTPError, UnicodeDecodeError, ValueError):
            raise HibpUnavailable() from None


def _parse(body: str) -> tuple[tuple[str, bool], ...]:
    entries: list[tuple[str, bool]] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _LINE.fullmatch(line)
        if match is None:
            raise HibpUnavailable()
        entries.append((match.group(1).upper(), int(match.group(2)) > 0))
    return tuple(entries)
