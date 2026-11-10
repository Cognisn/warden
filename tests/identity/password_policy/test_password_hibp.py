"""The Pwned Passwords range client (ruling PW7): k-anonymity, padding, fixed errors.

No live service: every request goes to an ``httpx.MockTransport``. The live
check is ``live/test_password_hibp_live.py``, marked ``integration``.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest

from warden.config import PasswordsConfig
from warden.identity.password_policy import HibpUnavailable
from warden.identity.password_policy.hibp import HibpRangeClient, RangeCache

PASSWORD = "Tr0ub4dor&3 synthetic"
DIGEST = hashlib.sha1(PASSWORD.encode()).digest()  # noqa: S324 - the HIBP format
HEX = DIGEST.hex().upper()
PREFIX, SUFFIX = HEX[:5], HEX[5:]
OTHER = "0" * 35


class Recorder:
    def __init__(self, body: str = "", status: int = 200) -> None:
        self.requests: list[httpx.Request] = []
        self.body = body
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, text=self.body)


def _client(recorder: Recorder, **settings: object) -> HibpRangeClient:
    config = PasswordsConfig(**settings)  # type: ignore[arg-type]
    return HibpRangeClient(config, transport=httpx.MockTransport(recorder))


async def test_only_the_five_character_prefix_is_sent() -> None:
    recorder = Recorder(f"{OTHER}:3\r\n{SUFFIX}:12\r\n")
    assert await _client(recorder).contains(DIGEST)
    (request,) = recorder.requests
    assert request.method == "GET"
    assert str(request.url) == f"https://api.pwnedpasswords.com/range/{PREFIX}"
    assert request.url.path.rsplit("/", 1)[1] == PREFIX
    sent = str(request.url) + "".join(f"{k}:{v}" for k, v in request.headers.items())
    assert SUFFIX not in sent and SUFFIX.lower() not in sent
    assert request.content == b""


async def test_padding_and_the_user_agent_are_sent() -> None:
    recorder = Recorder()
    await _client(recorder, hibp_user_agent="Example Product").contains(DIGEST)
    request = recorder.requests[0]
    assert request.headers["Add-Padding"] == "true"
    assert request.headers["User-Agent"] == "Example Product"
    recorder = Recorder()
    await _client(recorder, hibp_padding=False).contains(DIGEST)
    assert "Add-Padding" not in recorder.requests[0].headers


async def test_a_mirror_url_is_used_with_or_without_a_trailing_slash() -> None:
    for base in (
        "https://pwned.example.com/mirror/range",
        "https://pwned.example.com/mirror/range/",
    ):
        recorder = Recorder()
        await _client(recorder, hibp_range_url=base).contains(DIGEST)
        assert str(recorder.requests[0].url) == f"https://pwned.example.com/mirror/range/{PREFIX}"


async def test_a_listed_suffix_matches_and_others_do_not() -> None:
    assert await _client(Recorder(f"{SUFFIX}:1")).contains(DIGEST)
    assert await _client(Recorder(f"{SUFFIX.lower()}:1")).contains(DIGEST)
    assert not await _client(Recorder(f"{OTHER}:5\n")).contains(DIGEST)
    # One character different in the last place is a different hash.
    near = SUFFIX[:-1] + ("0" if SUFFIX[-1] != "0" else "1")
    assert not await _client(Recorder(f"{near}:5\n")).contains(DIGEST)
    assert not await _client(Recorder("")).contains(DIGEST)


async def test_padding_entries_with_a_zero_count_are_not_matches() -> None:
    assert not await _client(Recorder(f"{SUFFIX}:0\n{OTHER}:4")).contains(DIGEST)


async def test_every_entry_is_compared_even_after_a_match() -> None:
    # Constant work for a given response: a match early or late reads the same lines.
    early = f"{SUFFIX}:2\n" + f"{OTHER}:1\n" * 50
    late = f"{OTHER}:1\n" * 50 + f"{SUFFIX}:2\n"
    assert await _client(Recorder(early)).contains(DIGEST)
    assert await _client(Recorder(late)).contains(DIGEST)


@pytest.mark.parametrize(
    "recorder",
    [
        Recorder("", status=503),
        Recorder("", status=429),
        Recorder("", status=404),
        Recorder("not a range answer"),
        Recorder(f"{SUFFIX}:many"),
        Recorder(f"{SUFFIX[:-1]}:1"),
    ],
)
async def test_any_failure_is_one_fixed_error(recorder: Recorder) -> None:
    with pytest.raises(HibpUnavailable) as caught:
        await _client(recorder).contains(DIGEST)
    message = str(caught.value)
    assert message == "the breached-password range service is unavailable"
    assert PREFIX not in message and "pwnedpasswords" not in message
    assert caught.value.__cause__ is None or PREFIX not in str(caught.value.__cause__)


async def test_a_transport_error_is_the_same_fixed_error() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}")

    client = HibpRangeClient(PasswordsConfig(), transport=httpx.MockTransport(refuse))
    with pytest.raises(HibpUnavailable) as caught:
        await client.contains(DIGEST)
    assert str(caught.value) == "the breached-password range service is unavailable"
    assert caught.value.__suppress_context__


async def test_nothing_is_cached_across_calls() -> None:
    recorder = Recorder(f"{SUFFIX}:1")
    client = _client(recorder)
    await client.contains(DIGEST)
    await client.contains(DIGEST)
    assert len(recorder.requests) == 2


async def test_one_run_asks_once_per_prefix() -> None:
    recorder = Recorder(f"{SUFFIX}:1")
    client = _client(recorder)
    cache = RangeCache()
    sibling = bytes.fromhex(PREFIX + "0" * 35)
    assert await client.contains(DIGEST, cache=cache)
    assert not await client.contains(sibling, cache=cache)
    assert len(recorder.requests) == 1
    assert cache.lookups == 1


async def test_a_digest_must_be_twenty_bytes() -> None:
    with pytest.raises(ValueError, match="20 bytes"):
        await _client(Recorder()).contains(DIGEST[:19])
