"""TOTP primitives (RFC 6238) and recovery code formats. No database."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from warden.identity import totp

RFC_SECRET = b"12345678901234567890"


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_sha1_vectors(timestamp: int, expected: str) -> None:
    step = totp.step_for(timestamp)
    assert totp.code_at(RFC_SECRET, step, digits=8) == expected
    assert totp.code_at(RFC_SECRET, step) == expected[-6:]


def test_step_is_thirty_seconds() -> None:
    assert totp.step_for(0) == 0
    assert totp.step_for(29.9) == 0
    assert totp.step_for(30) == 1


def test_matching_step_accepts_one_step_either_side() -> None:
    now = 1000
    for step in (now - 1, now, now + 1):
        assert totp.matching_step(RFC_SECRET, totp.code_at(RFC_SECRET, step), now) == step
    assert totp.matching_step(RFC_SECRET, totp.code_at(RFC_SECRET, now - 2), now) is None
    assert totp.matching_step(RFC_SECRET, totp.code_at(RFC_SECRET, now + 2), now) is None


@pytest.mark.parametrize(
    "code",
    [
        "\uff11\uff12\uff13\uff14\uff15\uff16",  # full-width; int() takes them (#125)
        "\u0661\u0662\u0663\u0664\u0665\u0666",  # Arabic-Indic digits
        "12345\uff16",
        "123456\n",  # trailing newline (#135)
        "\n123456",
        " 123456",
        "12345",
        "1234567",
        "abcdef",
        "",
        "1" * 10_000,
        123456,
        None,
        b"123456",
    ],
)
def test_malformed_codes_are_refused_cleanly(code: object) -> None:
    assert totp.parse_code(code) is None
    assert totp.matching_step(RFC_SECRET, code, 1000) is None


def test_well_formed_code_parses() -> None:
    assert totp.parse_code("012345") == "012345"


def test_generated_secrets_are_160_bits_and_distinct() -> None:
    first, second = totp.generate_secret(), totp.generate_secret()
    assert len(first) == 20 and first != second


def test_provisioning_uri() -> None:
    uri = totp.provisioning_uri(RFC_SECRET, account="alice@example.com", issuer="Example Product")
    parts = urlsplit(uri)
    assert parts.scheme == "otpauth" and parts.netloc == "totp"
    assert parts.path == "/Example%20Product:alice%40example.com"
    query = parse_qs(parts.query)
    assert query == {
        "secret": ["GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"],
        "issuer": ["Example Product"],
        "algorithm": ["SHA1"],
        "digits": ["6"],
        "period": ["30"],
    }


def test_recovery_codes_are_distinct_and_parse_back() -> None:
    codes = totp.generate_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    for code in codes:
        normalised = totp.parse_recovery_code(code)
        assert normalised is not None
        assert totp.parse_recovery_code(code.upper()) == normalised
        assert totp.parse_recovery_code(code.replace("-", "")) == normalised


@pytest.mark.parametrize(
    "code",
    [
        "",
        "abcde-fghij\n",
        "abcde-fghi",
        "abcde_fghij",
        "\uff41bcde-fghij",
        "abcde-fghi\u212a",  # Kelvin sign: lower() would turn it into an ASCII "k"
        5,
        None,
    ],
)
def test_malformed_recovery_codes_are_refused(code: object) -> None:
    assert totp.parse_recovery_code(code) is None


def test_recovery_code_hash_is_stable_and_distinct() -> None:
    a, b = totp.generate_recovery_codes(2)
    na, nb = totp.parse_recovery_code(a), totp.parse_recovery_code(b)
    assert na is not None and nb is not None
    assert totp.hash_recovery_code(na) == totp.hash_recovery_code(na)
    assert totp.hash_recovery_code(na) != totp.hash_recovery_code(nb)
