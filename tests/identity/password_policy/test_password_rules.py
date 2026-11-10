"""The password rule engine (rulings PW3, PW4 and PW5): pure, deterministic, no I/O.

Lengths are counted in Unicode code points after NFC normalisation, so a
precomposed and a decomposed accent count the same, and a character outside
the Basic Multilingual Plane counts once.
"""

from __future__ import annotations

import pytest

from warden.identity.password_policy import (
    DESCRIPTION_VERSION,
    PassphraseRule,
    PasswordPolicyError,
    PasswordRules,
    RuleCode,
    Tier,
    UserContext,
    evaluate,
)

NOBODY = UserContext()


def _rules(**overrides: object) -> PasswordRules:
    values: dict[str, object] = {"min_length": 12}
    values.update(overrides)
    return PasswordRules(**values)  # type: ignore[arg-type]


def _failed(password: str, rules: PasswordRules, context: UserContext = NOBODY) -> set[str]:
    return {r.code for r in evaluate(password, rules, context).results if not r.passed}


def test_the_seeded_shape_checks_length_only() -> None:
    rules = _rules()
    result = evaluate("a" * 12, rules, NOBODY)
    assert result.ok
    assert [r.code for r in result.results] == [RuleCode.MIN_LENGTH, RuleCode.MAX_LENGTH]
    assert not result.passphrase
    assert result.tier is None


def test_length_boundaries() -> None:
    rules = _rules(min_length=12, max_length=16)
    assert _failed("a" * 11, rules) == {"min_length"}
    assert _failed("a" * 12, rules) == set()
    assert _failed("a" * 16, rules) == set()
    assert _failed("a" * 17, rules) == {"max_length"}


def test_length_is_counted_in_code_points_after_nfc() -> None:
    rules = _rules(min_length=8, max_length=8)
    composed = "caf\u00e9" + "abcd"
    decomposed = "cafe\u0301" + "abcd"
    assert len(decomposed) == 9
    assert _failed(composed, rules) == set()
    assert _failed(decomposed, rules) == set()
    # A character outside the BMP is one code point (a browser's .length says two).
    assert _failed("\U0001f600" * 8, rules) == set()


def test_a_combining_mark_that_does_not_compose_counts_but_belongs_to_no_class() -> None:
    rules = _rules(min_length=8, min_classes=2)
    # x + combining acute has no precomposed form: two code points, one lowercase.
    assert _failed("x\u0301" * 4, rules) == {"min_classes"}


@pytest.mark.parametrize(
    ("password", "classes"),
    [
        ("abcdefghijkl", 1),
        ("abcdefABCDEF", 2),
        ("abcdefABC123", 3),
        ("abcdeABC123!", 4),
        ("abcdABC12!\u5bc6\u7801", 5),
        ("\U0001d49c" + "bcdefghijk!", 3),  # mathematical script capital A is uppercase
        ("\U0001f600" + "abcdefghijk", 2),  # an emoji is a symbol
        ("abc def ghij", 2),  # a space is a symbol
    ],
)
def test_character_classes(password: str, classes: int) -> None:
    assert evaluate(password, _rules(min_classes=classes), NOBODY).ok
    if classes < 5:
        assert _failed(password, _rules(min_classes=classes + 1)) == {"min_classes"}


def test_the_longest_run_of_one_character() -> None:
    rules = _rules(max_repeat=3)
    assert _failed("abcaaabcdefg", rules) == set()
    assert _failed("abcaaaabcdef", rules) == {"max_repeat"}
    # Runs are counted after NFC: a decomposed accent is one character.
    assert _failed("x" + "e\u0301" * 4 + "abcdefgh", rules) == {"max_repeat"}


def test_the_users_email_local_part_and_display_name() -> None:
    rules = _rules(forbid_user_details=True)
    context = UserContext(email="jane.citizen@example.com", display_name="Jane Q Citizen")
    assert _failed("correct horse battery", rules, context) == set()
    assert _failed("my-JANE.CITIZEN-pw", rules, context) == {"no_email", "no_display_name"}
    assert _failed("citizenkane-2026", rules, context) == {"no_email", "no_display_name"}
    # Tokens shorter than three code points are ignored ("Q").
    assert _failed("q is not a name x", rules, context) == set()
    assert _failed("only-example.com-here", rules, context) == set()


def test_user_details_are_compared_without_regard_to_case_after_nfc() -> None:
    rules = _rules(forbid_user_details=True)
    context = UserContext(email="zoe@example.org", display_name="Ren\u00e9e")
    assert _failed("I am RENE\u0301E and proud", rules, context) == {"no_display_name"}
    assert _failed("zo\u00eb is not zoe? ZOE!", rules, context) == {"no_email"}


def test_user_detail_rules_are_listed_only_when_enabled() -> None:
    context = UserContext(email="jane@example.com", display_name="Jane")
    codes = [r.code for r in evaluate("jane-jane-jane", _rules(), context).results]
    assert "no_email" not in codes and "no_display_name" not in codes


PHRASE = PassphraseRule(min_length=20, min_words=4, relaxes_classes=True)


@pytest.mark.parametrize(
    ("password", "passphrase"),
    [
        ("correct horse battery staple", True),
        ("correct-horse.battery_staple", True),
        ("correct horse batterystaple", False),  # three words
        ("a b c d", False),  # four words, too short
        ("abcd efgh ijkl mnopqr", True),  # 21 code points, four words
        ("abcd efgh ijkl mnop", False),  # 19 code points
        ("abcd  efgh   ijkl  mnop", True),  # runs of separators split once
        ("  leading and trailing  ", False),  # three words
    ],
)
def test_passphrase_boundaries(password: str, passphrase: bool) -> None:
    rules = _rules(min_length=8, passphrase=PHRASE)
    assert evaluate(password, rules, NOBODY).passphrase is passphrase


def test_a_passphrase_may_waive_the_class_rule_but_nothing_else() -> None:
    rules = _rules(min_length=8, min_classes=3, max_repeat=2, passphrase=PHRASE)
    result = evaluate("correct horse battery staple", rules, NOBODY)
    assert result.ok and result.passphrase
    classes = next(r for r in result.results if r.code == "min_classes")
    assert classes.passed and classes.waived
    assert _failed("correct horse batttery staple", rules) == {"max_repeat"}
    strict = _rules(min_length=8, min_classes=3, passphrase=PassphraseRule(20, 4, False))
    assert _failed("correct horse battery staple", strict) == {"min_classes"}


TIERS = (
    Tier(name="passphrase", passphrase=True, max_age_days=None),
    Tier(name="long", min_length=16, min_classes=3, max_age_days=365),
    Tier(name="standard", min_length=12, max_age_days=90),
)


def test_the_first_tier_met_is_the_one_recorded() -> None:
    rules = _rules(min_length=12, passphrase=PHRASE, tiers=TIERS)
    assert evaluate("correct horse battery staple", rules, NOBODY).tier == "passphrase"
    assert evaluate("Abcdefghijk1mnop", rules, NOBODY).tier == "long"
    assert evaluate("abcdefghijk1mnop", rules, NOBODY).tier == "standard"
    assert evaluate("abcdefghijkl", rules, NOBODY).tier == "standard"


def test_no_tiers_means_no_tier() -> None:
    assert evaluate("abcdefghijkl", _rules(), NOBODY).tier is None


def test_the_policy_description_round_trips() -> None:
    rules = _rules(
        min_length=12,
        max_length=64,
        min_classes=2,
        max_repeat=3,
        forbid_user_details=True,
        passphrase=PHRASE,
        tiers=TIERS,
        warning_days=7,
    )
    description = rules.describe()
    assert description["version"] == DESCRIPTION_VERSION == 1
    assert description["normalisation"] == "NFC"
    assert description["length_unit"] == "code_point"
    assert PasswordRules.from_description(description) == rules


def test_a_description_of_another_version_is_refused() -> None:
    description = _rules().describe()
    description["version"] = 2
    with pytest.raises(PasswordPolicyError):
        PasswordRules.from_description(description)


@pytest.mark.parametrize(
    "overrides",
    [
        {"min_length": 7},
        {"min_length": 1025},
        {"min_length": 20, "max_length": 19},
        {"max_length": 1025},
        {"min_classes": 6},
        {"min_classes": -1},
        {"max_repeat": 0},
        {"warning_days": 366},
        {"passphrase": PassphraseRule(min_length=0, min_words=4)},
        {"passphrase": PassphraseRule(min_length=20, min_words=1)},
        # A passphrase tier needs a passphrase rule.
        {"tiers": (Tier(name="p", passphrase=True), Tier(name="s"))},
        # Tier names are unique.
        {"tiers": (Tier(name="s", min_length=16), Tier(name="s"))},
        # Every password that passes must meet some tier, so the last is a catch-all.
        {"tiers": (Tier(name="long", min_length=16),)},
        {"min_classes": 1, "tiers": (Tier(name="two", min_classes=2),)},
        {"tiers": (Tier(name="", max_age_days=30),)},
        {"tiers": (Tier(name="s", max_age_days=0),)},
        {"tiers": tuple(Tier(name=f"t{i}") for i in range(11))},
    ],
)
def test_inconsistent_rules_are_refused(overrides: dict[str, object]) -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        _rules(**overrides).validate()
    # The message names fields and reasons, never a value a user typed.
    assert "correct horse" not in str(caught.value)


def test_a_relaxed_passphrase_lowers_the_catch_all_class_requirement() -> None:
    rules = _rules(
        min_classes=3,
        passphrase=PHRASE,
        tiers=(Tier(name="any", min_length=12, min_classes=0),),
    )
    rules.validate()
    strict = _rules(min_classes=3, tiers=(Tier(name="three", min_length=12, min_classes=3),))
    strict.validate()


def test_evaluation_never_raises_for_any_text() -> None:
    rules = _rules(min_classes=2, forbid_user_details=True, passphrase=PHRASE, tiers=TIERS)
    for text in ("", "\x00", "\ud800", "a" * 5000, "\u200b" * 20):
        evaluate(text, rules, UserContext(email="x@example.com", display_name=""))
