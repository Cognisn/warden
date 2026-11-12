"""The password rule engine (rulings PW3, PW4 and PW5): fixed, deterministic rules.

``evaluate(password, rules, context)`` is pure: no I/O, no clock, no
randomness, and it never raises for any text. Every rule's result carries a
stable code, so a browser can show a checklist and a refusal can name each
failed rule.

Counting. The password is normalised to NFC first, then measured in Unicode
code points. A precomposed and a decomposed accent count the same, and a
character outside the Basic Multilingual Plane (an emoji, say) counts once,
where a browser's ``String.length`` counts it twice: a browser counts with
``[...text.normalize("NFC")].length``.

Character classes, by Unicode general category of each code point:
lowercase (Ll), uppercase (Lu, Lt), digit (Nd), other letters (Lo, Lm) and
symbol (punctuation P*, symbols S* and the space separator Zs). Marks,
controls and other categories count towards length but belong to no class.

Passphrases (PW4): a password at least ``passphrase.min_length`` code points
long with at least ``passphrase.min_words`` words, where words are the
non-empty pieces left by splitting on space, hyphen-minus, full stop and
underscore. A passphrase may waive the class rule; every other rule applies.

User details: the email's local part (whole, and each piece of it) and each
word of the display name, where pieces and words are the runs of letters and
digits (categories L* and N*). Pieces shorter than three code points are
ignored. Comparison is by containment after NFC and lower-casing
(``str.lower``, which matches JavaScript's ``toLowerCase``).

Tiers (PW5): ordered, strongest first. A tier's condition is "passphrase",
or a minimum length and class count. ``evaluate`` reports the first tier the
password meets. Validation makes the last tier a catch-all, so every
password that passes the rules meets some tier.

``PasswordRules.describe()`` is the stable, versioned JSON shape a browser
evaluates; ``docs/contract/password-rule-vectors.json`` holds test cases the
engine and any client must agree on.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from warden.identity.password_policy.errors import PasswordPolicyError
from warden.identity.passwords import MAX_PASSWORD_LENGTH

__all__ = [
    "CLASS_CATEGORIES",
    "DESCRIPTION_VERSION",
    "MAX_TIERS",
    "MIN_POLICY_LENGTH",
    "PASSPHRASE_SEPARATORS",
    "USER_DETAIL_MIN_LENGTH",
    "Evaluation",
    "PassphraseRule",
    "PasswordRules",
    "RuleCode",
    "RuleResult",
    "Tier",
    "UserContext",
    "evaluate",
    "normalise",
]

DESCRIPTION_VERSION = 1
MIN_POLICY_LENGTH = 8
MAX_TIERS = 10
MAX_TIER_AGE_DAYS = 3650
MAX_WARNING_DAYS = 365
USER_DETAIL_MIN_LENGTH = 3
PASSPHRASE_SEPARATORS = (" ", "-", ".", "_")

CLASS_CATEGORIES: Mapping[str, tuple[str, ...]] = {
    "lowercase": ("Ll",),
    "uppercase": ("Lu", "Lt"),
    "digit": ("Nd",),
    "other_letter": ("Lo", "Lm"),
    "symbol": ("Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc", "Sk", "So", "Zs"),
}
_CLASS_OF = {category: name for name, cats in CLASS_CATEGORIES.items() for category in cats}


class RuleCode(StrEnum):
    """Stable codes, one per rule, in the order results are reported."""

    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    MIN_CLASSES = "min_classes"
    MAX_REPEAT = "max_repeat"
    NO_EMAIL = "no_email"
    NO_DISPLAY_NAME = "no_display_name"


@dataclass(frozen=True, slots=True)
class PassphraseRule:
    """When a password counts as a passphrase (PW4)."""

    min_length: int
    min_words: int
    relaxes_classes: bool = False


@dataclass(frozen=True, slots=True)
class Tier:
    """A change-period tier (PW5): its condition and maximum age."""

    name: str
    passphrase: bool = False
    """Met by a passphrase; ``min_length`` and ``min_classes`` are then unused."""
    min_length: int = 0
    min_classes: int = 0
    max_age_days: int | None = None
    """Days until a password in this tier must change; None means never."""


@dataclass(frozen=True, slots=True)
class UserContext:
    """What the user-detail rules compare against; both optional."""

    email: str | None = None
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class RuleResult:
    code: RuleCode
    passed: bool
    waived: bool = False
    """The class rule passed only because the password is a passphrase."""


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Each configured rule's result, whether it is a passphrase, and its tier."""

    results: tuple[RuleResult, ...]
    passphrase: bool
    tier: str | None

    @property
    def ok(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failed(self) -> tuple[RuleCode, ...]:
        return tuple(r.code for r in self.results if not r.passed)


@dataclass(frozen=True, slots=True)
class PasswordRules:
    """A policy's deterministic rules (PW3), passphrase setting (PW4) and tiers (PW5)."""

    min_length: int
    max_length: int = MAX_PASSWORD_LENGTH
    min_classes: int = 0
    max_repeat: int | None = None
    forbid_user_details: bool = False
    passphrase: PassphraseRule | None = None
    tiers: tuple[Tier, ...] = field(default=())
    warning_days: int = 14

    def validate(self) -> None:
        """Raise ``PasswordPolicyError`` naming every inconsistent field."""
        problems = _problems(self)
        if problems:
            raise PasswordPolicyError("; ".join(problems))

    def describe(self) -> dict[str, Any]:
        """The versioned JSON shape a browser evaluates."""
        return {
            "version": DESCRIPTION_VERSION,
            "normalisation": "NFC",
            "length_unit": "code_point",
            "min_length": self.min_length,
            "max_length": self.max_length,
            "min_classes": self.min_classes,
            "classes": {name: list(cats) for name, cats in CLASS_CATEGORIES.items()},
            "max_repeat": self.max_repeat,
            "forbid_user_details": self.forbid_user_details,
            "user_detail_min_length": USER_DETAIL_MIN_LENGTH,
            "passphrase": None
            if self.passphrase is None
            else {
                "min_length": self.passphrase.min_length,
                "min_words": self.passphrase.min_words,
                "separators": list(PASSPHRASE_SEPARATORS),
                "relaxes_classes": self.passphrase.relaxes_classes,
            },
            "tiers": [
                {
                    "name": t.name,
                    "passphrase": t.passphrase,
                    "min_length": t.min_length,
                    "min_classes": t.min_classes,
                    "max_age_days": t.max_age_days,
                }
                for t in self.tiers
            ],
            "warning_days": self.warning_days,
        }

    @classmethod
    def from_description(cls, description: Mapping[str, Any]) -> PasswordRules:
        """Rebuild rules from ``describe()``'s shape; refuses another version."""
        if description.get("version") != DESCRIPTION_VERSION:
            raise PasswordPolicyError(f"version must be {DESCRIPTION_VERSION}")
        try:
            phrase = description["passphrase"]
            rules = cls(
                min_length=_int(description["min_length"]),
                max_length=_int(description["max_length"]),
                min_classes=_int(description["min_classes"]),
                max_repeat=_opt_int(description["max_repeat"]),
                forbid_user_details=_bool(description["forbid_user_details"]),
                passphrase=None
                if phrase is None
                else PassphraseRule(
                    min_length=_int(phrase["min_length"]),
                    min_words=_int(phrase["min_words"]),
                    relaxes_classes=_bool(phrase["relaxes_classes"]),
                ),
                tiers=tuple(
                    Tier(
                        name=_str(t["name"]),
                        passphrase=_bool(t["passphrase"]),
                        min_length=_int(t["min_length"]),
                        min_classes=_int(t["min_classes"]),
                        max_age_days=_opt_int(t["max_age_days"]),
                    )
                    for t in description["tiers"]
                ),
                warning_days=_int(description["warning_days"]),
            )
        except (KeyError, TypeError) as exc:
            raise PasswordPolicyError("the description is not a password policy") from exc
        rules.validate()
        return rules


def _int(value: Any) -> int:
    if type(value) is not int:
        raise TypeError("not an integer")
    return value


def _opt_int(value: Any) -> int | None:
    return None if value is None else _int(value)


def _bool(value: Any) -> bool:
    if type(value) is not bool:
        raise TypeError("not a boolean")
    return value


def _str(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("not a string")
    return value


def _within(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _problems(rules: PasswordRules) -> list[str]:
    problems: list[str] = []
    if not _within(rules.min_length, MIN_POLICY_LENGTH, MAX_PASSWORD_LENGTH):
        problems.append(f"min_length must be between {MIN_POLICY_LENGTH} and {MAX_PASSWORD_LENGTH}")
    if not _within(rules.max_length, rules.min_length, MAX_PASSWORD_LENGTH):
        problems.append(f"max_length must be between min_length and {MAX_PASSWORD_LENGTH}")
    if not _within(rules.min_classes, 0, len(CLASS_CATEGORIES)):
        problems.append(f"min_classes must be between 0 and {len(CLASS_CATEGORIES)}")
    if rules.max_repeat is not None and not _within(rules.max_repeat, 1, MAX_PASSWORD_LENGTH):
        problems.append(f"max_repeat must be between 1 and {MAX_PASSWORD_LENGTH}, or unset")
    if type(rules.forbid_user_details) is not bool:
        problems.append("forbid_user_details must be true or false")
    if not _within(rules.warning_days, 0, MAX_WARNING_DAYS):
        problems.append(f"warning_days must be between 0 and {MAX_WARNING_DAYS}")
    phrase = rules.passphrase
    if phrase is not None:
        if not _within(phrase.min_length, 1, MAX_PASSWORD_LENGTH):
            problems.append(f"passphrase.min_length must be between 1 and {MAX_PASSWORD_LENGTH}")
        if not _within(phrase.min_words, 2, 64):
            problems.append("passphrase.min_words must be between 2 and 64")
        if type(phrase.relaxes_classes) is not bool:
            problems.append("passphrase.relaxes_classes must be true or false")
    problems.extend(_tier_problems(rules))
    return problems


def _tier_problems(rules: PasswordRules) -> list[str]:
    tiers = rules.tiers
    if not tiers:
        return []
    problems: list[str] = []
    if len(tiers) > MAX_TIERS:
        problems.append(f"tiers may number at most {MAX_TIERS}")
    names: set[str] = set()
    for index, tier in enumerate(tiers):
        where = f"tiers[{index}]"
        if not isinstance(tier.name, str) or not 1 <= len(tier.name) <= 64:
            problems.append(f"{where}.name must be 1 to 64 characters")
        elif any(unicodedata.category(ch)[0] == "C" for ch in tier.name):
            problems.append(f"{where}.name must not contain control characters")
        elif tier.name in names:
            problems.append(f"{where}.name must be unique")
        else:
            names.add(tier.name)
        if type(tier.passphrase) is not bool:
            problems.append(f"{where}.passphrase must be true or false")
        elif tier.passphrase and rules.passphrase is None:
            problems.append(f"{where}.passphrase needs the policy's passphrase rule")
        if not _within(tier.min_length, 0, MAX_PASSWORD_LENGTH):
            problems.append(f"{where}.min_length must be between 0 and {MAX_PASSWORD_LENGTH}")
        if not _within(tier.min_classes, 0, len(CLASS_CATEGORIES)):
            problems.append(f"{where}.min_classes must be between 0 and {len(CLASS_CATEGORIES)}")
        if tier.max_age_days is not None and not _within(tier.max_age_days, 1, MAX_TIER_AGE_DAYS):
            problems.append(f"{where}.max_age_days must be between 1 and {MAX_TIER_AGE_DAYS}")
    problems.extend(_unreached_tiers(rules))
    last = tiers[-1]
    relaxed = rules.passphrase is not None and rules.passphrase.relaxes_classes
    floor = 0 if relaxed else rules.min_classes
    if last.passphrase or last.min_length > rules.min_length or last.min_classes > floor:
        problems.append(
            "the last tier must be met by every password the rules accept:"
            " no passphrase condition, min_length at most the policy's and min_classes"
            " at most the policy's (0 when a passphrase relaxes the class rule)"
        )
    return problems


def _preempts(earlier: Tier, later: Tier, rules: PasswordRules) -> bool:
    """Whether every password meeting ``later`` also meets ``earlier``, so ``later`` is unused."""
    if earlier.passphrase:
        return later.passphrase
    if later.passphrase:
        # A passphrase is at least the passphrase length, with any number of classes.
        phrase = rules.passphrase
        return (
            phrase is not None
            and earlier.min_classes <= 0
            and earlier.min_length <= phrase.min_length
        )
    return earlier.min_length <= later.min_length and earlier.min_classes <= later.min_classes


def _unreached_tiers(rules: PasswordRules) -> list[str]:
    """Tiers are ordered strongest first: a tier an earlier one always pre-empts is refused."""
    tiers = rules.tiers
    if not all(_well_formed(t) for t in tiers):
        return []
    return [
        f"tiers[{index}] is never reached: an earlier tier accepts every password it does,"
        " so order tiers strongest first"
        for index, later in enumerate(tiers)
        if any(_preempts(earlier, later, rules) for earlier in tiers[:index])
    ]


def _well_formed(tier: Tier) -> bool:
    return (
        type(tier.passphrase) is bool
        and type(tier.min_length) is int
        and type(tier.min_classes) is int
    )


def normalise(password: str) -> str:
    """NFC, as every rule and the watch-list terms see the password."""
    try:
        return unicodedata.normalize("NFC", password)
    except (TypeError, ValueError):
        return password


def _classes(text: str) -> int:
    return len({_CLASS_OF.get(unicodedata.category(ch)) for ch in text} - {None})


def _longest_run(text: str) -> int:
    longest = run = 0
    previous = ""
    for ch in text:
        run = run + 1 if ch == previous else 1
        previous = ch
        longest = max(longest, run)
    return longest


def _words(text: str) -> int:
    count = 0
    in_word = False
    for ch in text:
        if ch in PASSPHRASE_SEPARATORS:
            in_word = False
        elif not in_word:
            in_word = True
            count += 1
    return count


def _pieces(text: str) -> list[str]:
    """Runs of letters and digits."""
    pieces: list[str] = []
    current: list[str] = []
    for ch in text:
        if unicodedata.category(ch)[0] in ("L", "N"):
            current.append(ch)
        elif current:
            pieces.append("".join(current))
            current = []
    if current:
        pieces.append("".join(current))
    return pieces


def _detail_tokens(text: str | None, *, whole: bool) -> set[str]:
    if not text:
        return set()
    lowered = normalise(text).lower()
    tokens = set(_pieces(lowered))
    if whole:
        tokens.add(lowered)
    return {t for t in tokens if len(t) >= USER_DETAIL_MIN_LENGTH}


def _local_part(email: str | None) -> str | None:
    if not email or "@" not in email:
        return email
    return email.rpartition("@")[0]


def _meets(tier: Tier, length: int, classes: int, passphrase: bool) -> bool:
    if tier.passphrase:
        return passphrase
    return length >= tier.min_length and classes >= tier.min_classes


def evaluate(password: str, rules: PasswordRules, context: UserContext) -> Evaluation:
    """Each rule's result, whether ``password`` is a passphrase, and the first tier it meets."""
    text = normalise(password)
    length = len(text)
    classes = _classes(text)
    phrase = rules.passphrase
    passphrase = (
        phrase is not None and length >= phrase.min_length and _words(text) >= phrase.min_words
    )
    results = [
        RuleResult(RuleCode.MIN_LENGTH, length >= rules.min_length),
        RuleResult(RuleCode.MAX_LENGTH, length <= rules.max_length),
    ]
    if rules.min_classes > 0:
        enough = classes >= rules.min_classes
        waived = not enough and passphrase and phrase is not None and phrase.relaxes_classes
        results.append(RuleResult(RuleCode.MIN_CLASSES, enough or waived, waived=waived))
    if rules.max_repeat is not None:
        results.append(RuleResult(RuleCode.MAX_REPEAT, _longest_run(text) <= rules.max_repeat))
    if rules.forbid_user_details:
        lowered = text.lower()
        email = _detail_tokens(_local_part(context.email), whole=True)
        name = _detail_tokens(context.display_name, whole=False)
        results.append(RuleResult(RuleCode.NO_EMAIL, not any(t in lowered for t in email)))
        results.append(RuleResult(RuleCode.NO_DISPLAY_NAME, not any(t in lowered for t in name)))
    tier = next((t.name for t in rules.tiers if _meets(t, length, classes, passphrase)), None)
    return Evaluation(results=tuple(results), passphrase=passphrase, tier=tier)
