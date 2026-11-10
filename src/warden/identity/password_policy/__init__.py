"""Password policies and watch lists (rulings PW0 to PW14 of 10 November 2026).

The rule engine (``evaluate``) is pure and has no I/O. The stores keep
policies, role mappings and pins, password history, per-user password
state, watch lists and forced-change challenges in warden's own schema. The
range client asks the Pwned Passwords range API about a five-character
SHA-1 prefix, only for a policy that enables it. Fingerprints are sealed
with a konfig key and rechecked on the product's schedule.

This package adds no HTTP route and changes no sign-in or set-password
behaviour: identity's flows call it. Results and errors carry identifiers,
rule codes and counts only, never a password, a hash or a hash prefix.
"""

from warden.identity.password_policy.builtin import BUILTIN_REASON, BuiltinList
from warden.identity.password_policy.errors import (
    HibpUnavailable,
    PasswordPolicyConflict,
    PasswordPolicyError,
    PasswordPolicyNotFound,
    WatchListError,
    WatchListImportError,
    WatchListNotFound,
)
from warden.identity.password_policy.fingerprint import (
    Fingerprints,
    OpenedFingerprint,
    SealedFingerprint,
    password_digest,
)
from warden.identity.password_policy.hibp import HibpRangeClient, RangeCache
from warden.identity.password_policy.rules import (
    DESCRIPTION_VERSION,
    Evaluation,
    PassphraseRule,
    PasswordRules,
    RuleCode,
    RuleResult,
    Tier,
    UserContext,
    evaluate,
)

__all__ = [
    "BUILTIN_REASON",
    "DESCRIPTION_VERSION",
    "BuiltinList",
    "Evaluation",
    "Fingerprints",
    "HibpRangeClient",
    "HibpUnavailable",
    "OpenedFingerprint",
    "PassphraseRule",
    "PasswordPolicyConflict",
    "PasswordPolicyError",
    "PasswordPolicyNotFound",
    "PasswordRules",
    "RangeCache",
    "RuleCode",
    "RuleResult",
    "SealedFingerprint",
    "Tier",
    "UserContext",
    "WatchListError",
    "WatchListImportError",
    "WatchListNotFound",
    "evaluate",
    "password_digest",
]
