"""The signed-in response body, shared by every route that issues a session.

Password sign-in, refresh, MFA completion and the single sign-on handoff all
return this body, so a product handles them the same way. A password sign-in
that must first change the password answers with the forced-change body
instead, wherever it would have issued a session. Internal to warden's
routers: not exported from ``warden.identity``.
"""

from __future__ import annotations

from typing import Any

from warden.identity.password_policy import ChangeReason
from warden.identity.service import PasswordChangeIssued, PasswordTokenPair
from warden.identity.tokens import TokenPair

__all__ = ["change_body", "session_body", "token_body"]


def token_body(pair: TokenPair, **extra: Any) -> dict[str, Any]:
    """The body for a newly issued token pair; ``extra`` fields follow the fixed ones.

    A password sign-in within its policy's warning window adds
    ``password_expires_in_days`` (ruling PW5).
    """
    body: dict[str, Any] = {
        "status": "signed_in",
        "access_token": pair.access_token,
        "token_type": "Bearer",
        "expires_in": pair.expires_in,
        "refresh_token": pair.refresh_token,
        "refresh_expires_in": pair.refresh_expires_in,
    }
    if isinstance(pair, PasswordTokenPair) and pair.password_expires_in_days is not None:
        body["password_expires_in_days"] = pair.password_expires_in_days
    return {**body, **extra}


def change_body(change: PasswordChangeIssued, **extra: Any) -> dict[str, Any]:
    """The forced-change answer (ruling PW9): no session, a challenge and the reason."""
    body: dict[str, Any] = {
        "status": "password_change_required",
        "challenge": change.token,
        "expires_in": change.expires_in,
        "reason": change.reason.value,
    }
    if change.reason is ChangeReason.WATCH_LIST:
        body["watch_list_reason"] = change.watch_list_reason
    return {**body, **extra}


def session_body(answer: TokenPair | PasswordChangeIssued, **extra: Any) -> dict[str, Any]:
    """The session, or the forced change a password sign-in must make first."""
    if isinstance(answer, PasswordChangeIssued):
        return change_body(answer, **extra)
    return token_body(answer, **extra)
