"""The signed-in response body, shared by every route that issues a session.

Password sign-in, refresh, MFA completion and the single sign-on handoff all
return this body, so a product handles them the same way. Internal to
warden's routers: not exported from ``warden.identity``.
"""

from __future__ import annotations

from typing import Any

from warden.identity.tokens import TokenPair

__all__ = ["token_body"]


def token_body(pair: TokenPair, **extra: Any) -> dict[str, Any]:
    """The body for a newly issued token pair; ``extra`` fields follow the fixed ones."""
    return {
        "status": "signed_in",
        "access_token": pair.access_token,
        "token_type": "Bearer",
        "expires_in": pair.expires_in,
        "refresh_token": pair.refresh_token,
        "refresh_expires_in": pair.refresh_expires_in,
        **extra,
    }
