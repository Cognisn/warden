"""Answer bodies shared by the administration and self-service routes.

Internal to warden's routers: not exported from ``warden.identity``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from warden.identity.sign_in_settings import SecondFactorKind, SignInMethodState, SignInSettings
from warden.identity.users import User

__all__ = ["allowed_factors", "iso", "method_state", "settings_body", "user_body"]


def iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat()


def method_state(state: SignInMethodState) -> dict[str, Any]:
    """A user's own setting, the method in force and any pending change."""
    pending = state.pending
    return {
        "setting": None if state.setting is None else state.setting.value,
        "effective": state.effective.value,
        "pending": None
        if pending is None
        else {
            "from": pending.from_method.value,
            "to": pending.to_method.value,
            "requested_at": iso(pending.requested_at),
            "link": None if pending.link is None else pending.link.value,
            "link_sent_at": iso(pending.link_sent_at),
        },
    }


def allowed_factors(settings: SignInSettings) -> list[str]:
    """The allowed second factors in their fixed order: TOTP, then passkey."""
    return [kind.value for kind in SecondFactorKind if kind in settings.allowed_second_factors]


def settings_body(settings: SignInSettings) -> dict[str, Any]:
    return {
        "default_sign_in_method": settings.default_sign_in_method.value,
        "allowed_second_factors": allowed_factors(settings),
        "updated_at": iso(settings.updated_at),
        "updated_by": settings.updated_by,
    }


def user_body(user: User) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "status": user.status.value,
        "sign_in_method": user.sign_in_method.value,
        "has_password": user.has_password,
        "created_at": iso(user.created_at),
        "updated_at": iso(user.updated_at),
    }
