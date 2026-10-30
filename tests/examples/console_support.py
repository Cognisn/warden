"""Helpers shared by the sample console's tests (imported as ``console_support``)."""

from __future__ import annotations

from typing import Any

PASSWORD = "correct horse battery staple"


def console_config(**sections: Any) -> Any:
    from warden.config import parse_config

    data: dict[str, Any] = {
        "http": {
            "public_base_url": "http://localhost:8040",
            "accept_invitation_link": "/accept?t={token}",
            "reset_password_link": "/reset?t={token}",
            "sso_completion_link": "/signed-in",
        },
        "identity": {"require_mfa": False},
        "mail": {"from_address": "console@example.com"},
        "syslog": {"enabled": True, "host": "127.0.0.1", "port": 9, "transport": "udp"},
    }
    for name, values in sections.items():
        data[name] = {**data.get(name, {}), **values}
    return parse_config(data)


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value
