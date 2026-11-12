"""The signed-in body every route that issues a session returns."""

from __future__ import annotations

import json
import uuid

from warden.identity import TokenPair
from warden.identity.http import json_response
from warden.identity.routers.tokens import token_body

PAIR = TokenPair(
    access_token="access-dev-only",
    expires_in=900,
    refresh_token="refresh-dev-only",
    refresh_expires_in=86_400,
    session_id=uuid.UUID(int=1),
)


def test_the_body_has_fixed_fields_in_a_fixed_order() -> None:
    body = token_body(PAIR)
    assert list(body) == [
        "status",
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "refresh_expires_in",
    ]
    assert json_response(body).body == (
        b'{"status":"signed_in","access_token":"access-dev-only","token_type":"Bearer",'
        b'"expires_in":900,"refresh_token":"refresh-dev-only","refresh_expires_in":86400}'
    )


def test_extra_fields_follow_the_fixed_ones() -> None:
    body = token_body(PAIR, recovery_codes=["a", "b"])
    assert list(body)[-1] == "recovery_codes"
    assert json.loads(json_response(body).body)["recovery_codes"] == ["a", "b"]


def test_the_session_id_is_never_in_the_body() -> None:
    assert str(PAIR.session_id) not in json.dumps(token_body(PAIR))
