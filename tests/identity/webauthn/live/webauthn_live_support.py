"""The live WebAuthn check's application, server and browser.

Imported as ``webauthn_live_support``.

- ``live_app``: a test-only FastAPI application mounting warden's auth,
  lifecycle and administration routers, and serving the page in ``page/``
  under a content security policy that admits no inline script.
- ``LiveServer``: a small HTTP/1.1 server on 127.0.0.1 that hands each
  request to that application. It runs on the test's own event loop, beside
  the database pool, so nothing crosses loops but bytes on a socket.
- ``LiveBrowser``: Chromium through Playwright, with virtual authenticators
  from the DevTools WebAuthn domain. Playwright runs on its own thread and
  event loop (on Windows the Proactor loop, which it needs for its driver,
  while psycopg needs the Selector loop).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import sys
import threading
from collections.abc import Coroutine
from pathlib import Path
from types import TracebackType
from typing import Any, Self, TypeVar

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse
from identity_support import RecordingSender

from warden.config import WardenConfig, parse_config
from warden.identity import Identity

T = TypeVar("T")

PAGE = Path(__file__).parent / "page"

# The page's own files only: no inline script, no other origin.
CSP = (
    "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# A USB security key without a PIN or built-in verification, which keeps no
# resident key: a second factor only.
SECURITY_KEY: dict[str, Any] = {
    "protocol": "ctap2",
    "transport": "usb",
    "hasResidentKey": False,
    "hasUserVerification": False,
    "isUserVerified": False,
    "automaticPresenceSimulation": True,
}

# A platform authenticator that keeps resident keys and verifies the user: a passkey.
PASSKEY: dict[str, Any] = {
    "protocol": "ctap2",
    "transport": "internal",
    "hasResidentKey": True,
    "hasUserVerification": True,
    "isUserVerified": True,
    "automaticPresenceSimulation": True,
}


def live_config(port: int) -> WardenConfig:
    """The relying party is ``localhost``; the one allowed origin is the page's."""
    origin = f"http://localhost:{port}"
    return parse_config(
        {
            "http": {
                "public_base_url": origin,
                "accept_invitation_link": f"{origin}/invitation?t={{token}}",
                "reset_password_link": f"{origin}/reset?t={{token}}",
                "passkey_registration_link": f"{origin}/passkey?t={{token}}",
            },
            "identity": {"require_mfa": False},
            "webauthn": {
                "rp_id": "localhost",
                "rp_name": "warden live check",
                "allowed_origins": origin,
            },
        }
    )


def live_app(identity: Identity) -> FastAPI:
    application = FastAPI()
    identity.install(application)
    application.include_router(identity.auth_router(), prefix="/auth")
    application.include_router(identity.lifecycle_router(), prefix="/auth")
    application.include_router(identity.admin_router(permission="users.manage"), prefix="/admin")
    headers = {"content-security-policy": CSP, "cache-control": "no-store"}

    @application.get("/", include_in_schema=False)
    @application.get("/invitation", include_in_schema=False)
    @application.get("/passkey", include_in_schema=False)
    async def page() -> FileResponse:
        return FileResponse(PAGE / "index.html", media_type="text/html", headers=headers)

    @application.get("/ceremony.js", include_in_schema=False)
    async def script() -> FileResponse:
        return FileResponse(PAGE / "ceremony.js", media_type="text/javascript", headers=headers)

    return application


def mail_link(mail: RecordingSender, index: int = -1) -> str:
    """The link in a sent message (the live links are ``http://localhost:<port>/...?t=``)."""
    return next(
        line.strip() for line in mail.sent[index].text.splitlines() if "?t=" in line
    ).rstrip(".")


# The server.

_HOP_BY_HOP = frozenset(
    {"connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding", "host"}
)


class LiveServer:
    """HTTP/1.1 on 127.0.0.1, one request per connection, handed to an ASGI app."""

    def __init__(self, app: FastAPI, port: int) -> None:
        self.app = app
        self.port = port
        self.origin = f"http://localhost:{port}"
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def __aenter__(self) -> Self:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", self.port)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        assert self._server is not None
        self._server.close()
        for writer in list(self._writers):
            writer.close()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._server.wait_closed(), 5)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            async with asyncio.timeout(30):
                head = await reader.readuntil(b"\r\n\r\n")
                request_line, *lines = head.decode("latin-1").split("\r\n")
                method, target, _ = request_line.split(" ", 2)
                headers = [
                    (name.strip(), value.strip())
                    for name, _, value in (line.partition(":") for line in lines if line)
                ]
                length = next((int(v) for k, v in headers if k.lower() == "content-length"), 0)
                body = await reader.readexactly(length) if length else b""
            peer = writer.get_extra_info("peername")
            transport = httpx.ASGITransport(app=self.app, client=(peer[0], peer[1]))
            async with httpx.AsyncClient(transport=transport, base_url=self.origin) as client:
                response = await client.request(
                    method,
                    target,
                    headers=[(k, v) for k, v in headers if k.lower() not in _HOP_BY_HOP],
                    content=body,
                )
            status = f"HTTP/1.1 {response.status_code} {response.reason_phrase}"
            out = [status]
            out += [f"{k}: {v}" for k, v in response.headers.multi_items() if k not in _HOP_BY_HOP]
            out += [f"content-length: {len(response.content)}", "connection: close", "", ""]
            writer.write("\r\n".join(out).encode("latin-1") + response.content)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            pass  # A speculative connection the browser opened and never used.
        finally:
            self._writers.discard(writer)
            writer.close()


# The browser.


def _b64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class LiveBrowser:
    """Chromium with one page, its DevTools session and its virtual authenticators."""

    def __init__(self, origin: str) -> None:
        self.origin = origin
        self._loop = (
            asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
        )
        self._thread = threading.Thread(target=self._loop.run_forever, name="playwright")
        self._seq = 0
        self._playwright: Any = None
        self._browser: Any = None
        self._page: Any = None
        self._cdp: Any = None

    async def _run(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run a coroutine on the browser's loop and wait for it from the test's loop."""
        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(coro, self._loop))

    async def __aenter__(self) -> Self:
        self._thread.start()
        await self._run(self._start())
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            await self._run(self._stop())
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(10)
            self._loop.close()

    async def _start(self) -> None:
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch()
        self._page = await self._browser.new_page()
        self._cdp = await self._page.context.new_cdp_session(self._page)
        await self._cdp.send("WebAuthn.enable", {"enableUI": False})

    async def _stop(self) -> None:
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    # Virtual authenticators.

    async def add_authenticator(self, options: dict[str, Any]) -> str:
        answer = await self._run(
            self._cdp.send("WebAuthn.addVirtualAuthenticator", {"options": options})
        )
        return str(answer["authenticatorId"])

    async def remove_authenticator(self, authenticator: str) -> None:
        await self._run(
            self._cdp.send(
                "WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator}
            )
        )

    async def set_user_verified(self, authenticator: str, *, verified: bool) -> None:
        await self._run(
            self._cdp.send(
                "WebAuthn.setUserVerified",
                {"authenticatorId": authenticator, "isUserVerified": verified},
            )
        )

    async def credentials(self, authenticator: str) -> list[dict[str, Any]]:
        """What the authenticator holds: the credential id, residency and signature count."""
        answer = await self._run(
            self._cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator})
        )
        held = []
        for credential in answer["credentials"]:
            raw = _b64(credential["credentialId"])
            held.append(
                {
                    "credential_id": raw,
                    "id": _b64url(raw),
                    "is_resident": credential["isResidentCredential"],
                    "sign_count": credential["signCount"],
                }
            )
        return held

    # The page.

    async def open(self, path: str) -> None:
        await self._run(self._open(path))

    async def _open(self, path: str) -> None:
        await self._page.goto(self.origin + path)
        await self._page.wait_for_selector("#outcome[data-ready='yes']", state="attached")
        self._seq = 0

    async def act(self, action: str, **fields: str) -> dict[str, Any]:
        """Fill the named fields, press the action's button and read what the page saw."""
        return await self._run(self._act(action, fields))

    async def _act(self, action: str, fields: dict[str, str]) -> dict[str, Any]:
        for name, value in fields.items():
            await self._page.fill(f"#{name}", value)
        await self._page.click(f"#{action}")
        self._seq += 1
        await self._page.wait_for_selector(
            f"#outcome[data-seq='{self._seq}']", state="attached", timeout=30_000
        )
        outcome: dict[str, Any] = json.loads(await self._page.text_content("#outcome") or "{}")
        assert outcome["action"] == action, outcome
        return outcome
