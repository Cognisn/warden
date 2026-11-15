"""The sample console's screens in a real browser (marked ``integration``).

Chromium, driven by Playwright, loads the console's own page and scripts from
a live server on 127.0.0.1 and walks screens the way a person does, so a
screen that draws itself wrongly fails here although every route it calls
answers correctly. Covered: the forced-enrolment card (an account that must
set up a second factor: the authenticator route and the security key route),
the authenticator set-up on the Account screen, and the Account screen's
text.

    WARDEN_IT_CONSOLE_PORT   a free port in the slot's own block

Install Chromium for Playwright first (``python -m playwright install
chromium``; see CLAUDE.md). The page loads as ``http://localhost:<port>``,
so the relying party ID is ``localhost``.
"""

from __future__ import annotations

import base64
import os
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from console_support import PASSWORD, make_user

TESTS = Path(__file__).resolve().parents[1]
for extra in (TESTS / "identity", TESTS / "identity" / "webauthn" / "live"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from webauthn_live_support import SECURITY_KEY, LiveBrowser, LiveServer  # noqa: E402

pytestmark = [pytest.mark.integration, pytest.mark.db]

PORT_TEXT = os.environ.get("WARDEN_IT_CONSOLE_PORT")

if not PORT_TEXT:
    pytest.skip("live console check not configured", allow_module_level=True)

assert PORT_TEXT
PORT = int(PORT_TEXT)
ORIGIN = f"http://localhost:{PORT}"
WAIT = 15_000


class ConsoleBrowser(LiveBrowser):
    """What a person does on the console's page, by what the page shows."""

    async def goto(self, path: str = "/") -> None:
        async def run() -> None:
            await self._page.goto(self.origin + path)
            await self._page.wait_for_selector("#screen h2", timeout=WAIT)

        await self._run(run())

    async def fill(self, label: str, value: str) -> None:
        async def run() -> None:
            await self._page.get_by_label(label, exact=True).first.fill(value)

        await self._run(run())

    async def press(self, name: str) -> None:
        async def run() -> None:
            await self._page.get_by_role("button", name=name, exact=True).click()

        await self._run(run())

    async def see(self, text: str) -> None:
        """Wait until the screen shows ``text``."""

        async def run() -> None:
            await self._page.get_by_text(text, exact=False).first.wait_for(timeout=WAIT)

        await self._run(run())

    async def screen(self) -> str:
        async def run() -> str:
            return str(await self._page.inner_text("#screen"))

        return await self._run(run())

    async def loose_text(self) -> list[str]:
        """Text that sits straight under the screen, outside any element."""

        async def run() -> list[str]:
            found = await self._page.evaluate(
                "[...document.getElementById('screen').childNodes]"
                ".filter((n) => n.nodeType === 3).map((n) => n.data.trim()).filter(Boolean)"
            )
            return [str(t) for t in found]

        return await self._run(run())

    async def texts(self, selector: str) -> list[str]:
        async def run() -> list[str]:
            return [str(t) for t in await self._page.locator(selector).all_inner_texts()]

        return await self._run(run())


@pytest.fixture
async def required(make_console: Any) -> Any:
    """A console that makes every account set up a second factor."""
    return await make_console(http={"public_base_url": ORIGIN}, identity={"require_mfa": True})


@pytest.fixture
async def open_console(make_console: Any) -> Any:
    """A console that does not."""
    return await make_console(http={"public_base_url": ORIGIN})


@asynccontextmanager
async def serve(console: Any) -> AsyncIterator[ConsoleBrowser]:
    async with LiveServer(console.app, PORT) as server, ConsoleBrowser(server.origin) as browser:
        yield browser


@pytest.fixture
async def forced(required: Any) -> AsyncIterator[ConsoleBrowser]:
    await make_user(required, "dana@example.com", "editor")
    async with serve(required) as browser:
        yield browser


@pytest.fixture
async def plain(open_console: Any) -> AsyncIterator[ConsoleBrowser]:
    await make_user(open_console, "erin@example.com", "editor")
    async with serve(open_console) as browser:
        yield browser


async def sign_in(browser: ConsoleBrowser, email: str) -> None:
    await browser.goto("/#/signin")
    await browser.fill("Email", email)
    await browser.fill("Password", PASSWORD)
    await browser.press("Sign in")


def code_for(secret: str) -> str:
    from warden.identity.totp import code_at, step_for

    key = base64.b32decode(secret.strip() + "=" * (-len(secret.strip()) % 8))
    return code_at(key, step_for(time.time()))


async def enrol_authenticator(browser: ConsoleBrowser, begin: str) -> None:
    """From the button that starts it to the recovery codes, the screens a person sees."""
    await browser.press(begin)
    await browser.see("Secret (base32)")
    await browser.see("Code from the app")
    secret = (await browser.texts("pre"))[-1]
    await browser.fill("Code from the app", code_for(secret))
    await browser.press("Confirm")
    await browser.see("Enrolled.")
    shown = await browser.screen()
    assert shown.count("Enrolled.") == 1
    assert shown.count("Keep these recovery codes somewhere safe") == 1
    assert len(await browser.texts(".codes div")) > 0


async def test_forced_enrolment_with_an_authenticator_app(forced: ConsoleBrowser) -> None:
    await sign_in(forced, "dana@example.com")
    await forced.see("Set up a second factor")
    await enrol_authenticator(forced, "Set up an authenticator app instead")
    await forced.see("Continue to your account")


async def test_forced_enrolment_with_a_security_key(forced: ConsoleBrowser) -> None:
    await forced.add_authenticator(SECURITY_KEY)
    await sign_in(forced, "dana@example.com")
    await forced.see("Set up a second factor")
    await forced.fill("Nickname (optional)", "Blue key")
    await forced.press("Register a security key or passkey")
    await forced.see("Registered Blue key.")
    shown = await forced.screen()
    assert shown.count("Keep these recovery codes somewhere safe") == 1
    assert len(await forced.texts(".codes div")) > 0


async def test_the_account_screen_sets_up_an_authenticator(plain: ConsoleBrowser) -> None:
    await sign_in(plain, "erin@example.com")
    await plain.see("Authenticator (TOTP)")
    await enrol_authenticator(plain, "Set up an authenticator")


async def test_the_account_screen_shows_no_stray_null(plain: ConsoleBrowser) -> None:
    await sign_in(plain, "erin@example.com")
    await plain.see("Authenticator (TOTP)")
    assert await plain.loose_text() == []
    assert (await plain.screen()).startswith("Account")
