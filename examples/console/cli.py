"""``python -m examples.console``: set up, bootstrap and run the sample console.

    python -m examples.console init --sandbox DIR [--ports-file FILE]
    python -m examples.console create-admin --config FILE --email ADDRESS
    python -m examples.console serve --config FILE [--without-mail] [--dev-clock]

``init`` writes ``<sandbox>/console.yaml`` and seeds konfig's secrets store.
``create-admin`` creates the first administrator. ``serve`` starts the app on
127.0.0.1 at the configured console port; with ``--without-mail`` it installs
no mail sender, to show how the screens follow warden's capabilities; with
``--dev-clock`` it builds ``Identity`` with a clock the Development screen can
move forward, to walk password expiry without waiting. Migrations and the signing key
come from the warden CLI, as in a product: ``warden --config FILE migrate``
and ``warden --config FILE keys rotate``.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from pathlib import Path
from typing import Any

from examples.console.app import build_console
from examples.console.bootstrap import create_administrator
from examples.console.devclock import DevClock
from examples.console.settings import (
    LoadedSettings,
    load_settings,
    read_ports,
    seed_secrets,
    write_config,
)
from warden.config import ConfigError

__all__ = ["main"]

HOST = "127.0.0.1"


def _run[T](coro: Coroutine[Any, Any, T]) -> T:
    if sys.platform == "win32":
        # psycopg's async driver cannot run on the Proactor event loop.
        return asyncio.run(coro, loop_factory=asyncio.SelectorEventLoop)
    return asyncio.run(coro)


def _dsn(loaded: LoadedSettings) -> str:
    if loaded.config.db.dsn is None:
        raise ConfigError("invalid warden configuration:\n  warden.db.dsn: is required")
    return loaded.config.db.dsn.get_secret_value()


async def _with_pool[T](loaded: LoadedSettings, work: Callable[[Any], Awaitable[T]]) -> T:
    from psycopg_pool import AsyncConnectionPool

    pool: Any = AsyncConnectionPool(_dsn(loaded), min_size=1, max_size=10, open=False)
    await pool.open(wait=True)
    try:
        return await work(pool)
    finally:
        await pool.close()


def _trust_provider_ca(loaded: LoadedSettings) -> None:
    """Make single sign-on trust the stub provider's private CA.

    warden reaches the provider through httpx, which reads ``SSL_CERT_FILE``.
    warden has no setting of its own for the provider's CA (see README.md,
    "Gaps"), so the sample sets this for its own process only.
    """
    ca_file = loaded.provider_ca_file
    if ca_file and Path(ca_file).is_file():
        os.environ["SSL_CERT_FILE"] = ca_file


def _init(args: argparse.Namespace) -> int:
    sandbox = Path(args.sandbox)
    ports = read_ports(Path(args.ports_file) if args.ports_file else sandbox / "ports.txt")
    path = write_config(sandbox, ports)
    seed_secrets(load_settings(path))
    print(f"wrote {path}")
    print("next: warden --config <that file> migrate, then keys rotate, then create-admin")
    return 0


def _create_admin(loaded: LoadedSettings, email: str, password: str | None) -> int:
    secret = password if password is not None else getpass.getpass("password: ")

    async def work(pool: Any) -> str:
        console = build_console(loaded.config, pool, loaded.secrets)
        user = await create_administrator(console.identity, email, secret)
        return str(user.id)

    user_id = _run(_with_pool(loaded, work))
    print(f"administrator {email} ({user_id})")
    return 0


def _serve(loaded: LoadedSettings, *, send_mail: bool = True, dev_clock: bool = False) -> int:
    import uvicorn

    _trust_provider_ca(loaded)

    async def work(pool: Any) -> None:
        console = build_console(
            loaded.config,
            pool,
            loaded.secrets,
            send_mail=send_mail,
            dev_clock=DevClock() if dev_clock else None,
        )
        if dev_clock:
            print("DEVELOPMENT CLOCK ON: the Development screen can move time forward")
        server = uvicorn.Server(
            uvicorn.Config(console.app, host=HOST, port=loaded.port, loop="none", lifespan="on")
        )
        print(f"warden sample console on http://localhost:{loaded.port}/")
        await server.serve()

    _run(_with_pool(loaded, work))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m examples.console",
        description="warden's sample console (local development only)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="write the sandbox configuration and seed secrets")
    init.add_argument("--sandbox", required=True, help="the sandbox directory")
    init.add_argument("--ports-file", help="name=port lines (default <sandbox>/ports.txt)")

    admin = commands.add_parser("create-admin", help="create the first administrator")
    admin.add_argument("--config", required=True)
    admin.add_argument("--email", required=True)
    admin.add_argument("--password", help="prompted for when left out")

    serve = commands.add_parser("serve", help="start the console on 127.0.0.1")
    serve.add_argument("--config", required=True)
    serve.add_argument(
        "--without-mail",
        action="store_true",
        help="install no mail sender, to see the screens disable what needs mail",
    )
    serve.add_argument(
        "--dev-clock",
        action="store_true",
        help="DEVELOPMENT ONLY: let the Development screen move time forward (password expiry)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            return _init(args)
        loaded = load_settings(Path(args.config))
        if args.command == "create-admin":
            return _create_admin(loaded, args.email, args.password)
        return _serve(loaded, send_mail=not args.without_mail, dev_clock=args.dev_clock)
    except (ConfigError, ValueError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
