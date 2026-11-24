"""Browser scripts warden publishes, for a product to serve from its own static route.

warden ships no user interface and serves no file itself. This subpackage holds
the one piece of logic a browser needs to agree with the server: the password
rule evaluator (``passwordrules.js``, a classic script that defines the global
``WardenPasswordRules``). A product finds it with :func:`path` and serves it::

    from fastapi.responses import FileResponse
    import warden.static

    @app.get("/static/warden/passwordrules.js")
    async def passwordrules() -> FileResponse:
        return FileResponse(warden.static.path("passwordrules.js"), media_type="text/javascript")

The server stays the authority; the script only shows a checklist. See the
clients guide, section 18.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["names", "path"]

_DIRECTORY = Path(__file__).resolve().parent
_SCRIPTS = ("passwordrules.js",)


def names() -> tuple[str, ...]:
    """The file names of the scripts warden ships."""
    return _SCRIPTS


def path(name: str) -> Path:
    """The location of a shipped script, by its exact file name.

    Anything else (a path, a parent reference, a module of the package) raises
    ``FileNotFoundError``, so a product that passes a request value through cannot
    be led to another file.
    """
    if name not in _SCRIPTS:
        raise FileNotFoundError(f"warden ships no script named {name!r}")
    return _DIRECTORY / name
