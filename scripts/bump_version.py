"""Stamp warden's version.

Used only by the integration session, on a release branch:

    python scripts/bump_version.py 0.1.0a1

The version lives in one place, ``src/warden/__init__.py``; hatchling reads
it from there for the distribution metadata. The script refuses to stamp
anywhere but ``release/vX.Y.Z``, and only a version of that same release.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

INIT_PATH = Path(__file__).resolve().parents[1] / "src" / "warden" / "__init__.py"

_RELEASE_BRANCH = re.compile(r"release/v(\d+\.\d+\.\d+)")
_VERSION = re.compile(r"(\d+\.\d+\.\d+)(?:(?:a|b|rc)[1-9]\d*)?")
_VERSION_LINE = re.compile(r'^__version__ = "[^"\n]*"$', re.MULTILINE)


class StampRefused(Exception):
    """The requested stamp is not allowed."""


def stamp(version: str, *, branch: str, init_path: Path = INIT_PATH) -> None:
    """Write ``version`` into ``init_path``, or raise ``StampRefused``."""
    branch_match = _RELEASE_BRANCH.fullmatch(branch)
    if branch_match is None:
        raise StampRefused(f"refusing to stamp on {branch!r}: only release/vX.Y.Z branches")
    version_match = _VERSION.fullmatch(version)
    if version_match is None:
        raise StampRefused(f"refusing malformed version {version!r}")
    if version_match.group(1) != branch_match.group(1):
        raise StampRefused(f"version {version} does not belong to {branch}")

    text = init_path.read_text(encoding="utf-8")
    if len(_VERSION_LINE.findall(text)) != 1:
        raise StampRefused(f"{init_path} must hold exactly one __version__ line")
    # newline="\n": the repository is eol=lf, and a text-mode write on Windows emits CRLF.
    init_path.write_text(
        _VERSION_LINE.sub(f'__version__ = "{version}"', text), encoding="utf-8", newline="\n"
    )


def _current_branch() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: bump_version.py VERSION", file=sys.stderr)
        return 2
    try:
        stamp(argv[0], branch=_current_branch())
    except StampRefused as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"stamped {argv[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
