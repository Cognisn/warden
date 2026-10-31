"""Check warden's built distributions, and the installed package, before publication.

Used by the CI build job, the release workflow and ``tests/packaging``.

    python .github/scripts/check_dist.py files DIST_DIR [--version VERSION]
    python .github/scripts/check_dist.py imports

``files`` checks that DIST_DIR holds exactly one wheel and one sdist of
cognisn-warden at VERSION (by default the version in ``src/warden/__init__.py``),
that the wheel holds only the ``warden`` package and its metadata, and that the
sdist holds no ``examples`` directory anywhere. ``imports`` imports every
public module of the installed ``warden`` and fails unless it comes from an
installed copy rather than this source tree; run it from outside the checkout.
"""

from __future__ import annotations

import argparse
import email.parser
import importlib
import pkgutil
import re
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
DIST_NAME = "cognisn_warden"

WHEEL_REQUIRED = ("warden/__init__.py", "warden/py.typed")
WHEEL_LICENCES = ("licenses/LICENSE", "licenses/NOTICE")
SDIST_REQUIRED = (
    "PKG-INFO",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "src/warden/__init__.py",
    "src/warden/py.typed",
)


def source_version() -> str:
    text = (ROOT / "src" / "warden" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if match is None:
        raise SystemExit("no __version__ in src/warden/__init__.py")
    return match.group(1)


def _metadata_version(text: str) -> str | None:
    return email.parser.Parser().parsestr(text, headersonly=True).get("Version")


def wheel_problems(path: Path, version: str) -> list[str]:
    """Everything wrong with one wheel; an empty list means it is good."""
    info = f"{DIST_NAME}-{version}.dist-info"
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")]
        metadata = (
            archive.read(f"{info}/METADATA").decode("utf-8")
            if f"{info}/METADATA" in names
            else None
        )
    problems = [
        f"outside the warden package: {name}"
        for name in names
        if PurePosixPath(name).parts[0] not in ("warden", info)
    ]
    required = [*WHEEL_REQUIRED, *(f"{info}/{name}" for name in WHEEL_LICENCES)]
    problems += [f"missing: {name}" for name in required if name not in names]
    if metadata is None:
        problems.append(f"missing: {info}/METADATA")
    elif _metadata_version(metadata) != version:
        problems.append(f"metadata version {_metadata_version(metadata)}, expected {version}")
    return problems


def sdist_problems(path: Path, version: str) -> list[str]:
    """Everything wrong with one sdist; an empty list means it is good."""
    top = f"{DIST_NAME}-{version}"
    with tarfile.open(path, "r:gz") as archive:
        members = [m for m in archive.getmembers() if not m.isdir()]
        names = [m.name for m in members]
        pkg_info = next((m for m in members if m.name == f"{top}/PKG-INFO"), None)
        handle = archive.extractfile(pkg_info) if pkg_info is not None else None
        metadata = handle.read().decode("utf-8") if handle is not None else None
    problems = [f"outside {top}/: {name}" for name in names if not name.startswith(f"{top}/")]
    problems += [
        f"examples are not shipped: {name}"
        for name in names
        if "examples" in PurePosixPath(name).parts[:-1]
    ]
    problems += [f"missing: {name}" for name in SDIST_REQUIRED if f"{top}/{name}" not in names]
    if metadata is not None and _metadata_version(metadata) != version:
        problems.append(f"metadata version {_metadata_version(metadata)}, expected {version}")
    return problems


def dist_problems(directory: Path, version: str) -> list[str]:
    """Exactly one wheel and one sdist, each of them good."""
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        return [f"expected one wheel and one sdist, found {len(wheels)} and {len(sdists)}"]
    problems = [f"{wheels[0].name}: {p}" for p in wheel_problems(wheels[0], version)]
    problems += [f"{sdists[0].name}: {p}" for p in sdist_problems(sdists[0], version)]
    return problems


def import_problems(root: Path = ROOT) -> list[str]:
    """Import every public module of the installed warden, refusing one under ``root``."""
    import warden

    origin = Path(warden.__file__).resolve()
    if root.resolve() in origin.parents:
        return [f"warden imports from the source tree ({origin}), not an installed copy"]
    problems = []
    names = ["warden"]
    for module in pkgutil.walk_packages(warden.__path__, prefix="warden."):
        if not any(part.startswith("_") for part in module.name.split(".")):
            names.append(module.name)
    for name in names:
        try:
            importlib.import_module(name)
        except Exception as exc:  # report every failure, not just the first
            problems.append(f"{name}: {type(exc).__name__}: {exc}")
    print(f"imported {len(names) - len(problems)} of {len(names)} public modules")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    files = sub.add_parser("files", help="check the wheel and sdist in a directory")
    files.add_argument("directory", type=Path)
    files.add_argument("--version", help="the version expected (default: the source's)")
    sub.add_parser("imports", help="import every public module of the installed warden")
    args = parser.parse_args(argv)

    if args.command == "files":
        version = args.version or source_version()
        problems = dist_problems(args.directory, version)
    else:
        problems = import_problems()
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print("ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
