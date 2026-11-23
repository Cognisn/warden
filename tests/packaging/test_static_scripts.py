"""The browser rules ship in the wheel and the sdist; the sample console's copy does not exist."""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = "warden/static/passwordrules.js"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("static")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(ROOT)],
        check=True,
        capture_output=True,
    )
    return out


def test_the_wheel_carries_the_script_and_its_package(built: Path) -> None:
    (wheel,) = built.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        assert {SCRIPT, "warden/static/__init__.py"} <= names
        source = (ROOT / "src" / SCRIPT).read_bytes()
        assert archive.read(SCRIPT) == source
    assert not [n for n in names if n.endswith(".js") and n != SCRIPT], names


def test_the_sdist_carries_the_script(built: Path) -> None:
    (sdist,) = built.glob("*.tar.gz")
    with tarfile.open(sdist) as archive:
        names = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}
    assert f"src/{SCRIPT}" in names
    assert not [n for n in names if n.startswith("examples/") or "/examples/" in n], names


def test_the_console_has_no_copy_of_the_script() -> None:
    assert not (ROOT / "examples" / "console" / "static" / "js" / "passwordrules.js").exists()
