"""The built-in common-password list (ruling PW12) ships in the wheel and the sdist,
with the README that records its source, provenance and licence."""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DATA = "warden/identity/password_policy/data/common-passwords.sha1.gz"
README = "warden/identity/password_policy/data/README.md"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("bundled")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(ROOT)],
        check=True,
        capture_output=True,
    )
    return out


def test_the_wheel_carries_the_list_and_its_readme(built: Path) -> None:
    (wheel,) = built.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        assert {DATA, README} <= names
        source = (ROOT / "src" / DATA).read_bytes()
        assert archive.read(DATA) == source


def test_the_sdist_carries_the_list_and_its_readme(built: Path) -> None:
    (sdist,) = built.glob("*.tar.gz")
    with tarfile.open(sdist) as archive:
        names = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}
    assert {f"src/{DATA}", f"src/{README}"} <= names
