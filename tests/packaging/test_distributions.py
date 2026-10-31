"""The built distributions hold what is published, and nothing else.

The wheel carries only the ``warden`` package and its metadata. The sdist
carries no ``examples/`` directory anywhere: the sample console is for local
development and is not part of the package (design D3). The checks are the
ones the CI build job and the release workflow run
(``.github/scripts/check_dist.py``), so the test and the pipeline cannot
disagree about what a good distribution is.
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

import warden

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "check_dist.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_dist", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_dist"] = module
    spec.loader.exec_module(module)
    return module


check_dist = _load()
VERSION = warden.__version__


@pytest.fixture(scope="module")
def dist(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """The sdist, and the wheel built from it, as the release workflow builds them."""
    out = tmp_path_factory.mktemp("dist")
    # --no-isolation: build with the installed hatchling instead of fetching it.
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(ROOT)],
        check=True,
        capture_output=True,
    )
    yield out


@pytest.fixture(scope="module")
def source_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A wheel built straight from the source tree, as `python -m build --wheel` does."""
    out = tmp_path_factory.mktemp("wheel")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--outdir",
            str(out),
            str(ROOT),
        ],
        check=True,
        capture_output=True,
    )
    return _only(out, "*.whl")


def _only(directory: Path, pattern: str) -> Path:
    found = sorted(directory.glob(pattern))
    assert len(found) == 1, found
    return found[0]


def test_the_wheel_holds_only_the_warden_package(dist: Path) -> None:
    assert check_dist.wheel_problems(_only(dist, "*.whl"), VERSION) == []


def test_a_wheel_built_from_source_holds_only_the_warden_package(source_wheel: Path) -> None:
    # The release builds the wheel from the sdist, which has no examples to leak;
    # a wheel built from the checkout must be just as clean.
    assert check_dist.wheel_problems(source_wheel, VERSION) == []


def test_the_sdist_holds_no_examples(dist: Path) -> None:
    assert check_dist.sdist_problems(_only(dist, "*.tar.gz"), VERSION) == []


def test_the_directory_check_passes_on_the_build(dist: Path) -> None:
    assert check_dist.dist_problems(dist, VERSION) == []


def test_the_wheel_carries_the_package_version(dist: Path) -> None:
    wheel = _only(dist, "*.whl")
    assert wheel.name.startswith(f"cognisn_warden-{VERSION}-")


# The checks themselves must be able to fail: each is shown a distribution
# with exactly the defect it exists to catch.


def _wheel(
    tmp_path: Path, names: list[str], version: str = VERSION, declared: str | None = None
) -> Path:
    """A wheel at ``version`` whose METADATA declares ``declared`` (by default the same)."""
    path = tmp_path / f"cognisn_warden-{version}-py3-none-any.whl"
    info = f"cognisn_warden-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "")
        archive.writestr(
            f"{info}/METADATA", f"Metadata-Version: 2.4\nVersion: {declared or version}\n"
        )
    return path


def _sdist(
    tmp_path: Path, names: list[str], version: str = VERSION, declared: str | None = None
) -> Path:
    """An sdist at ``version`` whose PKG-INFO declares ``declared`` (by default the same)."""
    path = tmp_path / f"cognisn_warden-{version}.tar.gz"
    top = f"cognisn_warden-{version}"
    with tarfile.open(path, "w:gz") as archive:
        for name in [*names, "PKG-INFO"]:
            member = tarfile.TarInfo(f"{top}/{name}")
            data = (
                f"Metadata-Version: 2.4\nVersion: {declared or version}\n".encode()
                if name == "PKG-INFO"
                else b""
            )
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return path


GOOD_WHEEL = [
    "warden/__init__.py",
    "warden/py.typed",
    f"cognisn_warden-{VERSION}.dist-info/licenses/LICENSE",
    f"cognisn_warden-{VERSION}.dist-info/licenses/NOTICE",
]
GOOD_SDIST = [
    "src/warden/__init__.py",
    "src/warden/py.typed",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
]


def test_a_minimal_good_wheel_and_sdist_pass(tmp_path: Path) -> None:
    assert check_dist.wheel_problems(_wheel(tmp_path, GOOD_WHEEL), VERSION) == []
    assert check_dist.sdist_problems(_sdist(tmp_path, GOOD_SDIST), VERSION) == []


@pytest.mark.parametrize(
    "extra",
    ["examples/console/app.py", "tests/conftest.py", "warden_extra/x.py", "top.py"],
)
def test_a_wheel_with_anything_outside_warden_fails(tmp_path: Path, extra: str) -> None:
    problems = check_dist.wheel_problems(_wheel(tmp_path, [*GOOD_WHEEL, extra]), VERSION)
    assert any(extra in p for p in problems), problems


@pytest.mark.parametrize(
    "extra",
    ["examples/console/app.py", "tests/examples/test_console_app.py", "docs/examples/x.md"],
)
def test_an_sdist_with_examples_anywhere_fails(tmp_path: Path, extra: str) -> None:
    problems = check_dist.sdist_problems(_sdist(tmp_path, [*GOOD_SDIST, extra]), VERSION)
    assert any(extra in p for p in problems), problems


@pytest.mark.parametrize("missing", ["warden/py.typed", GOOD_WHEEL[2], GOOD_WHEEL[3]])
def test_a_wheel_missing_a_required_file_fails(tmp_path: Path, missing: str) -> None:
    names = [n for n in GOOD_WHEEL if n != missing]
    assert check_dist.wheel_problems(_wheel(tmp_path, names), VERSION)


@pytest.mark.parametrize("missing", ["LICENSE", "NOTICE", "src/warden/py.typed"])
def test_an_sdist_missing_a_required_file_fails(tmp_path: Path, missing: str) -> None:
    names = [n for n in GOOD_SDIST if n != missing]
    assert check_dist.sdist_problems(_sdist(tmp_path, names), VERSION)


def test_a_version_other_than_the_expected_one_fails(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path, [n.replace(VERSION, "9.9.9") for n in GOOD_WHEEL], "9.9.9")
    sdist = _sdist(tmp_path, GOOD_SDIST, "9.9.9")
    assert check_dist.wheel_problems(wheel, VERSION)
    assert check_dist.sdist_problems(sdist, VERSION)


def test_metadata_declaring_another_version_fails(tmp_path: Path) -> None:
    # Right file names, wrong version inside: only the metadata check sees it.
    wheel = check_dist.wheel_problems(_wheel(tmp_path, GOOD_WHEEL, declared="9.9.9"), VERSION)
    sdist = check_dist.sdist_problems(_sdist(tmp_path, GOOD_SDIST, declared="9.9.9"), VERSION)
    assert wheel == [f"metadata version 9.9.9, expected {VERSION}"]
    assert sdist == [f"metadata version 9.9.9, expected {VERSION}"]


def test_a_directory_with_two_wheels_or_no_sdist_fails(tmp_path: Path) -> None:
    _wheel(tmp_path, GOOD_WHEEL)
    assert check_dist.dist_problems(tmp_path, VERSION)  # no sdist
    _sdist(tmp_path, GOOD_SDIST)
    assert check_dist.dist_problems(tmp_path, VERSION) == []
    (tmp_path / "cognisn_warden-0.0.1-py3-none-any.whl").write_bytes(b"")
    assert check_dist.dist_problems(tmp_path, VERSION)  # two wheels


# The import check: every public module imports, from an installed copy only.


def test_every_public_module_imports(tmp_path: Path) -> None:
    # Any root but the checkout, so the source-tree refusal does not apply here.
    assert check_dist.import_problems(root=tmp_path) == []


def test_the_import_check_refuses_the_source_tree() -> None:
    if ROOT not in Path(warden.__file__).resolve().parents:
        pytest.skip("warden is not installed from this checkout")
    problems = check_dist.import_problems()
    assert len(problems) == 1 and "source tree" in problems[0], problems


def test_the_import_check_reports_a_module_that_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = check_dist.importlib.import_module

    def failing(name: str) -> ModuleType:
        if name == "warden.jwks":
            raise ImportError("simulated")
        return real(name)

    monkeypatch.setattr(check_dist.importlib, "import_module", failing)
    problems = check_dist.import_problems(root=tmp_path)
    assert problems == ["warden.jwks: ImportError: simulated"]
