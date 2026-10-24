"""The version script stamps only on a matching release branch."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bump_version.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bump_version", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["bump_version"] = module
    spec.loader.exec_module(module)
    return module


bump = _load()


@pytest.fixture
def init_file(tmp_path: Path) -> Path:
    path = tmp_path / "__init__.py"
    path.write_text('"""Doc."""\n\n__version__ = "0.1.0.dev0"\n\n__all__ = ["__version__"]\n')
    return path


def test_stamps_prerelease_on_release_branch(init_file: Path) -> None:
    bump.stamp("0.1.0a1", branch="release/v0.1.0", init_path=init_file)
    assert '__version__ = "0.1.0a1"\n' in init_file.read_text()
    assert init_file.read_text().count("__version__ =") == 1


@pytest.mark.parametrize("branch", ["main", "feat/0.1.0-foundation", "HEAD", "release/v0.1.0x"])
def test_refuses_off_a_release_branch(init_file: Path, branch: str) -> None:
    before = init_file.read_text()
    with pytest.raises(bump.StampRefused):
        bump.stamp("0.1.0a1", branch=branch, init_path=init_file)
    assert init_file.read_text() == before


def test_refuses_version_for_another_release(init_file: Path) -> None:
    with pytest.raises(bump.StampRefused):
        bump.stamp("0.2.0a1", branch="release/v0.1.0", init_path=init_file)


@pytest.mark.parametrize(
    "version", ["0.1.0a1\n", "0.1.0-a1", "v0.1.0", "0.1", "0.1.0a", "0.1.0.dev1"]
)
def test_refuses_malformed_versions(init_file: Path, version: str) -> None:
    with pytest.raises(bump.StampRefused):
        bump.stamp(version, branch="release/v0.1.0", init_path=init_file)


@pytest.mark.parametrize("version", ["0.1.0", "0.1.0a2", "0.1.0b1", "0.1.0rc1"])
def test_accepts_release_forms(init_file: Path, version: str) -> None:
    bump.stamp(version, branch="release/v0.1.0", init_path=init_file)
    assert f'__version__ = "{version}"' in init_file.read_text()


def test_refuses_file_without_exactly_one_version_line(tmp_path: Path) -> None:
    path = tmp_path / "__init__.py"
    path.write_text('__version__ = "0.1.0"\n__version__ = "0.1.0"\n')
    with pytest.raises(bump.StampRefused):
        bump.stamp("0.1.0a1", branch="release/v0.1.0", init_path=path)
