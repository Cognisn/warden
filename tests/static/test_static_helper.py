"""``warden.static.path`` locates the scripts warden ships, for a product to serve."""

from __future__ import annotations

from pathlib import Path

import pytest

import warden.static


def test_path_returns_the_packaged_script() -> None:
    found = warden.static.path("passwordrules.js")
    assert isinstance(found, Path)
    assert found.is_file()
    assert found.parent == Path(warden.static.__file__).parent


def test_names_lists_what_ships() -> None:
    assert warden.static.names() == ("passwordrules.js",)


@pytest.mark.parametrize(
    "name",
    ["../config.py", r"..\config.py", "sub/passwordrules.js", "", ".", "__init__.py", "x.js"],
)
def test_path_refuses_anything_that_is_not_a_shipped_script(name: str) -> None:
    with pytest.raises(FileNotFoundError):
        warden.static.path(name)
