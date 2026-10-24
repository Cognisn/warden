"""Packaging: one version source, typed marker, distribution metadata."""

from importlib import metadata, resources

from packaging.version import Version

import warden


def test_version_is_pep440() -> None:
    Version(warden.__version__)


def test_distribution_version_matches_package() -> None:
    assert metadata.version("cognisn-warden") == warden.__version__


def test_package_is_marked_typed() -> None:
    assert resources.files("warden").joinpath("py.typed").is_file()


def test_runtime_licence_is_apache() -> None:
    meta = metadata.metadata("cognisn-warden")
    assert meta["License-Expression"] == "Apache-2.0"
