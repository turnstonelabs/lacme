"""Smoke test — verify the package imports and has a version."""

from lacme import __version__


def test_version_is_set():
    assert __version__ == "1.0.5"
