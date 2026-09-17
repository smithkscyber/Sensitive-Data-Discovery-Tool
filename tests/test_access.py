"""Tests for server-side path confinement.

The web UI takes a folder path from whoever can reach the page. Unrestricted,
``/etc`` and a user's home directory are one text box away and the tool would
read them and render what it found.

The CLI is deliberately *not* confined: someone running it already has whatever
access their shell has, and fencing that in would be theatre rather than
security. These tests cover the UI's path, which is the one that faces a user
who is not the operator.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.access import ENV_VAR, PathNotAllowed, resolve_scan_path, scan_root


@pytest.fixture
def root(tmp_path):
    (tmp_path / "share" / "hr").mkdir(parents=True)
    (tmp_path / "share" / "hr" / "file.txt").write_text("x")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "keys.txt").write_text("x")
    return tmp_path / "share"


def test_a_path_inside_the_root_resolves(root):
    assert resolve_scan_path("hr", root=root) == (root / "hr").resolve()


def test_the_root_itself_is_allowed(root):
    assert resolve_scan_path(".", root=root) == root.resolve()


def test_an_absolute_path_outside_the_root_is_refused(root):
    with pytest.raises(PathNotAllowed):
        resolve_scan_path("/etc", root=root)


def test_dot_dot_traversal_is_refused(root):
    """The reason resolve() runs before the comparison.

    A string test would see "hr/../../secrets" start with the root and allow
    it; resolving collapses the segments first, so it does not.
    """
    with pytest.raises(PathNotAllowed):
        resolve_scan_path("hr/../../secrets", root=root)


def test_a_symlink_pointing_outside_is_refused(root, tmp_path):
    """Resolution follows links, so a planted symlink cannot smuggle a path out."""
    link = root / "shortcut"
    try:
        os.symlink(tmp_path / "secrets", link)
    except OSError:  # pragma: no cover - platforms without symlink permission
        pytest.skip("symlinks unavailable")
    with pytest.raises(PathNotAllowed):
        resolve_scan_path("shortcut", root=root)


def test_harmless_dot_dot_inside_the_root_still_works(root):
    """Confinement must not reject a legitimate path that happens to use "..".

    Over-blocking teaches operators to disable the control.
    """
    assert resolve_scan_path("hr/../hr", root=root) == (root / "hr").resolve()


def test_a_home_shorthand_outside_the_root_is_refused(root):
    with pytest.raises(PathNotAllowed):
        resolve_scan_path("~", root=root)


def test_the_error_says_how_to_widen_the_root(root):
    with pytest.raises(PathNotAllowed, match=ENV_VAR):
        resolve_scan_path("/etc", root=root)


def test_the_root_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_VAR, str(tmp_path))
    assert scan_root() == tmp_path.resolve()


def test_the_root_defaults_to_the_working_directory(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert scan_root() == Path.cwd().resolve()
