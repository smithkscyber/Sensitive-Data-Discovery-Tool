"""Confine server-side scanning to a directory an operator chose.

The CLI is deliberately unrestricted: someone running it already has whatever
filesystem access their shell has, and fencing that in would be theatre.

The web UI is a different situation. It is a server, and its folder field takes
a path from whoever can reach the page. Unrestricted, ``/etc`` and a user's home
directory are one text box away, and the tool would happily read them and render
what it found. So the UI resolves every requested path through here first.

The root defaults to the working directory and is set with ``SDD_SCAN_ROOT``.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "SDD_SCAN_ROOT"


class PathNotAllowed(ValueError):
    """Raised for a path outside the configured scan root."""


def scan_root() -> Path:
    """The directory server-side scans are confined to."""
    return Path(os.environ.get(ENV_VAR, Path.cwd())).expanduser().resolve()


def resolve_scan_path(candidate: Path | str, root: Path | None = None) -> Path:
    """Resolve ``candidate`` and confirm it sits inside the scan root.

    ``resolve()`` before comparing is what makes this a real check rather than
    a string test: it collapses ``..`` segments and follows symlinks, so
    neither ``data/../../etc`` nor a symlink planted inside the root can point
    the scanner somewhere the operator did not allow.
    """
    base = (root or scan_root()).resolve()
    target = Path(candidate).expanduser()
    if not target.is_absolute():
        target = base / target
    target = target.resolve()

    if target != base and not target.is_relative_to(base):
        raise PathNotAllowed(
            f"{candidate} is outside the allowed scan root ({base}). "
            f"Set {ENV_VAR} to scan somewhere else."
        )
    return target
