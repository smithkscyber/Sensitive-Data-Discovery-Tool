"""Plain-text extraction: read the file and hand back its contents."""

from __future__ import annotations

from pathlib import Path


def extract(path: Path | str) -> str:
    """Return the file's text.

    ``newline=""`` is deliberate: Python's universal-newline mode silently
    rewrites CRLF to LF, which would shift every character offset after the
    first line break on a file written under Windows. Reading the bytes as
    written keeps offsets honest; normalisation, if ever wanted, belongs in one
    explicit place rather than as a side effect of opening a file.
    """
    # open() rather than Path.read_text(): the newline argument only reached
    # read_text() in Python 3.13, and this project supports 3.10+.
    with open(path, encoding="utf-8", errors="replace", newline="") as handle:
        return handle.read()
