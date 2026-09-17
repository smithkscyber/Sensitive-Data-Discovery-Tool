"""PDF extraction: page by page, via pdfplumber.

A PDF does not store text; it stores instructions for painting glyphs at
coordinates. Extraction reconstructs reading order from those positions, which
is why the result is never byte-identical to whatever produced the file. Blank
lines are the clearest case: a line with no characters leaves no marks on the
page, so nothing survives to extract. Any offsets recorded against the original
text are invalid here and must be re-derived from what this function returns.
"""

from __future__ import annotations

from pathlib import Path

import pdfplumber


def extract(path: Path | str) -> str:
    """Return a PDF's text, pages joined by a newline."""
    with pdfplumber.open(str(path)) as document:
        pages = [page.extract_text() or "" for page in document.pages]
    return "\n".join(pages)
