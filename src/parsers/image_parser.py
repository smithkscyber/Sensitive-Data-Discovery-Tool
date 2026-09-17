"""Image extraction: there is no text layer, so it is OCR or nothing.

Photographs of documents and screenshots both turn up in real shares, and both
are invisible to every other parser here.
"""

from __future__ import annotations

from pathlib import Path

from src.parsers import ocr


def extract(path: Path | str) -> str:
    """Return the characters OCR can read from an image."""
    return ocr.image_file_to_text(path)
