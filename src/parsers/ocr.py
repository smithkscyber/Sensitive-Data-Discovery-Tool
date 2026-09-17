"""Optical character recognition, for documents that carry no text layer.

A scanned contract is a picture of a page. It has no characters to extract, so
every parser above returns an empty string and the scanner reports the file as
clean -- which is the most dangerous result this tool can produce, because a
clean result is exactly what nobody investigates. Scanned documents are also
routine in the e-discovery workflows this project models, so that gap is not an
edge case.

OCR closes it by rendering the page to an image and reading the characters back
off it. That is slow -- roughly a second per page against milliseconds for a
text layer -- so it runs only when the text layer turns out to be empty, never
as the default path.

Tesseract is an external binary, not a Python package, so it may be absent.
Everything here degrades to "no text recovered" rather than raising, and
``is_available()`` lets callers explain the difference between a file with
nothing in it and a file nobody could read.
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

#: Render resolution. Tesseract is trained around 300 DPI and degrades sharply
#: below ~200 on small type; going higher mostly costs time.
RENDER_DPI = 300

#: A page with fewer than this many non-whitespace characters is treated as
#: having no usable text layer and is sent to OCR. Not zero: a scanned page
#: often carries a stray header or page number in real text, which would
#: otherwise be taken as proof the page was extracted successfully.
MIN_CHARS_PER_PAGE = 24


@functools.lru_cache(maxsize=1)
def is_available() -> bool:
    """True when both the Python binding and the Tesseract binary are present."""
    try:
        import pytesseract

        pytesseract.get_tesseract_version()
        return True
    except Exception as error:  # noqa: BLE001 - any failure means unavailable
        logger.info("OCR unavailable: %s", error)
        return False


def looks_empty(text: str, pages: int = 1) -> bool:
    """Whether extracted text is thin enough to suspect a scanned document."""
    return len(text.strip()) < MIN_CHARS_PER_PAGE * max(pages, 1)


def image_to_text(image) -> str:
    """Read characters off a PIL image. Returns "" when OCR is unavailable."""
    if not is_available():
        return ""
    import pytesseract

    try:
        return pytesseract.image_to_string(image).strip()
    except Exception as error:  # noqa: BLE001 - a failed read is not a crash
        logger.warning("OCR failed on an image: %s", error)
        return ""


def image_file_to_text(path: Path | str) -> str:
    """Read characters off an image file."""
    if not is_available():
        return ""
    from PIL import Image

    with Image.open(path) as image:
        # Some formats (notably multi-frame TIFF) open lazily; load the first
        # frame explicitly so the file handle can close before OCR runs.
        image.load()
        return image_to_text(image)


def pdf_pages_to_text(path: Path | str, only_pages: set[int] | None = None) -> dict[int, str]:
    """Render PDF pages and OCR them, keyed by zero-based page index.

    ``only_pages`` restricts the work to pages that actually need it, so a
    mostly-digital PDF with two scanned inserts pays for two pages rather than
    for the whole document.
    """
    if not is_available():
        return {}

    import pypdfium2 as pdfium

    recovered: dict[int, str] = {}
    document = pdfium.PdfDocument(str(path))
    try:
        for index in range(len(document)):
            if only_pages is not None and index not in only_pages:
                continue
            bitmap = document[index].render(scale=RENDER_DPI / 72)
            recovered[index] = image_to_text(bitmap.to_pil())
    finally:
        document.close()

    return recovered
