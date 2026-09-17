"""PDF extraction: text layer first, OCR only where there isn't one.

A PDF does not store text; it stores instructions for painting glyphs at
coordinates. Extraction reconstructs reading order from those positions, which
is why the result is never byte-identical to whatever produced the file. Blank
lines are the clearest case: a line with no characters leaves no marks on the
page, so nothing survives to extract. Any offsets recorded against the original
text are invalid here and must be re-derived from what this function returns.

A scanned PDF has no text layer at all -- it is a picture of a page. Those
pages are sent to OCR individually rather than the whole document, so a mostly
digital file with two scanned inserts pays for two pages, not for all of it.
"""

from __future__ import annotations

from pathlib import Path

import pdfplumber

from src.parsers import ocr


class EncryptedPdfError(ValueError):
    """Raised for a password-protected PDF."""


def extract(path: Path | str, use_ocr: bool = True) -> str:
    """Return a PDF's text, pages joined by a newline.

    Set ``use_ocr=False`` to read only the text layer -- useful when scanning a
    large share where the OCR cost outweighs catching scanned documents.
    """
    try:
        with pdfplumber.open(str(path)) as document:
            pages = [page.extract_text() or "" for page in document.pages]
    except Exception as error:
        # pdfminer raises an exception with an empty message for a
        # password-protected file, so the scanner would report
        # "PdfminerException: " and leave the operator no idea what to do.
        # An encrypted document is a real coverage gap worth naming, not a
        # mystery failure.
        if b"/Encrypt" in Path(path).read_bytes():
            raise EncryptedPdfError(
                f"{Path(path).name} is password-protected; its contents were "
                f"not scanned"
            ) from error
        raise

    if not use_ocr:
        return "\n".join(pages)

    # Per page, not per document: a mixed PDF is common and OCRing the pages
    # that already extracted cleanly would be wasted time and worse text.
    needs_ocr = {
        index for index, text in enumerate(pages) if ocr.looks_empty(text)
    }
    if not needs_ocr:
        return "\n".join(pages)

    for index, recovered in ocr.pdf_pages_to_text(path, only_pages=needs_ocr).items():
        if recovered:
            pages[index] = recovered

    return "\n".join(pages)
