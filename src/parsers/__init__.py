"""Per-format text extraction, dispatched by file extension.

Every detector and every recorded offset in the answer key indexes the text
*this* module returns -- not the bytes on disk. For .txt those are the same
thing; for .csv, .docx and .pdf they are not. Keeping one dispatcher means the
ground truth and the scanner can never disagree about what a file says.
"""

from __future__ import annotations

from pathlib import Path

from src.parsers import (
    csv_parser,
    docx_parser,
    eml_parser,
    html_parser,
    image_parser,
    json_parser,
    ocr,
    pdf_parser,
    text_parser,
    xlsx_parser,
)

#: Extension -> extractor. Extend here to add a format; nothing else needs to
#: know that a new one exists.
EXTRACTORS = {
    ".txt": text_parser.extract,
    ".text": text_parser.extract,
    ".md": text_parser.extract,
    ".csv": csv_parser.extract,
    ".docx": docx_parser.extract,
    ".pdf": pdf_parser.extract,
    # Images carry no text layer at all, so these depend entirely on OCR. They
    # are listed as supported regardless of whether Tesseract is installed: a
    # file the tool declines to look at should be reported as skipped, not
    # silently absent from the scan.
    ".png": image_parser.extract,
    ".jpg": image_parser.extract,
    ".jpeg": image_parser.extract,
    ".tif": image_parser.extract,
    ".tiff": image_parser.extract,
    ".bmp": image_parser.extract,
    # Spreadsheets and email are where bulk personal data actually lives in
    # the workflows this models, so their absence would undercut the framing
    # more than any detection gap.
    ".xlsx": xlsx_parser.extract,
    ".xlsm": xlsx_parser.extract,
    ".eml": eml_parser.extract,
    ".html": html_parser.extract,
    ".htm": html_parser.extract,
    ".json": json_parser.extract,
}

SUPPORTED_EXTENSIONS = tuple(sorted(EXTRACTORS))


class UnsupportedFormatError(ValueError):
    """Raised for a file whose extension has no extractor."""


def is_supported(path: Path | str) -> bool:
    return Path(path).suffix.lower() in EXTRACTORS


def parse(path: Path | str) -> str:
    """Extract text from ``path``, choosing the extractor by extension.

    Raises rather than returning "" for an unknown format. A scanner that
    silently yields no text for a file it cannot read reports that file as
    clean, which is the most dangerous possible failure for this tool: it
    looks exactly like a good result.
    """
    file_path = Path(path)
    extractor = EXTRACTORS.get(file_path.suffix.lower())
    if extractor is None:
        raise UnsupportedFormatError(
            f"no extractor for {file_path.suffix!r} ({file_path.name}); "
            f"supported: {', '.join(SUPPORTED_EXTENSIONS)}"
        )
    return extractor(file_path)
