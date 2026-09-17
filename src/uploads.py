"""Stage uploaded files on disk long enough to scan them, then remove them.

Streamlit hands over uploaded files as bytes in memory, while every parser in
this project takes a path -- pdfplumber and python-docx both need to seek
around a real file. So the bytes have to land somewhere.

Where they land matters for a tool whose entire purpose is finding sensitive
data. Staging goes to a ``TemporaryDirectory`` that is removed when the scan
returns, including when it raises, so the tool is never the reason copies of
scanned documents accumulate on disk.

This lives in ``src/`` rather than in ``app.py`` because it is logic, not
interface: it has a contract worth testing, and a Streamlit script cannot be
imported outside a Streamlit runtime.
"""

from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Protocol, Sequence

from src.detectors import hybrid
from src.scanner import Detector, ScanResult, scan_path


class Upload(Protocol):
    """The part of Streamlit's UploadedFile this module actually uses.

    Narrowed to two members so the staging logic can be tested with a plain
    object instead of a running Streamlit server.
    """

    name: str

    def getbuffer(self) -> bytes: ...


def stage_and_scan(
    uploads: Sequence[Upload], detect: Detector = hybrid.scan_text
) -> ScanResult:
    """Write uploads to a temporary directory, scan it, and clean up.

    Result paths are rewritten back to the original filenames. Without that,
    every row of the report would name a directory that no longer exists, and
    the report would quietly disclose the server's temp path.
    """
    with tempfile.TemporaryDirectory(prefix="sdd-scan-") as staging:
        root = Path(staging)
        original: dict[str, str] = {}

        for upload in uploads:
            # Path().name strips any directory component in the supplied name,
            # so an upload called "../../etc/passwd" cannot write outside the
            # staging directory.
            safe_name = Path(upload.name).name
            target = root / safe_name
            target.write_bytes(upload.getbuffer())
            original[target.as_posix()] = safe_name

        result = scan_path(root, detect=detect)

    result.scored = [
        replace(item, path=original.get(item.path, item.path))
        for item in result.scored
    ]
    result.skipped = [original.get(path, path) for path in result.skipped]
    result.failed = [
        replace(failure, path=original.get(failure.path, failure.path))
        for failure in result.failed
    ]
    return result
