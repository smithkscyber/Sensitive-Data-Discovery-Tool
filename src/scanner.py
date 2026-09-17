"""Walk a path, scan every file it can read, and score what it finds.

This is where the pieces meet: parse -> detect -> score. It is also the first
place the tool has to cope with a directory it did not create, which means
deciding what to do about files it cannot read.

Every file ends in exactly one of three states, and all three are reported:

* **scored** -- parsed and scanned; findings may be zero
* **skipped** -- no extractor for that extension
* **failed** -- an extractor was tried and raised

Scored files that yielded *no text at all* are additionally listed under
``empty``. That case is why: a scanned PDF is a picture of a page, so
extraction succeeds and returns nothing, and the file scores zero findings and
a NONE band -- indistinguishable from a genuinely clean document. OCR now
recovers most of those, but when it cannot (no Tesseract installed, an
unreadable scan), the fact has to stay visible rather than passing as a clean
result. A clean result is exactly what nobody investigates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from src.detectors import hybrid
from src.parsers import is_supported, parse
from src.reporting.risk_scorer import FileRisk, score_file

#: Signature of a detector: text in, matches out. Injectable so the walking
#: and error handling can be tested without loading a language model.
Detector = Callable[[str], Sequence[object]]


@dataclass(frozen=True)
class ScanFailure:
    """A file an extractor was tried on and raised."""

    path: str
    reason: str


@dataclass
class ScanResult:
    scored: list[FileRisk] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[ScanFailure] = field(default_factory=list)
    #: Scored files that produced no text. A subset of ``scored``, not a
    #: fourth outcome -- they were read, there was simply nothing in them.
    empty: list[str] = field(default_factory=list)

    @property
    def files_seen(self) -> int:
        return len(self.scored) + len(self.skipped) + len(self.failed)

    @property
    def finding_count(self) -> int:
        return sum(result.finding_count for result in self.scored)

    @property
    def complete(self) -> bool:
        """True when nothing failed. Skipped files do not make a scan partial.

        A skipped file is a known limit of the tool -- there is no extractor
        for .zip, and saying so is an honest answer. A failed file is a file
        the tool believed it could read and could not, which leaves a real gap
        in coverage.
        """
        return not self.failed


def scan_file(path: Path | str, detect: Detector = hybrid.scan_text) -> FileRisk:
    """Parse and scan one file. Raises if the file cannot be read."""
    return _scan(Path(path), detect)[0]


def _scan(path: Path, detect: Detector) -> tuple[FileRisk, str]:
    """Scan a file and hand back the extracted text alongside the score.

    The walk needs the text to tell an empty document from a clean one, and
    parsing twice to learn that would double the cost of every OCR fallback.
    """
    text = parse(path)
    return score_file(path, detect(text)), text


def scan_folder(
    root: Path | str,
    detect: Detector = hybrid.scan_text,
    recursive: bool = True,
) -> ScanResult:
    """Scan every readable file under ``root``.

    Sorted order, so two runs over an unchanged directory produce identical
    reports and a diff between them means something.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root_path}")

    paths = root_path.rglob("*") if recursive else root_path.glob("*")
    result = ScanResult()

    for path in sorted(paths):
        if not path.is_file():
            continue
        if not is_supported(path):
            result.skipped.append(path.as_posix())
            continue
        try:
            scored, text = _scan(path, detect)
            result.scored.append(scored)
            if not text.strip():
                result.empty.append(path.as_posix())
        except Exception as error:  # noqa: BLE001 - one bad file must not end the scan
            # Deliberately broad. Parsers wrap third-party libraries that raise
            # their own exception types for a corrupt PDF, an encrypted
            # document, a truncated archive. Enumerating them would mean a new
            # library version could abort a whole scan over one bad file --
            # while catching everything here still surfaces each failure by
            # name rather than swallowing it.
            result.failed.append(
                ScanFailure(path.as_posix(), f"{type(error).__name__}: {error}")
            )

    return result


def scan_path(
    path: Path | str,
    detect: Detector = hybrid.scan_text,
    recursive: bool = True,
) -> ScanResult:
    """Scan a file or a directory, whichever ``path`` turns out to be."""
    target = Path(path)
    if target.is_dir():
        return scan_folder(target, detect, recursive)
    if not target.exists():
        raise FileNotFoundError(f"no such file or directory: {target}")

    result = ScanResult()
    if not is_supported(target):
        result.skipped.append(target.as_posix())
        return result
    try:
        scored, text = _scan(target, detect)
        result.scored.append(scored)
        if not text.strip():
            result.empty.append(target.as_posix())
    except Exception as error:  # noqa: BLE001 - reported, not raised
        result.failed.append(
            ScanFailure(target.as_posix(), f"{type(error).__name__}: {error}")
        )
    return result
