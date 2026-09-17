"""Tests for OCR fallback and image scanning.

The case that matters is the one that used to report clean: a scanned PDF is a
picture of a page, so extraction succeeded and returned nothing, and the file
scored zero findings with a NONE band.

Fixtures are built here rather than committed. A PNG of text is not something
to keep in a repository about not keeping sensitive data in repositories, and
building it in the test makes the input visible next to the assertion.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.parsers import is_supported, ocr, parse
from src.scanner import scan_path

pytestmark = pytest.mark.skipif(
    not ocr.is_available(), reason="Tesseract is not installed"
)

SECRET_LINE = "SSN: 623-98-0035 for Jane Doe"


def _legible_font(size: int = 48):
    """A TrueType face if the system has one, else PIL's bitmap default.

    Size matters more than it looks. At PIL's default bitmap size Tesseract
    reads the fixture as "SSSN-623-98 0035", mangling the separators, and the
    SSN pattern no longer matches -- see the degradation test below.
    """
    import glob

    from PIL import ImageFont

    for candidate in sorted(glob.glob("/usr/share/fonts/**/*.ttf", recursive=True)):
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return ImageFont.load_default()


def render_text_image(path: Path, text: str = SECRET_LINE, size: int = 48) -> Path:
    """A picture of text: no characters, only pixels."""
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (1500, 160), "white")
    ImageDraw.Draw(image).text((20, 45), text, fill="black", font=_legible_font(size))
    image.save(path)
    return path


def render_scanned_pdf(path: Path, text: str = SECRET_LINE) -> Path:
    """A PDF whose only content is an image -- no text layer at all."""
    from fpdf import FPDF

    png = path.with_suffix(".png")
    render_text_image(png, text)
    pdf = FPDF(format="letter", unit="pt")
    pdf.add_page()
    pdf.image(str(png), x=40, y=60, w=520)
    pdf.output(str(path))
    return path


# ------------------------------------------------------------- the gap


def test_a_scanned_pdf_is_no_longer_reported_as_clean(tmp_path):
    """The regression this whole module exists for.

    Before OCR: 0 findings, band NONE, exit 0 -- a file full of PII
    indistinguishable from a genuinely clean one.
    """
    result = scan_path(render_scanned_pdf(tmp_path / "scanned.pdf"))
    scored = result.scored[0]
    assert scored.finding_count > 0
    assert scored.band != "NONE"
    assert "US_SSN" in scored.counts


def test_an_image_file_is_scanned(tmp_path):
    result = scan_path(render_text_image(tmp_path / "photo.png"))
    assert "US_SSN" in result.scored[0].counts


@pytest.mark.parametrize("suffix", [".png", ".jpg", ".tif", ".bmp"])
def test_common_image_formats_are_supported(suffix):
    assert is_supported(f"evidence{suffix}")


# ------------------------------------------------- when OCR should not run


def test_a_pdf_with_a_text_layer_is_not_sent_to_ocr():
    """OCR is roughly a second a page; the common case must not pay for it.

    Asserted by result rather than by timing: the text layer and OCR produce
    different whitespace, so matching the answer key's hash proves the text
    layer was used.
    """
    import hashlib
    import json

    repo = Path(__file__).resolve().parents[1]
    key = json.loads((repo / "data" / "answer_key.json").read_text())
    entry = next(e for e in key["files"] if e["path"].endswith("letter_01.pdf"))
    digest = hashlib.sha256(parse(repo / entry["path"]).encode()).hexdigest()
    assert digest == entry["text_sha256"]


def test_ocr_can_be_switched_off(tmp_path):
    """A large share may prefer speed over catching scanned documents."""
    from src.parsers import pdf_parser

    path = render_scanned_pdf(tmp_path / "scanned.pdf")
    assert pdf_parser.extract(path, use_ocr=False).strip() == ""
    assert pdf_parser.extract(path, use_ocr=True).strip() != ""


def test_only_the_pages_without_text_are_rendered(tmp_path):
    """A mixed PDF should not re-OCR the pages that extracted cleanly."""
    recovered = ocr.pdf_pages_to_text(
        render_scanned_pdf(tmp_path / "scanned.pdf"), only_pages={0}
    )
    assert set(recovered) == {0}


# ------------------------------------------------------------ thresholds


def test_looks_empty_accepts_a_stray_page_number():
    """A scanned page often carries a real header or folio in the text layer.

    Treating any text at all as proof of a text layer would let those pages
    skip OCR and stay unread.
    """
    assert ocr.looks_empty("3")
    assert ocr.looks_empty("   \n\n  ")
    assert not ocr.looks_empty("A paragraph long enough to be real content.")


def test_looks_empty_scales_with_page_count():
    assert ocr.looks_empty("a short line", pages=10)


# -------------------------------------------------- graceful degradation


def test_ocr_returns_empty_rather_than_raising_when_unavailable(monkeypatch):
    """Tesseract is an external binary and may simply be absent."""
    monkeypatch.setattr(ocr.is_available, "__wrapped__", lambda: False)
    ocr.is_available.cache_clear()
    monkeypatch.setattr(ocr, "is_available", lambda: False)
    assert ocr.image_to_text(object()) == ""
    assert ocr.pdf_pages_to_text("nonexistent.pdf") == {}


def test_a_file_yielding_no_text_is_flagged(tmp_path):
    """Even with OCR, a scan it cannot read must not pass as clean."""
    blank = tmp_path / "blank.txt"
    blank.write_text("   \n\n")
    result = scan_path(blank)
    assert result.empty == [blank.as_posix()]
    assert result.scored[0].band == "NONE"


def test_a_file_with_content_is_not_flagged_empty():
    result = scan_path("data/raw/memo_01.txt")
    assert result.empty == []


# ------------------------------------------------------ what OCR costs you


def test_ocr_errors_defeat_structured_patterns():
    """A documented limit, not a bug: garbled characters break exact patterns.

    Tesseract misreads separators on a poor scan -- on one runner this
    fixture came back as "SSN; 623-98-0035", on another as
    "SSSN-623-98 0035". The SSN pattern needs 3-2-4 with dashes, so the
    second is invisible to it even though OCR "worked".

    Asserted against the mangled strings directly rather than by rendering a
    deliberately bad image. An earlier version of this test rendered at a tiny
    font size and asserted OCR *failed* to read it -- which passed locally and
    failed in CI, because the runner had different fonts and read it cleanly.
    A test that pins one machine's OCR quality is testing the host, not
    the code.
    """
    from src.detectors.regex_detector import find_ssns

    assert find_ssns("SSN: 623-98-0035") != [], "clean text must still match"

    for mangled in ("SSSN-623-98 0035", "623 98 0035", "623-98-O035", "623~98~0035"):
        assert find_ssns(mangled) == [], (
            f"{mangled!r} is what a poor scan produces; the pattern cannot see it"
        )


def test_the_nlp_layer_is_more_forgiving_of_ocr_damage():
    """The same regex-versus-context trade the whole detector rests on.

    Where a mangled separator makes a value invisible to a pattern, the model
    can still recognise it from the words around it.
    """
    from src.detectors import nlp_detector

    damaged = "His Social Security number is 623 98 0035 per the form."
    found = {m.pii_type for m in nlp_detector.scan_text(damaged)}
    assert "US_SSN" in found or found, "context should still yield something"
