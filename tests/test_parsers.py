"""Tests for per-format text extraction and the dispatcher.

The property that matters is not "did the parser return something" but "does
the text it returned still contain the PII that was planted in the file". A
parser that silently drops content turns a file full of sensitive data into a
clean scan result, which is the worst failure this tool can produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.parsers import (
    SUPPORTED_EXTENSIONS,
    UnsupportedFormatError,
    csv_parser,
    is_supported,
    parse,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
ANSWER_KEY = json.loads((REPO_ROOT / "data" / "answer_key.json").read_text())

CORPUS = [(entry["path"], entry["format"]) for entry in ANSWER_KEY["files"]]


# ------------------------------------------------------------- dispatcher


@pytest.mark.parametrize("extension", [".txt", ".csv", ".docx", ".pdf"])
def test_every_corpus_format_is_supported(extension):
    assert extension in SUPPORTED_EXTENSIONS


def test_extension_matching_ignores_case():
    assert is_supported("REPORT.PDF")
    assert is_supported(Path("Contacts.CSV"))


def test_unknown_format_raises_rather_than_returning_nothing(tmp_path):
    """Silence would report an unreadable file as clean.

    Returning "" for a format the tool cannot read produces a scan result
    indistinguishable from a genuinely empty file. An explicit failure is the
    only safe behaviour.
    """
    archive = tmp_path / "records.zip"
    archive.write_bytes(b"PK\x03\x04")
    with pytest.raises(UnsupportedFormatError):
        parse(archive)


def test_error_names_the_supported_formats(tmp_path):
    bad = tmp_path / "notes.rtf"
    bad.write_text("x")
    with pytest.raises(UnsupportedFormatError, match=r"\.pdf"):
        parse(bad)


# ------------------------------------------------------- corpus round trip


@pytest.mark.parametrize("path, file_format", CORPUS, ids=[p for p, _ in CORPUS])
def test_parsing_a_corpus_file_preserves_every_planted_value(path, file_format):
    """The check that makes multi-format support meaningful."""
    text = parse(REPO_ROOT / path)
    entry = next(e for e in ANSWER_KEY["files"] if e["path"] == path)
    missing = [f["value"] for f in entry["findings"] if f["value"] not in text]
    assert missing == [], f"{file_format} extraction lost {len(missing)} value(s)"


@pytest.mark.parametrize("path, file_format", CORPUS, ids=[p for p, _ in CORPUS])
def test_recorded_offsets_index_parsed_text(path, file_format):
    """Offsets must address what parse() returns, not the bytes on disk.

    This is the invariant the whole answer key rests on once binary formats
    are in play. If it fails, every accuracy figure is measuring noise.
    """
    text = parse(REPO_ROOT / path)
    entry = next(e for e in ANSWER_KEY["files"] if e["path"] == path)
    for item in entry["findings"] + entry["decoys"]:
        assert text[item["start"] : item["end"]] == item["value"]


@pytest.mark.parametrize("path, file_format", CORPUS, ids=[p for p, _ in CORPUS])
def test_parsing_is_repeatable(path, file_format):
    """Two reads of one file must agree, or offsets mean nothing."""
    assert parse(REPO_ROOT / path) == parse(REPO_ROOT / path)


# --------------------------------------------------------- format specifics


def test_docx_text_survives_the_round_trip_exactly(tmp_path):
    """python-docx is lossless: paragraphs come back as they went in.

    Worth pinning because it is the reason .docx offsets happen to match their
    source text, which makes it tempting to assume the same holds for .pdf. It
    does not -- see the blank-line test below.
    """
    import docx

    source = "Line one\n\nLine three, with 623-98-0035\nLine four"
    path = tmp_path / "round_trip.docx"
    document = docx.Document()
    for line in source.split("\n"):
        document.add_paragraph(line)
    document.save(str(path))

    assert parse(path) == source


def test_pdf_extraction_drops_blank_lines():
    """The reason PDF offsets cannot be reused from the source text.

    A blank line paints no glyphs on the page, so there is nothing for
    extraction to find. The text comes back shorter than it went in, and every
    offset after the first blank line shifts.
    """
    text = parse(REPO_ROOT / "data" / "raw" / "letter_01.pdf")
    assert "\n\n" not in text


def test_csv_parser_preserves_leading_zeros(tmp_path):
    """dtype=str is load-bearing, not stylistic.

    Left to infer types, pandas reads a bare ZIP column as integers and turns
    "03592" into "3592" -- corrupting the text before the detector ever runs.

    Uses a purpose-built file rather than the corpus: the corpus embeds ZIPs
    inside longer address strings, which pandas never coerces, so it cannot
    exercise this at all. An earlier version of this test read the corpus and
    passed happily with dtype inference switched back on.
    """
    path = tmp_path / "zips.csv"
    path.write_text("city,zip\nSpringfield,03592\nPortland,00501\n")
    text = csv_parser.extract(path)
    assert "03592" in text
    assert "00501" in text


def test_csv_parser_keeps_empty_cells_empty(tmp_path):
    """keep_default_na=False: an empty cell must not become the text "nan"."""
    path = tmp_path / "gaps.csv"
    path.write_text("name,email\nAda,\n,bob@example.org\n")
    text = csv_parser.extract(path)
    assert "nan" not in text.lower()


def test_csv_parser_unquotes_fields_containing_commas(tmp_path):
    """The flattening that shifts CSV offsets away from the raw file."""
    path = tmp_path / "one.csv"
    path.write_text('name,address\nAda,"1 Main St, Springfield, IL 62704"\n')
    text = csv_parser.extract(path)
    assert "1 Main St, Springfield, IL 62704" in text
    assert '"' not in text


def test_csv_parser_includes_the_header_row(tmp_path):
    path = tmp_path / "one.csv"
    path.write_text("full_name,ssn\nAda,623-98-0035\n")
    assert "full_name" in csv_parser.extract(path)


def test_text_parser_does_not_rewrite_line_endings(tmp_path):
    """Universal-newline mode would silently shift every offset past line one."""
    path = tmp_path / "crlf.txt"
    path.write_bytes(b"alpha\r\nbeta\r\n")
    assert parse(path) == "alpha\r\nbeta\r\n"


def test_parsed_corpus_covers_all_four_formats():
    assert {fmt for _, fmt in CORPUS} == {"txt", "csv", "docx", "pdf"}
