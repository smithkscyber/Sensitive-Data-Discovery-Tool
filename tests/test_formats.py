"""Tests for the spreadsheet, email, HTML and JSON parsers.

Spreadsheets and email are the formats the e-discovery workflows this models
actually run on, and each hides PII somewhere the others do not: an email
carries it in headers, body and attachments at once, and a spreadsheet keeps
it on sheets nobody scrolls to.
"""

from __future__ import annotations

import pytest

from src.parsers import UnsupportedFormatError, is_supported, parse
from src.parsers.html_parser import strip_tags


@pytest.fixture
def workbook(tmp_path):
    import openpyxl

    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Contacts"
    sheet.append(["name", "email", "ssn"])
    sheet.append(["Jane Doe", "jane@example.com", "623-98-0035"])
    book.create_sheet("Archive").append(["Old number 555-123-4567"])
    path = tmp_path / "book.xlsx"
    book.save(path)
    return path


@pytest.fixture
def message(tmp_path):
    path = tmp_path / "mail.eml"
    path.write_text(
        "From: Jane Doe <jane@example.com>\n"
        "To: Bob Ray <bob@example.org>\n"
        "Subject: Account 623-98-0035\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nCall me on 555-123-4567.\n"
        "--B\nContent-Type: text/plain; name=\"note.txt\"\n"
        'Content-Disposition: attachment; filename="note.txt"\n\n'
        "Card 4720 0566 5876 3761\n--B--\n"
    )
    return path


# ------------------------------------------------------------------ xlsx


@pytest.mark.parametrize("suffix", [".xlsx", ".xlsm", ".eml", ".html", ".htm", ".json"])
def test_new_formats_are_dispatched(suffix):
    assert is_supported(f"evidence{suffix}")


def test_xlsx_reads_every_sheet(workbook):
    """PII hides on the sheet nobody scrolls to."""
    text = parse(workbook)
    assert "623-98-0035" in text
    assert "555-123-4567" in text, "second sheet was not read"


def test_xlsx_keeps_the_computed_value_of_a_formula(tmp_path):
    """data_only=True: a cell reading =CONCATENATE(...) tells a detector
    nothing, while the value it computes to may be an SSN."""
    import openpyxl

    book = openpyxl.Workbook()
    sheet = book.active
    sheet["A1"] = "623-98-0035"
    sheet["B1"] = "=A1"
    # openpyxl only stores a cached result when Excel wrote the file, so the
    # assertion is on the source cell -- what matters is that the parser asks
    # for values rather than formula text.
    path = tmp_path / "formula.xlsx"
    book.save(path)
    assert "=A1" not in parse(path)


def test_xlsx_skips_empty_cells(tmp_path):
    import openpyxl

    book = openpyxl.Workbook()
    book.active.append(["Jane Doe", None, "623-98-0035"])
    path = tmp_path / "gaps.xlsx"
    book.save(path)
    assert "None" not in parse(path)


# ------------------------------------------------------------------- eml


def test_eml_reads_headers(message):
    """Recipients are PII, and reading only the body would miss them."""
    text = parse(message)
    assert "bob@example.org" in text
    assert "623-98-0035" in text, "subject line was not read"


def test_eml_reads_the_body(message):
    assert "555-123-4567" in parse(message)


def test_eml_reads_text_attachments(message):
    """An attachment is where the interesting document usually is."""
    assert "4720 0566 5876 3761" in parse(message)


def test_eml_decodes_encoded_word_headers(tmp_path):
    """A name written as =?utf-8?B?...?= on the wire must be scanned as a name."""
    path = tmp_path / "encoded.eml"
    path.write_text(
        "From: =?utf-8?q?Jane_Doe?= <jane@example.com>\n"
        "Subject: test\n\nbody\n"
    )
    assert "Jane Doe" in parse(path)


def test_eml_names_binary_attachments_without_decoding_them(tmp_path):
    path = tmp_path / "binary.eml"
    path.write_text(
        "From: a@example.com\nMIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nbody\n"
        "--B\nContent-Type: application/octet-stream\n"
        'Content-Disposition: attachment; filename="payroll.bin"\n\n'
        "AAAA\n--B--\n"
    )
    assert "payroll.bin" in parse(path)


# ------------------------------------------------------------------ html


def test_html_strips_markup():
    assert strip_tags("<p>Call <b>555-123-4567</b></p>") == "Call 555-123-4567"


def test_html_ignores_script_and_style_content():
    """Their text is code, not prose. Scanning it produces unactionable findings."""
    markup = (
        "<style>.x{content:'999-99-9999'}</style>"
        "<script>var ssn='888-88-8888'</script>"
        "<p>SSN 623-98-0035</p>"
    )
    text = strip_tags(markup)
    assert "623-98-0035" in text
    assert "999-99-9999" not in text
    assert "888-88-8888" not in text


def test_html_decodes_entities():
    assert "a@b.com" in strip_tags("<p>a&#64;b.com</p>")


def test_html_does_not_double_count_a_mailto_link(tmp_path):
    """The href and the link text hold the same address; only one is visible."""
    path = tmp_path / "page.html"
    path.write_text('<p><a href="mailto:jane@example.com">jane@example.com</a></p>')
    assert parse(path).count("jane@example.com") == 1


# ------------------------------------------------------------------ json


def test_json_keeps_keys_next_to_values(tmp_path):
    """The key is context: "ssn": "..." is what lifts Presidio's confidence
    over the threshold, so flattening to bare values would lose detections."""
    path = tmp_path / "export.json"
    path.write_text('{"user":{"ssn":"623-98-0035"}}')
    text = parse(path)
    assert "user.ssn" in text
    assert "623-98-0035" in text


def test_json_flattens_nested_arrays(tmp_path):
    path = tmp_path / "export.json"
    path.write_text('{"phones":["555-123-4567","555-987-6543"]}')
    text = parse(path)
    assert "555-123-4567" in text and "555-987-6543" in text


def test_malformed_json_raises_rather_than_being_salvaged(tmp_path):
    """A partially parsed file would be scanned partially and reported whole."""
    path = tmp_path / "broken.json"
    path.write_text('{"user": ')
    with pytest.raises(Exception):
        parse(path)


# -------------------------------------------------------- encrypted files


def test_an_encrypted_pdf_is_reported_by_name_not_treated_as_clean(tmp_path):
    """pdfminer raises with an empty message for a password-protected file.

    Reported verbatim that becomes "PdfminerException: ", which tells an
    operator nothing. An encrypted document is a real coverage gap and has to
    say so.
    """
    from fpdf import FPDF

    from src.scanner import scan_path

    pdf = FPDF(format="letter", unit="pt")
    pdf.add_page()
    pdf.set_font("Courier", size=11)
    pdf.cell(0, 14, "SSN: 623-98-0035", new_x="LMARGIN", new_y="NEXT")
    pdf.set_encryption(owner_password="owner", user_password="secret")
    path = tmp_path / "locked.pdf"
    pdf.output(str(path))

    result = scan_path(path)
    assert not result.complete, "an unreadable file must not pass as clean"
    assert result.scored == []
    assert "password-protected" in result.failed[0].reason
