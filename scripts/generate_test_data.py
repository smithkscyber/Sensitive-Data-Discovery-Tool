#!/usr/bin/env python3
"""Generate the synthetic test corpus and its ground-truth answer key.

Every value written by this script is fabricated by Faker. No real personal
data is involved at any point -- see the data policy in README.md.

The corpus is the measuring stick for every detector built in later phases, so
two properties matter more than realism:

1. **Determinism.** A fixed seed plus pinned dependency versions mean this
   script produces byte-identical files on every run and every machine. Without
   that, the recorded offsets would drift and the answer key would rot.
2. **Completeness.** Every piece of PII in the output is routed through
   ``Doc.add_pii`` and recorded. Nothing sensitive reaches a file without an
   entry in the answer key -- otherwise a correct detection would be scored as
   a false positive in Phase 3.

**Offsets index parsed text, not file bytes.** Every offset in the answer key
is re-derived by running the finished file back through ``src.parsers.parse``
-- the same function the scanner uses. For .txt the two are identical; for
.csv, .docx and .pdf they are not, and recording source offsets for those would
describe text the scanner never sees.

Usage::

    python scripts/generate_test_data.py

Writes::

    data/raw/       5 .txt memos, 3 .csv contact lists, 3 .docx contracts,
                    3 .pdf letters
    data/answer_key.json
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import faker
from faker import Faker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.parsers import parse  # noqa: E402  (needs the path insert above)

# Changing the seed regenerates the entire corpus and invalidates every offset
# already recorded in the answer key. Change it only alongside a full rerun.
SEED = 20260916

REPO_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = REPO_ROOT / "data" / "raw"
ANSWER_KEY_PATH = REPO_ROOT / "data" / "answer_key.json"

#: Stamped into .docx and .pdf metadata instead of "now", so regenerating does
#: not rewrite every binary fixture with a fresh timestamp and a spurious diff.
FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)

#: The same moment as a ZIP date tuple, for the archive metadata inside a
#: .docx. ZIP stores local time with no zone, so this is a plain 6-tuple.
FIXED_ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)

#: Courier 10pt on US Letter fits about 92 characters. Long lines are rejected
#: rather than allowed to overflow the page, where the overflowing text would
#: silently fail to extract.
PDF_MAX_LINE = 90

# Entity labels match Presidio's vocabulary so Phase 4 can compare its output
# against this key without a translation layer.
US_SSN = "US_SSN"
CREDIT_CARD = "CREDIT_CARD"
EMAIL_ADDRESS = "EMAIL_ADDRESS"
PHONE_NUMBER = "PHONE_NUMBER"
IP_ADDRESS = "IP_ADDRESS"
PERSON = "PERSON"
LOCATION = "LOCATION"


class Doc:
    """Accumulates document text while recording where each planted item lands.

    Offsets are character indices into the finished text (Python string
    indices over the UTF-8 decoded content), which is exactly the coordinate
    space ``re`` will report matches in, so Phase 3 can compare spans directly.
    """

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._pos = 0
        self.findings: list[dict] = []
        self.decoys: list[dict] = []

    def add(self, text: str) -> "Doc":
        """Append literal text. Must not contain anything sensitive."""
        self._parts.append(text)
        self._pos += len(text)
        return self

    def add_pii(self, pii_type: str, value: str) -> "Doc":
        """Append a planted value and record its type and span."""
        start = self._pos
        self.add(value)
        self.findings.append(
            {"type": pii_type, "start": start, "end": self._pos, "value": value}
        )
        return self

    def add_decoy(self, near_miss_for: str, value: str, reason: str) -> "Doc":
        """Append a value that resembles PII but is not sensitive.

        Decoys make precision measurable. Without them a detector that flags
        every digit string scores perfectly on recall and is never penalised.
        """
        start = self._pos
        self.add(value)
        self.decoys.append(
            {
                "near_miss_for": near_miss_for,
                "start": start,
                "end": self._pos,
                "value": value,
                "reason": reason,
            }
        )
        return self

    @property
    def text(self) -> str:
        return "".join(self._parts)


@dataclass
class Fixture:
    """One generated file plus the ground truth about what is inside it."""

    path: Path
    text: str
    file_format: str
    findings: list[dict] = field(default_factory=list)
    decoys: list[dict] = field(default_factory=list)
    #: Filled in after the file is written, by re-reading it through parse().
    parsed_text: str = ""


class Mint:
    """Produces fake identifiers in formats the Phase 3 regexes will target."""

    def __init__(self, seed: int) -> None:
        Faker.seed(seed)
        self.fake = Faker("en_US")
        self.rng = random.Random(seed)

    def person(self) -> str:
        # first + last rather than name(), which sometimes adds a title such as
        # "Dr." -- an ambiguous PERSON boundary makes span comparison noisy.
        return f"{self.fake.first_name()} {self.fake.last_name()}"

    def email(self) -> str:
        # ascii_safe_email() only emits RFC 2606 reserved domains (example.com
        # and friends), so no generated address can ever reach a real mailbox.
        return self.fake.ascii_safe_email()

    def ssn(self) -> str:
        return self.fake.ssn()

    def phone(self) -> str:
        area = self.rng.randint(200, 989)
        exchange = self.rng.randint(200, 989)
        line = self.rng.randint(0, 9999)
        style = self.rng.choice(["paren", "dash", "dot"])
        if style == "paren":
            return f"({area}) {exchange}-{line:04d}"
        if style == "dash":
            return f"{area}-{exchange}-{line:04d}"
        return f"{area}.{exchange}.{line:04d}"

    def credit_card(self) -> str:
        digits = self.fake.credit_card_number(
            card_type=self.rng.choice(["visa16", "mastercard"])
        )
        groups = [digits[i : i + 4] for i in range(0, 16, 4)]
        return self.rng.choice([" ", "-", ""]).join(groups)

    def ip(self) -> str:
        return self.fake.ipv4_private()

    def address(self) -> str:
        return (
            f"{self.fake.street_address()}, {self.fake.city()}, "
            f"{self.fake.state_abbr()} {self.fake.postcode()}"
        )

    def employee_id(self) -> str:
        """Nine digits with no dashes -- tempting to a loose SSN pattern."""
        return f"{self.rng.randint(100000000, 999999999)}"

    def order_number(self) -> str:
        """Sixteen digits that deliberately fail the Luhn checksum."""
        while True:
            digits = f"{self.rng.randint(10**15, 10**16 - 1)}"
            if not _luhn_valid(digits):
                return digits


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def build_memo(mint: Mint, index: int) -> Fixture:
    """An internal memo: prose with PII scattered through natural sentences."""
    doc = Doc()
    recipient = mint.person()
    sender = mint.person()
    subject = mint.rng.choice(
        [
            "Q3 payroll correction",
            "Vendor onboarding follow-up",
            "Benefits enrollment discrepancy",
            "Account access review",
            "Expense reimbursement backlog",
        ]
    )

    doc.add("INTERNAL MEMORANDUM\n")
    doc.add("=" * 60 + "\n\n")
    doc.add("To:      ").add_pii(PERSON, recipient).add(" <")
    doc.add_pii(EMAIL_ADDRESS, mint.email()).add(">\n")
    doc.add("From:    ").add_pii(PERSON, sender).add("\n")
    doc.add("Subject: ").add(subject).add("\n")
    doc.add("Ref:     INC-").add_decoy(
        US_SSN,
        mint.employee_id(),
        "internal incident number, nine digits with no separators",
    ).add("\n\n")

    doc.add_pii(PERSON, recipient).add(",\n\n")
    doc.add("Following up on the item we discussed. The employee record in\n")
    doc.add("question lists a home address of ")
    doc.add_pii(LOCATION, mint.address()).add(",\n")
    doc.add("which does not match what payroll has on file. Their taxpayer\n")
    doc.add("identifier on the submitted form reads ")
    doc.add_pii(US_SSN, mint.ssn()).add(".\n\n")

    doc.add("Please confirm by phone at ")
    doc.add_pii(PHONE_NUMBER, mint.phone()).add(" before Friday, or\n")
    doc.add("reply to ").add_pii(EMAIL_ADDRESS, mint.email()).add(" if that is easier.\n\n")

    if index % 2 == 0:
        doc.add("The reimbursement was charged to the corporate card ending in\n")
        doc.add("the account below; finance has asked that we stop circulating it\n")
        doc.add("in plain text after this thread.\n\n")
        doc.add("    Card: ").add_pii(CREDIT_CARD, mint.credit_card()).add("\n\n")

    doc.add("For the audit trail, the request originated from the workstation at\n")
    doc.add("    ").add_pii(IP_ADDRESS, mint.ip()).add("\n")
    doc.add("running client build ").add_decoy(
        IP_ADDRESS,
        "10.2.14.3",
        "software version string in dotted-quad form, not a network address",
    ).add(".\n\n")

    doc.add("Thanks,\n").add_pii(PERSON, sender).add("\n")

    return Fixture(
        path=RAW_DIR / f"memo_{index:02d}.txt",
        text=doc.text,
        file_format="txt",
        findings=doc.findings,
        decoys=doc.decoys,
    )


def build_contact_csv(mint: Mint, index: int, rows: int = 8) -> Fixture:
    """A contact list: dense, highly structured, one record per line."""
    doc = Doc()
    doc.add("full_name,email,phone,address,ssn,employee_id\n")

    for _ in range(rows):
        _csv_field(doc, PERSON, mint.person())
        doc.add(",")
        _csv_field(doc, EMAIL_ADDRESS, mint.email())
        doc.add(",")
        _csv_field(doc, PHONE_NUMBER, mint.phone())
        doc.add(",")
        _csv_field(doc, LOCATION, mint.address())
        doc.add(",")
        _csv_field(doc, US_SSN, mint.ssn())
        doc.add(",")
        doc.add_decoy(
            US_SSN,
            mint.employee_id(),
            "payroll employee number, nine digits with no separators",
        )
        doc.add("\n")

    return Fixture(
        path=RAW_DIR / f"contacts_{index:02d}.csv",
        text=doc.text,
        file_format="csv",
        findings=doc.findings,
        decoys=doc.decoys,
    )


def _csv_field(doc: Doc, pii_type: str, value: str) -> None:
    """Write one CSV field, quoting when needed.

    The recorded span covers the value itself, not the surrounding quotes, so
    an offset still points at the PII rather than at punctuation.
    """
    if '"' in value or "\n" in value:
        raise ValueError(f"unsupported character in generated field: {value!r}")
    if "," in value:
        doc.add('"')
        doc.add_pii(pii_type, value)
        doc.add('"')
    else:
        doc.add_pii(pii_type, value)


def build_contract(mint: Mint, index: int) -> Fixture:
    """Source text for a .docx contract, converted to real .docx in Phase 5."""
    doc = Doc()
    client = mint.person()
    counsel = mint.person()

    doc.add("SERVICES AGREEMENT\n\n")
    doc.add("This Agreement is entered into by and between Northgate Analytics\n")
    doc.add('LLC ("Provider") and ')
    doc.add_pii(PERSON, client).add(' ("Client"), residing at\n')
    doc.add_pii(LOCATION, mint.address()).add(".\n\n")

    doc.add("1. NOTICES\n\n")
    doc.add("   All notices to Client shall be sent to ")
    doc.add_pii(EMAIL_ADDRESS, mint.email()).add("\n")
    doc.add("   or delivered by telephone to ")
    doc.add_pii(PHONE_NUMBER, mint.phone()).add(".\n\n")

    doc.add("2. PAYMENT\n\n")
    doc.add("   Client authorizes recurring charges to the payment instrument\n")
    doc.add("   on file, account number ")
    doc.add_pii(CREDIT_CARD, mint.credit_card()).add(".\n")
    doc.add("   Invoices reference purchase order ")
    doc.add_decoy(
        CREDIT_CARD,
        mint.order_number(),
        "sixteen-digit purchase order that fails the Luhn checksum",
    ).add(".\n\n")

    doc.add("3. TAX REPORTING\n\n")
    doc.add("   Client certifies that the taxpayer identification number\n")
    doc.add("   provided for reporting purposes is ")
    doc.add_pii(US_SSN, mint.ssn()).add(".\n\n")

    doc.add("IN WITNESS WHEREOF, the parties execute this Agreement.\n\n")
    doc.add("Client: ").add_pii(PERSON, client).add("\n")
    doc.add("Counsel: ").add_pii(PERSON, counsel).add("\n")
    doc.add("Contact: ").add_pii(EMAIL_ADDRESS, mint.email()).add("\n")

    return Fixture(
        path=RAW_DIR / f"contract_{index:02d}.docx",
        text=doc.text,
        file_format="docx",
        findings=doc.findings,
        decoys=doc.decoys,
    )


def build_letter(mint: Mint, index: int) -> Fixture:
    """Source text for a .pdf letter, converted to real .pdf in Phase 5."""
    doc = Doc()
    customer = mint.person()
    officer = mint.person()

    doc.add("Meridian Trust & Savings\n")
    doc.add("Member Services Department\n\n")
    doc.add_pii(PERSON, customer).add("\n")
    doc.add_pii(LOCATION, mint.address()).add("\n\n")

    doc.add("Dear ").add_pii(PERSON, customer).add(",\n\n")
    doc.add("We are writing regarding recent activity on your account. Our\n")
    doc.add("records show the card ending in the number below was used at a\n")
    doc.add("merchant outside your usual pattern:\n\n")
    doc.add("    ").add_pii(CREDIT_CARD, mint.credit_card()).add("\n\n")

    doc.add("If you recognize this charge, no action is required. If you do\n")
    doc.add("not, call us at ").add_pii(PHONE_NUMBER, mint.phone()).add(" or write to\n")
    doc.add_pii(EMAIL_ADDRESS, mint.email()).add(".\n\n")

    doc.add("For verification we may ask for the last four digits of the\n")
    doc.add("Social Security number associated with the account, which our\n")
    doc.add("records list as ").add_pii(US_SSN, mint.ssn()).add(".\n\n")
    doc.add("Your case reference is ")
    doc.add_decoy(
        US_SSN,
        mint.employee_id(),
        "case reference, nine digits with no separators",
    ).add(".\n\n")

    doc.add("Sincerely,\n")
    doc.add_pii(PERSON, officer).add("\n")
    doc.add("Member Services\n")

    return Fixture(
        path=RAW_DIR / f"letter_{index:02d}.pdf",
        text=doc.text,
        file_format="pdf",
        findings=doc.findings,
        decoys=doc.decoys,
    )


def build_contact_notice(mint: Mint, index: int) -> Fixture:
    """Contact details only -- the corpus's LOW band.

    Every other fixture carries a Social Security number, so without files
    like this one the corpus can only ever produce HIGH and CRITICAL and three
    of the five bands go unexercised by real data.
    """
    doc = Doc()
    doc.add("FACILITIES BULLETIN\n")
    doc.add("=" * 60 + "\n\n")
    doc.add("The loading bay will be closed for resurfacing next week.\n")
    doc.add("Deliveries should be rerouted to the west entrance.\n\n")
    doc.add("Questions to the facilities desk: ")
    doc.add_pii(EMAIL_ADDRESS, mint.email()).add("\n")
    doc.add("Out of hours, call ").add_pii(PHONE_NUMBER, mint.phone()).add(".\n\n")
    doc.add("No action is required from most teams.\n")

    return Fixture(
        path=RAW_DIR / f"bulletin_{index:02d}.txt",
        text=doc.text,
        file_format="txt",
        findings=doc.findings,
        decoys=doc.decoys,
    )


def build_site_note(mint: Mint, index: int) -> Fixture:
    """A single address and nothing more severe -- the MEDIUM band."""
    doc = Doc()
    doc.add("SITE VISIT NOTE\n")
    doc.add("=" * 60 + "\n\n")
    doc.add("The survey was completed on schedule. The property is\n")
    doc.add("registered at ").add_pii(LOCATION, mint.address()).add("\n")
    doc.add("and the access code has been rotated since the last visit.\n\n")
    doc.add("No follow-up is outstanding.\n")

    return Fixture(
        path=RAW_DIR / f"site_note_{index:02d}.txt",
        text=doc.text,
        file_format="txt",
        findings=doc.findings,
        decoys=doc.decoys,
    )


def build_clean_notice(mint: Mint, index: int) -> Fixture:
    """No PII at all -- the NONE band.

    A scan that never produces a clean result cannot demonstrate that it
    distinguishes one, and "found nothing" is a verdict the tool has to be
    able to reach correctly. Deliberately free of names, addresses and digit
    strings: both engines must see nothing here.
    """
    doc = Doc()
    doc.add("RECORDS RETENTION NOTICE\n")
    doc.add("=" * 60 + "\n\n")
    doc.add("All departments must review storage allocations before the end\n")
    doc.add("of the quarter. Retention periods are unchanged this cycle.\n\n")
    doc.add("Archived material older than seven years becomes eligible for\n")
    doc.add("disposal once the relevant department head has signed off.\n\n")
    doc.add("Questions should be raised through the usual channel.\n")

    return Fixture(
        path=RAW_DIR / f"retention_{index:02d}.txt",
        text=doc.text,
        file_format="txt",
        findings=doc.findings,
        decoys=doc.decoys,
    )


def generate() -> list[Fixture]:
    mint = Mint(SEED)
    fixtures: list[Fixture] = []
    fixtures.extend(build_memo(mint, i) for i in range(1, 6))
    fixtures.extend(build_contact_csv(mint, i) for i in range(1, 4))
    fixtures.extend(build_contract(mint, i) for i in range(1, 4))
    fixtures.extend(build_letter(mint, i) for i in range(1, 4))
    # Low-severity and clean fixtures, so the corpus exercises every risk band
    # rather than leaving LOW, MEDIUM and NONE to unit tests alone.
    fixtures.append(build_contact_notice(mint, 1))
    fixtures.append(build_site_note(mint, 1))
    fixtures.append(build_clean_notice(mint, 1))
    return fixtures


def verify(fixtures: list[Fixture], against: str = "text") -> None:
    """Prove every recorded span actually points at the value it claims.

    This is the check that makes the answer key trustworthy. If it ever fails,
    the key is lying and every accuracy number derived from it is meaningless.

    Run twice: once against the text the builder produced, which catches
    template bugs, and again against the text ``parse()`` returns from the
    written file, which catches anything the format conversion moved.
    """
    for fixture in fixtures:
        subject = getattr(fixture, against)
        spans = [
            (item["start"], item["end"], item["value"])
            for item in (*fixture.findings, *fixture.decoys)
        ]
        for start, end, value in spans:
            actual = subject[start:end]
            if actual != value:
                raise AssertionError(
                    f"{fixture.path.name}: span [{start}:{end}] holds "
                    f"{actual!r}, expected a recorded value of equal length"
                )
        ordered = sorted(spans)
        for (_, prev_end, _), (next_start, _, _) in zip(ordered, ordered[1:]):
            if next_start < prev_end:
                raise AssertionError(
                    f"{fixture.path.name}: overlapping spans at {next_start}"
                )

        # Catch values that reached the text without being recorded -- a name
        # interpolated into a template, say. An unrecorded value would be
        # scored as a false positive in Phase 3 and quietly depress precision.
        for _, _, value in spans:
            in_text = subject.count(value)
            recorded = sum(1 for _, _, other in spans if other == value)
            if in_text != recorded:
                raise AssertionError(
                    f"{fixture.path.name}: {value!r} appears {in_text}x in the "
                    f"text but {recorded}x in the key -- every occurrence must "
                    f"go through add_pii or add_decoy"
                )


def _freeze_zip_timestamps(path: Path) -> None:
    """Rewrite a ZIP archive with fixed member timestamps.

    A .docx is a ZIP, and python-docx stamps every member with the wall clock
    at save time. The member *contents* are identical run to run, but those
    timestamps are not, so regenerating produced a different file every time
    and the committed corpus always looked dirty.

    Setting the document's core properties is not enough -- those live inside
    docProps/core.xml, while this is the archive's own metadata one level up.
    """
    import zipfile

    with zipfile.ZipFile(path) as archive:
        members = [(info, archive.read(info.filename)) for info in archive.infolist()]

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for info, data in members:
            frozen = zipfile.ZipInfo(info.filename, date_time=FIXED_ZIP_TIMESTAMP)
            frozen.compress_type = info.compress_type
            frozen.external_attr = info.external_attr
            archive.writestr(frozen, data)


def _write_docx(path: Path, text: str) -> None:
    """One source line per Word paragraph.

    python-docx round-trips this exactly: the text read back out is identical
    to the text put in, blank lines included.
    """
    import docx

    document = docx.Document()
    for line in text.split("\n"):
        document.add_paragraph(line)
    document.core_properties.created = FIXED_TIMESTAMP
    document.core_properties.modified = FIXED_TIMESTAMP
    document.save(str(path))
    _freeze_zip_timestamps(path)


def _write_pdf(path: Path, text: str) -> None:
    """Draw each source line at a fixed position in a monospace font.

    Nothing here survives as text the way it was written. A PDF stores glyphs
    at coordinates, and extraction reconstructs lines from those positions, so
    the round trip is lossy by construction -- blank lines vanish entirely,
    because a line with no characters paints nothing on the page.

    Lines wider than the page would be clipped and silently lost, so an
    over-long line is a hard error rather than a quiet gap in the corpus.
    """
    from fpdf import FPDF

    lines = text.split("\n")
    too_long = [line for line in lines if len(line) > PDF_MAX_LINE]
    if too_long:
        raise ValueError(
            f"{path.name}: {len(too_long)} line(s) exceed {PDF_MAX_LINE} "
            f"characters and would be clipped off the page"
        )

    pdf = FPDF(format="letter", unit="pt")
    pdf.set_creation_date(FIXED_TIMESTAMP)
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()
    pdf.set_font("Courier", size=10)
    for line in lines:
        pdf.cell(0, 12, line, new_x="LMARGIN", new_y="NEXT")
    pdf.output(str(path))


WRITERS = {
    "txt": lambda path, text: path.write_text(text, encoding="utf-8", newline="\n"),
    "csv": lambda path, text: path.write_text(text, encoding="utf-8", newline="\n"),
    "docx": _write_docx,
    "pdf": _write_pdf,
}


def write_corpus(fixtures: list[Fixture]) -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for fixture in fixtures:
        WRITERS[fixture.file_format](fixture.path, fixture.text)


def relocate_offsets(fixtures: list[Fixture]) -> None:
    """Re-derive every offset against what ``parse()`` returns.

    The builder knows where it put each value in the text it composed. That is
    not where the value ends up in the text a parser extracts back out: a PDF
    drops blank lines, and the CSV parser flattens quoted cells into prose. An
    offset recorded against the source would point into text no detector will
    ever be handed.

    Values are located in document order behind a forward-moving cursor, which
    is what keeps a name that appears three times mapped to its three distinct
    positions rather than to the first one three times.
    """
    for fixture in fixtures:
        fixture.parsed_text = parse(fixture.path)
        ordered = sorted(
            (*fixture.findings, *fixture.decoys), key=lambda item: item["start"]
        )
        cursor = 0
        for item in ordered:
            found = fixture.parsed_text.find(item["value"], cursor)
            if found < 0:
                raise AssertionError(
                    f"{fixture.path.name}: a planted value recorded at "
                    f"{item['start']} did not survive the round trip through "
                    f"{fixture.file_format} -- extraction altered or dropped it"
                )
            item["start"] = found
            item["end"] = found + len(item["value"])
            cursor = item["end"]


def build_answer_key(fixtures: list[Fixture]) -> dict:
    files = []
    for fixture in fixtures:
        entry = {
            "path": fixture.path.relative_to(REPO_ROOT).as_posix(),
            "format": fixture.file_format,
            "text_sha256": hashlib.sha256(
                fixture.parsed_text.encode("utf-8")
            ).hexdigest(),
            "findings": sorted(fixture.findings, key=lambda f: f["start"]),
            "decoys": sorted(fixture.decoys, key=lambda d: d["start"]),
        }
        files.append(entry)

    totals: dict[str, int] = {}
    for fixture in fixtures:
        for finding in fixture.findings:
            totals[finding["type"]] = totals.get(finding["type"], 0) + 1

    return {
        "schema_version": 1,
        "generator": {
            "script": "scripts/generate_test_data.py",
            "seed": SEED,
            "faker_version": faker.VERSION,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        },
        "conventions": {
            "offsets": (
                "Character indices into the text src.parsers.parse() returns "
                "for the file -- not into the file's bytes. Half-open "
                "[start, end), matching Python slicing and re spans. The two "
                "differ for csv, docx and pdf, so offsets are re-derived from "
                "parsed text after each file is written."
            ),
            "values": (
                "Included because scoring needs them and every value here is "
                "synthetic. Detector output must still redact -- see README."
            ),
            "decoys": (
                "Values that resemble PII but are not sensitive. A detector "
                "that flags one has produced a false positive."
            ),
            "matching": (
                "Prefer overlap-based matching over exact spans. Presidio may "
                "bound a PERSON or LOCATION differently than the generator did."
            ),
            "determinism": (
                "No wall-clock timestamp is recorded, so this file changes "
                "only when the corpus itself changes. The .docx and .pdf "
                "fixtures carry a fixed metadata timestamp for the same "
                "reason, though their compressed bytes are not guaranteed "
                "identical across library versions; their parsed text is."
            ),
        },
        "summary": {
            "file_count": len(fixtures),
            "finding_count": sum(len(f.findings) for f in fixtures),
            "decoy_count": sum(len(f.decoys) for f in fixtures),
            "findings_by_type": dict(sorted(totals.items())),
        },
        "files": files,
    }


def main() -> int:
    fixtures = generate()
    verify(fixtures, against="text")       # the builder composed it correctly
    write_corpus(fixtures)
    relocate_offsets(fixtures)             # ...and it survived the file format
    verify(fixtures, against="parsed_text")

    answer_key = build_answer_key(fixtures)
    ANSWER_KEY_PATH.write_text(
        json.dumps(answer_key, indent=2) + "\n", encoding="utf-8"
    )

    summary = answer_key["summary"]
    by_format: dict[str, int] = {}
    for fixture in fixtures:
        by_format[fixture.file_format] = by_format.get(fixture.file_format, 0) + 1
    print(f"Wrote {summary['file_count']} files to data/raw/")
    for file_format, count in sorted(by_format.items()):
        print(f"  .{file_format:<5} {count}")
    print(f"Recorded {summary['finding_count']} findings, {summary['decoy_count']} decoys")
    for pii_type, count in summary["findings_by_type"].items():
        print(f"  {pii_type:<16} {count:>3}")
    print(f"Answer key: {ANSWER_KEY_PATH.relative_to(REPO_ROOT)}")
    print("All spans verified against parsed text, per format.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
