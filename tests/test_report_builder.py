"""Tests for the pandas reporting layer.

The load-bearing property is the one at the bottom: a report describes
sensitive data without containing any. Everything else is shape and plumbing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.reporting import report_builder as rb
from src.reporting.risk_scorer import score_file

STAMP = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class FakeMatch:
    pii_type: str


def matches(**counts):
    return [FakeMatch(t) for t, n in counts.items() for _ in range(n)]


@pytest.fixture
def results():
    return [
        score_file("data/raw/contacts_01.csv", matches(US_SSN=8, EMAIL_ADDRESS=8)),
        score_file("data/raw/memo_01.txt", matches(PERSON=4, IP_ADDRESS=2)),
        score_file("data/raw/clean.txt", []),
    ]


# ---------------------------------------------------------------- shape


def test_findings_frame_has_one_row_per_file_and_type(results):
    frame = rb.build_findings_frame(results, STAMP)
    assert list(frame.columns) == rb.FINDINGS_COLUMNS
    assert len(frame) == 4  # 2 types + 2 types + nothing for the clean file


def test_summary_frame_has_one_row_per_file(results):
    frame = rb.build_summary_frame(results, STAMP)
    assert list(frame.columns) == rb.SUMMARY_COLUMNS
    assert len(frame) == 3


def test_a_clean_file_still_appears_in_the_summary(results):
    """Absence of findings is a result, not a reason to omit the row.

    A file missing from the report is indistinguishable from a file that was
    never scanned.
    """
    frame = rb.build_summary_frame(results, STAMP)
    clean = frame[frame["file"] == "clean.txt"].iloc[0]
    assert clean["findings"] == 0
    assert clean["band"] == "NONE"


def test_summary_is_in_triage_order(results):
    frame = rb.build_summary_frame(results, STAMP)
    assert list(frame["file"]) == ["contacts_01.csv", "memo_01.txt", "clean.txt"]


def test_empty_scan_produces_empty_frames_not_a_crash():
    """Shape must not depend on content, or callers need a special case."""
    assert list(rb.build_findings_frame([], STAMP).columns) == rb.FINDINGS_COLUMNS
    assert list(rb.build_summary_frame([], STAMP).columns) == rb.SUMMARY_COLUMNS
    assert rb.build_findings_frame([], STAMP).empty


def test_risk_column_is_weight_times_count(results):
    frame = rb.build_findings_frame(results, STAMP)
    assert (frame["risk"] == frame["weight"] * frame["count"]).all()


def test_one_timestamp_for_the_whole_report(results):
    """A report describes a scan, not a sequence of slightly different moments."""
    frame = rb.build_summary_frame(results, STAMP)
    assert frame["scanned_at"].nunique() == 1
    assert frame["scanned_at"].iloc[0] == "2026-09-17T12:00:00+00:00"


def test_timestamp_defaults_to_now(results):
    frame = rb.build_summary_frame(results)
    assert frame["scanned_at"].iloc[0].startswith("20")


# --------------------------------------------------------------- totals


def test_summarise_by_type_aggregates_across_files(results):
    totals = rb.summarise_by_type(results)
    ssn = totals[totals["pii_type"] == "US_SSN"].iloc[0]
    assert ssn["count"] == 8
    assert ssn["files"] == 1
    assert ssn["risk"] == 80


def test_summarise_by_type_sorts_by_risk(results):
    totals = rb.summarise_by_type(results)
    assert list(totals["risk"]) == sorted(totals["risk"], reverse=True)


def test_summarise_by_type_on_an_empty_scan():
    assert rb.summarise_by_type([]).empty


# --------------------------------------------------------------- export


def test_writes_csv_without_an_index_column(results, tmp_path):
    out = rb.write_report(rb.build_summary_frame(results, STAMP), tmp_path / "r.csv")
    first_line = out.read_text().splitlines()[0]
    assert first_line.startswith("scanned_at,")


def test_writes_json_as_a_list_of_records(results, tmp_path):
    out = rb.write_report(rb.build_summary_frame(results, STAMP), tmp_path / "r.json")
    payload = json.loads(out.read_text())
    assert isinstance(payload, list)
    assert payload[0]["file"] == "contacts_01.csv"


def test_csv_and_json_carry_the_same_rows(results, tmp_path):
    frame = rb.build_summary_frame(results, STAMP)
    csv_path = rb.write_report(frame, tmp_path / "r.csv")
    json_path = rb.write_report(frame, tmp_path / "r.json")
    import pandas as pd

    from_csv = pd.read_csv(csv_path)
    from_json = pd.DataFrame(json.loads(json_path.read_text()))
    assert list(from_csv["file"]) == list(from_json["file"])
    assert list(from_csv["risk_score"]) == list(from_json["risk_score"])


def test_unsupported_output_format_raises(results, tmp_path):
    with pytest.raises(ValueError, match="csv"):
        rb.write_report(rb.build_summary_frame(results, STAMP), tmp_path / "r.xlsx")


def test_write_reports_emits_summary_and_detail(results, tmp_path):
    paths = rb.write_reports(results, tmp_path / "report.csv", STAMP)
    assert [p.name for p in paths] == ["report.csv", "report.findings.csv"]
    assert all(p.exists() for p in paths)


def test_write_reports_creates_missing_directories(results, tmp_path):
    paths = rb.write_reports(results, tmp_path / "deep" / "nested" / "report.json", STAMP)
    assert all(p.exists() for p in paths)


def test_format_summary_handles_an_empty_scan():
    assert rb.format_summary([]) == "No files scanned."


def test_format_summary_names_every_file(results):
    rendered = rb.format_summary(results)
    for result in results:
        assert result.name in rendered


# ------------------------------------------------- the property that matters


def test_a_real_report_contains_no_detected_value(tmp_path):
    """Scan the corpus for real, then prove the report leaks nothing.

    This is the one test that would catch a well-meaning "include a sample of
    what was found" column turning every report into a second copy of the data
    it exists to warn about.
    """
    import warnings

    warnings.filterwarnings("ignore")
    from src.detectors import hybrid
    from src.parsers import is_supported, parse

    key = json.loads((REPO_ROOT / "data" / "answer_key.json").read_text())
    planted = {
        finding["value"]
        for entry in key["files"]
        for finding in entry["findings"]
    }

    scanned = [
        score_file(path, hybrid.scan_text(parse(path)))
        for path in sorted((REPO_ROOT / "data" / "raw").iterdir())
        if path.is_file() and is_supported(path)
    ]
    assert scanned, "corpus should not be empty"

    written = rb.write_reports(scanned, tmp_path / "report.csv", STAMP)
    blob = "\n".join(p.read_text() for p in written)
    blob += "\n" + rb.format_summary(scanned)

    leaked = sorted(value for value in planted if value in blob)
    assert leaked == [], f"{len(leaked)} planted value(s) reached the report"
