"""Tests for the folder walk and the CLI.

Most of these inject a trivial detector rather than running Presidio. What is
under test is the walking, the error handling and the exit codes -- detection
accuracy is measured against the corpus elsewhere, and loading a language model
to prove that a corrupt PDF is reported would be a slow way to test the wrong
thing.

The one exception is the end-to-end test at the bottom, which is the whole
point of this phase.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import pytest

import main as cli
from src.detectors.regex_detector import scan_text as regex_scan
from src.scanner import scan_file, scan_folder, scan_path

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "data" / "raw"


@dataclass
class FakeMatch:
    pii_type: str


def no_findings(text):
    return []


def one_ssn(text):
    return [FakeMatch("US_SSN")]


@pytest.fixture
def messy(tmp_path):
    """A directory shaped like a real share: readable, unreadable, unknown."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "notes.txt").write_text("nothing here")
    (tmp_path / "sub" / "deep.txt").write_text("nor here")
    (tmp_path / "empty.txt").write_text("")
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04")
    (tmp_path / "corrupt.pdf").write_text("not a pdf at all")
    return tmp_path


# ----------------------------------------------------------- the walk


def test_scans_files_it_can_read(messy):
    result = scan_folder(messy, detect=no_findings)
    assert {r.name for r in result.scored} == {"notes.txt", "deep.txt", "empty.txt"}


def test_descends_into_subdirectories(messy):
    result = scan_folder(messy, detect=no_findings)
    assert any(r.name == "deep.txt" for r in result.scored)


def test_no_recursive_stays_at_the_top_level(messy):
    result = scan_folder(messy, detect=no_findings, recursive=False)
    assert not any(r.name == "deep.txt" for r in result.scored)


def test_unknown_extension_is_skipped_not_scanned(messy):
    result = scan_folder(messy, detect=no_findings)
    assert [Path(p).name for p in result.skipped] == ["archive.zip"]


def test_unreadable_file_is_recorded_as_failed(messy):
    """A corrupt file is neither clean nor invisible.

    This is the distinction the whole result type exists for: a file the tool
    believed it could read and could not is a gap in coverage, and a gap in
    coverage that reports as "no findings" is the failure this tool exists to
    prevent.
    """
    result = scan_folder(messy, detect=no_findings)
    assert len(result.failed) == 1
    assert Path(result.failed[0].path).name == "corrupt.pdf"
    assert not any(r.name == "corrupt.pdf" for r in result.scored)


def test_failure_reason_names_the_exception(messy):
    result = scan_folder(messy, detect=no_findings)
    assert "Exception" in result.failed[0].reason or ":" in result.failed[0].reason


def test_one_bad_file_does_not_abort_the_scan(messy):
    """The corrupt PDF sits alphabetically before two readable files."""
    result = scan_folder(messy, detect=no_findings)
    assert len(result.scored) == 3
    assert len(result.failed) == 1


def test_an_empty_file_is_scanned_not_skipped(messy):
    result = scan_folder(messy, detect=no_findings)
    empty = next(r for r in result.scored if r.name == "empty.txt")
    assert empty.finding_count == 0
    assert empty.band == "NONE"


def test_skipped_files_do_not_make_a_scan_incomplete(tmp_path):
    """No extractor for .zip is an honest answer, not a failure."""
    (tmp_path / "a.zip").write_bytes(b"PK")
    result = scan_folder(tmp_path, detect=no_findings)
    assert result.skipped and result.complete


def test_failed_files_do_make_a_scan_incomplete(messy):
    assert not scan_folder(messy, detect=no_findings).complete


def test_walk_order_is_deterministic(messy):
    first = [r.path for r in scan_folder(messy, detect=no_findings).scored]
    second = [r.path for r in scan_folder(messy, detect=no_findings).scored]
    assert first == second == sorted(first)


def test_counts_cover_every_file_seen(messy):
    result = scan_folder(messy, detect=no_findings)
    assert result.files_seen == 5


def test_findings_are_aggregated_across_files(messy):
    result = scan_folder(messy, detect=one_ssn)
    assert result.finding_count == 3


def test_scanning_a_non_directory_raises(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("x")
    with pytest.raises(NotADirectoryError):
        scan_folder(target, detect=no_findings)


# ------------------------------------------------------------ scan_path


def test_scan_path_accepts_a_single_file(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("x")
    result = scan_path(target, detect=one_ssn)
    assert len(result.scored) == 1


def test_scan_path_accepts_a_directory(messy):
    assert len(scan_path(messy, detect=no_findings).scored) == 3


def test_scan_path_reports_a_single_unreadable_file(tmp_path):
    target = tmp_path / "bad.pdf"
    target.write_text("not a pdf")
    result = scan_path(target, detect=no_findings)
    assert result.failed and not result.complete


def test_scan_path_raises_on_a_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_path(tmp_path / "nope.txt", detect=no_findings)


def test_scan_file_propagates_a_parse_error(tmp_path):
    """scan_file raises; the walk is what decides to carry on."""
    target = tmp_path / "bad.pdf"
    target.write_text("not a pdf")
    with pytest.raises(Exception):
        scan_file(target, detect=no_findings)


# ----------------------------------------------------------------- CLI


def test_cli_writes_both_reports(tmp_path):
    out = tmp_path / "report.csv"
    assert cli.main(["-i", str(CORPUS / "memo_01.txt"), "-o", str(out), "-q"]) == 0
    assert out.exists()
    assert out.with_suffix(".findings.csv").exists()


def test_cli_returns_2_for_a_missing_input(tmp_path, capsys):
    code = cli.main(["-i", str(tmp_path / "nope"), "-o", str(tmp_path / "r.csv")])
    assert code == 2
    assert "no such file" in capsys.readouterr().err


def test_cli_returns_2_for_an_unsupported_report_format(tmp_path):
    assert cli.main(["-i", str(CORPUS), "-o", str(tmp_path / "r.xlsx")]) == 2


def test_cli_returns_1_when_a_file_cannot_be_read(tmp_path):
    """A pipeline must be able to tell "found nothing" from "could not look"."""
    (tmp_path / "corrupt.pdf").write_text("not a pdf")
    assert cli.main(["-i", str(tmp_path), "-o", str(tmp_path / "r.csv"), "-q"]) == 1


def test_cli_names_unreadable_files_on_stderr(tmp_path, capsys):
    (tmp_path / "corrupt.pdf").write_text("not a pdf")
    cli.main(["-i", str(tmp_path), "-o", str(tmp_path / "r.csv"), "-q"])
    assert "corrupt.pdf" in capsys.readouterr().err


def test_cli_writes_json_when_asked(tmp_path):
    out = tmp_path / "report.json"
    cli.main(["-i", str(CORPUS / "memo_01.txt"), "-o", str(out), "-q"])
    payload = json.loads(out.read_text())
    assert isinstance(payload, list) and payload[0]["file"] == "memo_01.txt"


def test_quiet_suppresses_the_table_but_not_the_report(tmp_path, capsys):
    out = tmp_path / "report.csv"
    cli.main(["-i", str(CORPUS / "memo_01.txt"), "-o", str(out), "-q"])
    assert "BAND" not in capsys.readouterr().out
    assert out.exists()


def test_input_is_required(capsys):
    with pytest.raises(SystemExit):
        cli.main(["-o", "report.csv"])


# ------------------------------------------------------------ end to end


@pytest.fixture(scope="module")
def full_scan():
    from src.detectors import hybrid

    return scan_folder(CORPUS, detect=hybrid.scan_text)


def test_end_to_end_scan_reads_every_corpus_file(full_scan):
    """File count comes from the answer key, so growing the corpus is not a
    test failure -- only a mismatch between what exists and what was read."""
    key = json.loads((REPO_ROOT / "data" / "answer_key.json").read_text())
    assert len(full_scan.scored) == len(key["files"])
    assert full_scan.complete
    assert not full_scan.skipped
    assert not full_scan.empty


def test_end_to_end_counts_match_the_answer_key(full_scan):
    """The checkpoint this phase exists for.

    Per-type totals from a real folder walk, compared against ground truth.
    Five of seven types match exactly; the two that do not are the known,
    documented discrepancies, asserted here so they cannot drift silently.
    """
    from collections import Counter

    key = json.loads((REPO_ROOT / "data" / "answer_key.json").read_text())
    truth = Counter(f["type"] for e in key["files"] for f in e["findings"])

    found = Counter()
    for result in full_scan.scored:
        found.update(result.counts)

    for pii_type in ("US_SSN", "CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION"):
        assert found[pii_type] == truth[pii_type], pii_type

    # Two PERSON values the NER misses: a To: header and a Dear salutation.
    assert found["PERSON"] == truth["PERSON"] - 2
    # Five planted version strings that look exactly like IP addresses.
    assert found["IP_ADDRESS"] == truth["IP_ADDRESS"] + 5


def test_end_to_end_scans_all_four_formats(full_scan):
    assert {r.file_format for r in full_scan.scored} == {"txt", "csv", "docx", "pdf"}


def test_end_to_end_exercises_every_risk_band(full_scan):
    """The corpus reaches all five bands, not just the severe two.

    Until low-severity and clean fixtures were added, every file carried an
    SSN, so LOW, MEDIUM and NONE were unreachable from real data and only
    unit tests ever touched them.
    """
    from src.reporting.risk_scorer import BANDS

    assert {result.band for result in full_scan.scored} == set(BANDS)


def test_end_to_end_report_matches_the_scan(full_scan, tmp_path):
    from src.reporting.report_builder import write_reports

    summary_path, findings_path = write_reports(full_scan.scored, tmp_path / "r.csv")
    summary = pd.read_csv(summary_path)
    findings = pd.read_csv(findings_path)

    assert len(summary) == len(full_scan.scored)
    assert summary["findings"].sum() == full_scan.finding_count
    assert findings["count"].sum() == full_scan.finding_count


def test_regex_only_scan_also_runs_end_to_end():
    """The pipeline must not be wired to one detector.

    scan_folder takes the detector as an argument; if that ever hardened into
    an import, swapping engines for a comparison would stop working.
    """
    result = scan_folder(CORPUS, detect=regex_scan)
    key = json.loads((REPO_ROOT / "data" / "answer_key.json").read_text())
    assert len(result.scored) == len(key["files"])
    assert result.finding_count > 0
