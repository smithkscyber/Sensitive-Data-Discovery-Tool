"""Tests for the upload staging helper and the Streamlit app.

The app is driven through ``st.testing.v1.AppTest``, which runs the script
headlessly and exposes the widgets it produced. It cannot drop a file onto the
uploader -- that is a browser gesture -- so the staging contract is tested
directly against ``stage_and_scan`` instead, which is why that function lives
in ``src/`` rather than inside the script.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src.uploads import stage_and_scan

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "data" / "raw"


class FakeUpload:
    """Stands in for Streamlit's UploadedFile: a name and some bytes."""

    def __init__(self, name: str, data: bytes):
        self.name = name
        self._data = data

    @classmethod
    def from_path(cls, path: Path) -> "FakeUpload":
        return cls(path.name, path.read_bytes())

    def getbuffer(self) -> bytes:
        return self._data


def nothing(text):
    return []


# --------------------------------------------------------- upload staging


def test_uploads_are_scanned():
    result = stage_and_scan(
        [FakeUpload.from_path(CORPUS / "memo_01.txt")], detect=nothing
    )
    assert len(result.scored) == 1


def test_staging_directory_is_removed_after_the_scan():
    """The security claim the sidebar makes, asserted rather than asserted-in-prose.

    A tool whose job is finding sensitive data must not be the reason copies
    of it accumulate in /tmp.
    """
    before = set(glob.glob("/tmp/sdd-scan-*"))
    stage_and_scan([FakeUpload.from_path(CORPUS / "memo_01.txt")], detect=nothing)
    assert set(glob.glob("/tmp/sdd-scan-*")) - before == set()


def test_a_detector_that_raises_is_recorded_not_propagated():
    """The scanner absorbs per-file failures, so staging completes normally.

    Worth pinning because it is counter-intuitive: a detector blowing up on
    one file looks like it should abort the scan, and deliberately does not.
    """
    before = set(glob.glob("/tmp/sdd-scan-*"))

    def explode(text):
        raise RuntimeError("detector failed")

    result = stage_and_scan(
        [FakeUpload.from_path(CORPUS / "memo_01.txt")], detect=explode
    )

    assert not result.complete
    assert "RuntimeError" in result.failed[0].reason
    assert set(glob.glob("/tmp/sdd-scan-*")) - before == set()


def test_staging_directory_is_removed_even_when_an_exception_escapes():
    """Cleanup must not depend on the happy path.

    A read failure on the upload itself propagates out of ``stage_and_scan``
    rather than being caught per file, which is the case that would leak a
    staging directory if it were not inside a context manager.
    """
    before = set(glob.glob("/tmp/sdd-scan-*"))

    class Unreadable:
        name = "broken.txt"

        def getbuffer(self):
            raise OSError("upload stream died")

    with pytest.raises(OSError):
        stage_and_scan([Unreadable()], detect=nothing)

    assert set(glob.glob("/tmp/sdd-scan-*")) - before == set()


def test_results_carry_the_original_filenames():
    """Not the temp path.

    Reporting a temp path would name a directory that no longer exists, and
    would disclose the server's filesystem layout in an exported report.
    """
    result = stage_and_scan(
        [FakeUpload.from_path(CORPUS / "contacts_01.csv")], detect=nothing
    )
    assert result.scored[0].path == "contacts_01.csv"


def test_a_directory_component_in_the_name_cannot_escape_staging(tmp_path):
    """An upload named "../../etc/passwd" must not write outside the temp dir."""
    result = stage_and_scan(
        [FakeUpload("../../escaped.txt", b"nothing sensitive")], detect=nothing
    )
    assert result.scored[0].path == "escaped.txt"
    assert not (REPO_ROOT.parent / "escaped.txt").exists()


def test_every_corpus_format_survives_an_upload():
    uploads = [
        FakeUpload.from_path(CORPUS / name)
        for name in ("memo_01.txt", "contacts_01.csv", "contract_01.docx", "letter_01.pdf")
    ]
    result = stage_and_scan(uploads, detect=nothing)
    assert {r.file_format for r in result.scored} == {"txt", "csv", "docx", "pdf"}
    assert result.complete


def test_an_unreadable_upload_is_reported_not_dropped():
    result = stage_and_scan([FakeUpload("broken.pdf", b"not a pdf")], detect=nothing)
    assert not result.complete
    assert result.failed[0].path == "broken.pdf"


def test_no_uploads_scans_nothing():
    result = stage_and_scan([], detect=nothing)
    assert result.scored == [] and result.complete


# ------------------------------------------------------------- the app


@pytest.fixture
def app():
    return AppTest.from_file(str(REPO_ROOT / "app.py"), default_timeout=300)


def test_app_starts_without_error(app):
    app.run()
    assert not app.exception


def test_app_opens_with_guidance_not_an_empty_screen(app):
    """A tool that opens blank tells the reader nothing about what it does."""
    app.run()
    assert any("Scan" in info.value for info in app.info)


def test_scan_button_is_disabled_until_there_is_something_to_scan(app):
    app.run()
    app.radio[0].set_value("Upload files").run()
    assert app.button[0].disabled


def test_choosing_a_folder_enables_the_scan_button(app):
    app.run()
    app.radio[0].set_value("Server folder").run()
    assert not app.button[0].disabled


def test_folder_defaults_to_the_bundled_corpus(app):
    app.run()
    app.radio[0].set_value("Server folder").run()
    assert app.text_input[0].value == "data/raw"


def test_a_missing_folder_reports_an_error_rather_than_crashing(app):
    app.run()
    app.radio[0].set_value("Server folder").run()
    app.text_input[0].set_value("does/not/exist").run()
    app.button[0].click().run()
    assert not app.exception
    assert app.error


def test_scanning_the_corpus_renders_results(app):
    """The end-to-end path a user actually takes, through the real UI."""
    app.run()
    app.radio[0].set_value("Server folder").run()
    app.button[0].click().run()

    assert not app.exception
    key = json.loads((REPO_ROOT / "data" / "answer_key.json").read_text())
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Files scanned"] == str(len(key["files"]))
    assert int(metrics["Findings"]) > 0
    assert int(metrics["Critical"]) > 0
    assert int(metrics["High"]) > 0


def test_results_survive_a_widget_change_without_rescanning(app):
    """Results live in session state, so toggling a control does not lose them."""
    app.run()
    app.radio[0].set_value("Server folder").run()
    app.button[0].click().run()
    app.checkbox[0].set_value(False).run()
    key = json.loads((REPO_ROOT / "data" / "answer_key.json").read_text())
    assert {m.label: m.value for m in app.metric}["Files scanned"] == str(len(key["files"]))


def test_app_offers_all_three_exports(app):
    app.run()
    app.radio[0].set_value("Server folder").run()
    app.button[0].click().run()
    labels = {button.label for button in app.download_button}
    assert labels == {"Summary (CSV)", "Findings (CSV)", "Summary (JSON)"}
