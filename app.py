"""Streamlit front end for the Sensitive Data Discovery Tool.

    streamlit run app.py

Detection, parsing, scoring and reporting all live in ``src/``. This file only
collects input, calls ``scanner.scan_path``, and renders what comes back -- if
a rule about PII lived here, the CLI and the UI would eventually disagree about
what the tool found.

Uploaded files are written to a temporary directory, scanned, and deleted
before the function returns. A tool whose purpose is finding sensitive data
should not be the reason copies of it accumulate on disk.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from src.detectors import hybrid, nlp_detector
from src.parsers import SUPPORTED_EXTENSIONS
from src.reporting.report_builder import build_findings_frame, build_summary_frame
from src.reporting.risk_scorer import BANDS
from src.scanner import ScanResult, scan_path
from src.uploads import stage_and_scan

#: Extensions the uploader accepts, derived from the parsers rather than typed
#: out again, so adding a format cannot leave the UI silently refusing it.
UPLOAD_TYPES = sorted(
    ext.lstrip(".") for ext in SUPPORTED_EXTENSIONS if ext not in (".text", ".md")
)

#: Severity colours for the band column. Deliberately not the accent -- state
#: should read at a glance without being confused for a brand colour.
BAND_COLOURS = {
    "CRITICAL": "#b3261e",
    "HIGH": "#b4610f",
    "MEDIUM": "#7d6605",
    "LOW": "#41607d",
    "NONE": "#767b86",
}

st.set_page_config(
    page_title="Sensitive Data Discovery",
    page_icon="🔍",
    layout="wide",
)


@st.cache_resource(show_spinner=False)
def warm_detector():
    """Load the spaCy model once for the life of the server process.

    Without this every widget interaction reruns the script and rebuilds a
    ~560MB model, which turns a sub-second scan into a ten-second one.
    """
    return nlp_detector.get_analyzer()


def band_style(row: pd.Series) -> list[str]:
    colour = BAND_COLOURS.get(row["band"], BAND_COLOURS["NONE"])
    return [f"color: {colour}; font-weight: 600" if col == "band" else "" for col in row.index]


# --------------------------------------------------------------- sidebar

with st.sidebar:
    st.subheader("Scan source")
    source = st.radio(
        "Scan source",
        ("Upload files", "Server folder"),
        label_visibility="collapsed",
    )

    uploads: list = []
    folder = ""
    recursive = True

    if source == "Upload files":
        uploads = st.file_uploader(
            "Drag and drop files here",
            type=UPLOAD_TYPES,
            accept_multiple_files=True,
            help="TXT, CSV, DOCX and PDF. Files are deleted after the scan.",
        )
    else:
        folder = st.text_input("Folder path", value="data/raw")
        recursive = st.checkbox("Include subfolders", value=True)

    ready = bool(uploads) if source == "Upload files" else bool(folder.strip())
    label = f"Scan {len(uploads)} file{'s' if len(uploads) != 1 else ''}" if uploads else "Scan"
    run = st.button(label, type="primary", disabled=not ready, width="stretch")

    st.divider()
    st.caption(
        "Uploads are written to a temporary directory, scanned, and deleted "
        "when the scan finishes. Nothing is retained on disk."
    )
    st.caption(f"Readable formats: {', '.join(SUPPORTED_EXTENSIONS)}")


# ------------------------------------------------------------------ main

st.title("Sensitive Data Discovery")
st.caption("Hybrid regex + NLP detection across TXT, CSV, DOCX and PDF.")

if run:
    with st.spinner("Loading the language model…"):
        warm_detector()
    try:
        with st.spinner("Scanning…"):
            if source == "Upload files":
                st.session_state["result"] = stage_and_scan(uploads, hybrid.scan_text)
            else:
                st.session_state["result"] = scan_path(
                    Path(folder.strip()), detect=hybrid.scan_text, recursive=recursive
                )
        st.session_state["scanned_at"] = datetime.now(timezone.utc)
    except (FileNotFoundError, NotADirectoryError) as error:
        st.session_state.pop("result", None)
        st.error(f"{error}. Check the path and try again.")

result: ScanResult | None = st.session_state.get("result")

if result is None:
    st.info(
        "Drop files into the sidebar, or point the scanner at a folder, then "
        "press **Scan**. Try `data/raw` for the bundled synthetic corpus."
    )
    st.stop()

scanned_at = st.session_state.get("scanned_at")
summary = build_summary_frame(result.scored, scanned_at)
findings = build_findings_frame(result.scored, scanned_at)

bands = {band: int((summary["band"] == band).sum()) for band in BANDS}
columns = st.columns(4)
columns[0].metric("Files scanned", len(result.scored))
columns[1].metric("Findings", result.finding_count)
columns[2].metric("Critical", bands["CRITICAL"])
columns[3].metric("High", bands["HIGH"])

if not result.complete:
    st.warning(
        f"{len(result.failed)} file(s) could not be read. A file the scanner "
        f"could not open is not a clean file — see the details below."
    )

st.subheader("Files by risk")
if summary.empty:
    st.write("No readable files were found.")
else:
    st.dataframe(
        summary[["file", "format", "findings", "risk_score", "peak_severity", "band"]]
        .style.apply(band_style, axis=1),
        hide_index=True,
        width="stretch",
        # Sized to the result set, so a 14-file scan is read rather than
        # scrolled. Capped, because a thousand-file share must not push the
        # chart and the export buttons off the page.
        height=min(38 + 35 * len(summary), 560),
        column_config={
            "file": "File",
            "format": "Format",
            "findings": st.column_config.NumberColumn("Findings"),
            "risk_score": st.column_config.NumberColumn("Risk"),
            "peak_severity": st.column_config.NumberColumn("Peak"),
            "band": "Band",
        },
    )

st.subheader("PII types found")
if findings.empty:
    st.write("Nothing was detected in these files.")
else:
    by_type = (
        findings.groupby("pii_type", as_index=False)["count"]
        .sum()
        .sort_values("count", ascending=False)
    )
    # Altair rather than st.bar_chart, which orders categories alphabetically
    # and cannot be told otherwise. A chart answering "what is most prevalent"
    # has to be sorted by prevalence, or the reader does the ranking by eye.
    #
    # Horizontal, because the type names are long enough that vertical bars
    # would rotate the labels and make the chart harder to read than the table.
    chart = (
        alt.Chart(by_type)
        .mark_bar(cornerRadiusEnd=2)
        .encode(
            x=alt.X("count:Q", title="Findings"),
            y=alt.Y("pii_type:N", title=None, sort="-x"),
            tooltip=["pii_type", "count"],
        )
        .properties(height=alt.Step(26))
    )
    st.altair_chart(chart, width="stretch")

if result.skipped or result.failed or result.empty:
    st.subheader("Not scanned")
    if result.failed:
        with st.expander(f"{len(result.failed)} file(s) could not be read", expanded=True):
            for failure in result.failed:
                st.write(f"**{failure.path}** — {failure.reason}")
    if result.empty:
        with st.expander(f"{len(result.empty)} file(s) produced no text"):
            for path in result.empty:
                st.write(path)
            st.caption(
                "Read successfully but empty. For a PDF or an image that "
                "usually means a scan OCR could not recover — worth a look "
                "rather than treating as clean."
            )
    if result.skipped:
        with st.expander(f"{len(result.skipped)} file(s) have no extractor"):
            for path in result.skipped:
                st.write(path)
            st.caption(
                "No extractor for these extensions. Unlike a read failure, this "
                "is a known limit rather than a gap in coverage."
            )

st.subheader("Export")
st.caption("Reports carry PII types, counts and risk scores — never the values found.")
downloads = st.columns(3)
downloads[0].download_button(
    "Summary (CSV)",
    summary.to_csv(index=False),
    file_name="report.csv",
    mime="text/csv",
    width="stretch",
)
downloads[1].download_button(
    "Findings (CSV)",
    findings.to_csv(index=False),
    file_name="report.findings.csv",
    mime="text/csv",
    width="stretch",
)
downloads[2].download_button(
    "Summary (JSON)",
    json.dumps(summary.to_dict(orient="records"), indent=2),
    file_name="report.json",
    mime="application/json",
    width="stretch",
)
