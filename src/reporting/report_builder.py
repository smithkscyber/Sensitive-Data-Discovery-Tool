"""Build and export scan reports with pandas.

Two frames, because two questions get asked of a scan and one table answers
them badly:

* **findings** -- one row per file and PII type. Answers "what is in this
  file", and aggregates cleanly by type across a whole share.
* **summary** -- one row per file. Answers "what do I open first".

Neither frame contains a detected value. Only types, counts and scores cross
this boundary, so a report can be mailed to a reviewer or checked into a ticket
without becoming a second copy of the data it is warning about.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import pandas as pd

from src.reporting.risk_scorer import BANDS, FileRisk, rank, weight_for

FINDINGS_COLUMNS = [
    "scanned_at",
    "file",
    "path",
    "format",
    "pii_type",
    "count",
    "weight",
    "risk",
]

SUMMARY_COLUMNS = [
    "scanned_at",
    "file",
    "path",
    "format",
    "findings",
    "risk_score",
    "peak_severity",
    "band",
]


def _timestamp(scanned_at: datetime | None) -> str:
    """One ISO-8601 UTC string for the whole report.

    Stamped once and reused for every row, so a report describes a scan rather
    than a sequence of slightly different moments. Injectable because a
    wall-clock default makes output untestable.
    """
    moment = scanned_at or datetime.now(timezone.utc)
    return moment.isoformat(timespec="seconds")


def build_findings_frame(
    results: Sequence[FileRisk], scanned_at: datetime | None = None
) -> pd.DataFrame:
    """One row per (file, PII type)."""
    stamp = _timestamp(scanned_at)
    rows = [
        {
            "scanned_at": stamp,
            "file": result.name,
            "path": result.path,
            "format": result.file_format,
            "pii_type": pii_type,
            "count": count,
            "weight": weight_for(pii_type),
            "risk": weight_for(pii_type) * count,
        }
        for result in rank(results)
        for pii_type, count in sorted(result.counts.items())
    ]
    # An explicit column list keeps an empty scan's frame the same shape as a
    # populated one, so downstream code never has to special-case "no findings".
    return pd.DataFrame(rows, columns=FINDINGS_COLUMNS)


def build_summary_frame(
    results: Sequence[FileRisk], scanned_at: datetime | None = None
) -> pd.DataFrame:
    """One row per file, in triage order."""
    stamp = _timestamp(scanned_at)
    rows = [
        {
            "scanned_at": stamp,
            "file": result.name,
            "path": result.path,
            "format": result.file_format,
            "findings": result.finding_count,
            "risk_score": result.risk_score,
            "peak_severity": result.peak_severity,
            "band": result.band,
        }
        for result in rank(results)
    ]
    return pd.DataFrame(rows, columns=SUMMARY_COLUMNS)


def summarise_by_type(results: Sequence[FileRisk]) -> pd.DataFrame:
    """Totals per PII type across every file scanned."""
    frame = build_findings_frame(results)
    if frame.empty:
        return pd.DataFrame(columns=["pii_type", "count", "files", "risk"])

    grouped = (
        frame.groupby("pii_type")
        .agg(count=("count", "sum"), files=("file", "nunique"), risk=("risk", "sum"))
        .reset_index()
        .sort_values("risk", ascending=False, ignore_index=True)
    )
    return grouped


def write_report(frame: pd.DataFrame, path: Path | str) -> Path:
    """Write a frame to .csv or .json, chosen by suffix."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    suffix = out.suffix.lower()
    if suffix == ".csv":
        # index=False: the row number is an artefact of the frame, not data,
        # and an unnamed leading column confuses every spreadsheet that opens it.
        frame.to_csv(out, index=False)
    elif suffix == ".json":
        # orient="records" gives a list of objects rather than pandas' default
        # column-major dict -- the shape any other tool expects to consume.
        out.write_text(
            json.dumps(frame.to_dict(orient="records"), indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        raise ValueError(
            f"cannot write {out.suffix!r}; report formats are .csv and .json"
        )
    return out


def write_reports(
    results: Sequence[FileRisk],
    output: Path | str,
    scanned_at: datetime | None = None,
) -> list[Path]:
    """Write the summary to ``output`` and the detail beside it.

    ``report.csv`` gets ``report.findings.csv`` next to it, in the format the
    caller asked for. One flag, both views, no second command to remember.
    """
    out = Path(output)
    stamp = scanned_at or datetime.now(timezone.utc)

    summary_path = write_report(build_summary_frame(results, stamp), out)
    findings_path = write_report(
        build_findings_frame(results, stamp),
        out.with_suffix(f".findings{out.suffix}"),
    )
    return [summary_path, findings_path]


def format_summary(results: Sequence[FileRisk]) -> str:
    """Render the summary as a terminal table. Contains no PII by construction."""
    if not results:
        return "No files scanned."

    ordered = rank(results)
    width = max(len(r.name) for r in ordered)
    header = (
        f"{'FILE':<{width}}  {'FMT':<5}{'FINDINGS':>9}{'RISK':>7}{'PEAK':>6}  BAND"
    )
    lines = [header, "-" * (len(header) + 4)]
    lines.extend(
        f"{r.name:<{width}}  {r.file_format:<5}{r.finding_count:>9}"
        f"{r.risk_score:>7}{r.peak_severity:>6}  {r.band}"
        for r in ordered
    )

    totals = {band: sum(1 for r in ordered if r.band == band) for band in BANDS}
    present = ", ".join(f"{band} {n}" for band, n in totals.items() if n)
    lines += [
        "-" * (len(header) + 4),
        f"{len(ordered)} files, {sum(r.finding_count for r in ordered)} findings"
        f"  ({present})",
    ]
    return "\n".join(lines)
