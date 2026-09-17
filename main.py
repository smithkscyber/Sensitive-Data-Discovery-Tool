#!/usr/bin/env python3
"""Command-line entry point for the Sensitive Data Discovery Tool.

    python main.py --input data/raw --output report.csv

Writes two reports: a per-file summary in triage order, and the per-type detail
beside it. Neither contains a detected value.

Exit codes matter here, because this is the kind of tool that ends up in a
pipeline:

    0  every file was read, whether or not anything was found
    1  at least one file could not be read
    2  bad arguments, or the input path does not exist

A scan that found nothing and a scan that could not read half the share must
not look the same to a caller, so an unreadable file is a non-zero exit rather
than a line of output somebody might miss.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.reporting.report_builder import format_summary, summarise_by_type, write_reports
from src.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Scan documents for personally identifiable information.",
        epilog=(
            "All output is redacted: reports carry PII types, counts and risk "
            "scores, never the values found."
        ),
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        type=Path,
        metavar="PATH",
        help="file or directory to scan",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("report.csv"),
        metavar="PATH",
        help="report path, .csv or .json (default: report.csv). "
        "The per-type detail is written alongside as PATH.findings.EXT",
    )
    parser.add_argument(
        "--no-recursive",
        dest="recursive",
        action="store_false",
        help="do not descend into subdirectories",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="write the reports without printing the summary table",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.input.exists():
        print(f"error: no such file or directory: {args.input}", file=sys.stderr)
        return 2
    if args.output.suffix.lower() not in (".csv", ".json"):
        print(
            f"error: report format {args.output.suffix or '(none)'!r} is not "
            f"supported; use .csv or .json",
            file=sys.stderr,
        )
        return 2

    result = scan_path(args.input, recursive=args.recursive)
    written = write_reports(
        result.scored, args.output, datetime.now(timezone.utc)
    )

    if not args.quiet:
        print(format_summary(result.scored))
        if result.scored:
            print()
            print(summarise_by_type(result.scored).to_string(index=False))

    if result.skipped:
        print(
            f"\nSkipped {len(result.skipped)} file(s) with no extractor:",
            file=sys.stderr,
        )
        for path in result.skipped:
            print(f"  {path}", file=sys.stderr)

    if result.empty:
        # Not an error: an empty file is legitimately empty. But a PDF or an
        # image that yields nothing is usually a scan OCR could not read, and
        # that must not pass as a clean result.
        print(
            f"\nNo text could be extracted from {len(result.empty)} file(s):",
            file=sys.stderr,
        )
        for path in result.empty:
            print(f"  {path}", file=sys.stderr)

    if result.failed:
        # To stderr and non-zero: these files were not scanned, and treating
        # them as clean is the failure this tool exists to prevent.
        print(f"\nFailed to read {len(result.failed)} file(s):", file=sys.stderr)
        for failure in result.failed:
            print(f"  {failure.path}: {failure.reason}", file=sys.stderr)

    print(f"\nReports written:")
    for path in written:
        print(f"  {path}")

    return 0 if result.complete else 1


if __name__ == "__main__":
    sys.exit(main())
