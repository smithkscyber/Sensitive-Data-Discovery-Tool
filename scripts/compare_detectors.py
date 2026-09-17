#!/usr/bin/env python3
"""Score regex-only, NLP-only, and the merged detector on the same corpus.

    python scripts/compare_detectors.py

The three tables side by side are the evidence for the hybrid design: they
show what each engine contributes and what it costs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detectors import hybrid, nlp_detector, regex_detector
from src.evaluation import format_report, score_corpus

ALL_TYPES = sorted(set(regex_detector.SUPPORTED_TYPES) | set(nlp_detector.NLP_ENTITIES))


def main() -> int:
    runs = [
        ("Regex only", regex_detector.scan_text, regex_detector.SUPPORTED_TYPES),
        ("Presidio NLP only", nlp_detector.scan_text, nlp_detector.NLP_ENTITIES),
        ("Hybrid (regex + NLP)", hybrid.scan_text, ALL_TYPES),
    ]
    reports = []
    for title, scan, types in runs:
        report = score_corpus(scan, types)
        reports.append((title, report))
        print(format_report(report, title))
        print()

    print("=" * 72)
    print(f"{'DETECTOR':<24}{'PRECISION':>12}{'RECALL':>10}{'F1':>10}{'TP':>6}{'FP':>6}{'FN':>6}")
    print("-" * 72)
    for title, report in reports:
        t = report.totals
        print(
            f"{title:<24}{t.precision:>12.3f}{t.recall:>10.3f}{t.f1:>10.3f}"
            f"{t.true_positives:>6}{t.false_positives:>6}{t.false_negatives:>6}"
        )

    # The number that actually means something. The corpus above has been
    # tuned against repeatedly, so a perfect score on it says only that no
    # known failure mode remains. The held-out file was written by hand, scored
    # once, and is never used to adjust a pattern.
    holdout_key = Path(__file__).resolve().parents[1] / "data" / "holdout_key.json"
    if holdout_key.exists():
        holdout = score_corpus(hybrid.scan_text, ALL_TYPES, answer_key_path=holdout_key)
        h = holdout.totals
        print("-" * 72)
        print(
            f"{'Held-out (not tuned on)':<24}{h.precision:>12.3f}{h.recall:>10.3f}"
            f"{h.f1:>10.3f}{h.true_positives:>6}{h.false_positives:>6}"
            f"{h.false_negatives:>6}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
