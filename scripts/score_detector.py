#!/usr/bin/env python3
"""Score the regex detector against the answer key and print the result.

    python scripts/score_detector.py

Phase 4 reruns this with the merged regex+Presidio detector to quantify what
the NLP layer actually buys.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detectors.regex_detector import SUPPORTED_TYPES, scan_text
from src.evaluation import format_report, score_corpus


def main() -> int:
    report = score_corpus(scan_text, SUPPORTED_TYPES)
    print(format_report(report, "Regex detector (Phase 3 baseline)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
