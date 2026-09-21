"""Score the detectors on third-party text rather than on our own corpus.

    python scripts/benchmark_external.py                 # default run
    python scripts/benchmark_external.py --limit 2090    # ten identities each
    python scripts/benchmark_external.py --quick         # hybrid only, US only

Why this exists is in ``src/benchmark``'s docstring. The short version: every
figure measured against ``data/raw`` is this project grading its own homework,
because the sentences were written here. The templates behind this benchmark
were not, and the detectors were never shown them during development.

Nothing printed here contains a personal value. Misses and false positives are
reported by *placeholder* -- the slot the value came from -- which says far
more about the failure than the text would, and keeps the no-raw-PII rule
intact.
"""

from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import benchmark
from src.detectors import hybrid, nlp_detector, regex_detector
from src.evaluation import ScoreReport, format_report, score_spans

DETECTORS = {
    "Regex only": (regex_detector.scan_text, frozenset(regex_detector.SUPPORTED_TYPES)),
    "Presidio NLP only": (nlp_detector.scan_text, frozenset(nlp_detector.NLP_ENTITIES)),
    "Hybrid (regex + NLP)": (hybrid.scan_text, benchmark.SCOREABLE_TYPES),
}


def run(name, scan, scoreable, sentences):
    """Score one detector over the rendered sentences.

    ``scoreable`` bounds what the detector is answerable for, exactly as
    ``score_corpus`` does it: charging the regex engine with missing a PERSON
    would measure the design rather than the code.
    """
    report = ScoreReport()
    gold_by_slot = collections.Counter()
    missed_by_slot = collections.Counter()
    fp_by_placeholder = collections.Counter()
    missed_by_template = collections.Counter()

    for sentence in sentences:
        gold = [f for f in sentence.findings if f["type"] in scoreable]
        for finding in sentence.findings:
            if finding["type"] not in scoreable:
                report.out_of_scope[finding["type"]] = (
                    report.out_of_scope.get(finding["type"], 0) + 1
                )

        for finding in gold:
            gold_by_slot[(finding["type"], finding["placeholder"])] += 1

        outcome = score_spans(scan(sentence.text), gold, [], report, name)
        report.files_scored += 1

        for index in outcome.missed:
            missed_by_slot[(gold[index]["type"], gold[index]["placeholder"])] += 1
            missed_by_template[sentence.template_index] += 1

        for prediction in outcome.spurious:
            landed = next(
                (
                    d["placeholder"]
                    for d in sentence.distractors
                    if d["start"] < prediction.end and prediction.start < d["end"]
                ),
                "(unplanted text)",
            )
            fp_by_placeholder[(prediction.pii_type, landed)] += 1

    return report, (gold_by_slot, missed_by_slot), fp_by_placeholder, missed_by_template


def _recall_by_slot(gold_by_slot, missed_by_slot, floor=4):
    """Recall for each kind of value, worst first.

    This is the table that answers "when is it good and when is it not", and
    it is why the benchmark records which placeholder every value came from.
    An aggregate LOCATION recall of 0.728 is a number; "complete addresses
    1.000, bare unit numbers 0.000" is an explanation.
    """
    title = "Recall by source slot (worst first)"
    lines = [title, "-" * len(title), f"  {'RECALL':>7}  {'FOUND':>6}  {'OF':>5}  TYPE / SLOT"]
    rows = []
    for key, total in gold_by_slot.items():
        if total < floor:
            continue
        found = total - missed_by_slot.get(key, 0)
        rows.append((found / total, found, total, key))
    for recall, found, total, (pii_type, slot) in sorted(rows):
        lines.append(f"  {recall:>7.3f}  {found:>6}  {total:>5}  {pii_type:<14} {{{{{slot}}}}}")
    return lines + [""]


def _breakdown(title, counter, limit=12):
    if not counter:
        return [f"{title}: none", ""]
    lines = [title, "-" * len(title)]
    for (pii_type, slot), count in counter.most_common(limit):
        lines.append(f"  {count:>4}  {pii_type:<14} {{{{{slot}}}}}")
    remainder = sum(counter.values()) - sum(c for _, c in counter.most_common(limit))
    if remainder:
        lines.append(f"  {remainder:>4}  (other slots)")
    return lines + [""]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit",
        type=int,
        default=1045,
        help="sentences to render per region (default: 1045, five per template)",
    )
    parser.add_argument(
        "--quick", action="store_true", help="hybrid detector, US identities only"
    )
    parser.add_argument(
        "--detail", action="store_true", help="also list the worst-performing templates"
    )
    args = parser.parse_args()

    regions = [("US identities", True)]
    if not args.quick:
        regions.append(("Non-US identities (scope probe)", False))

    for region_name, us_only in regions:
        sentences = benchmark.build(limit=args.limit, us_only=us_only)
        gold_total = sum(len(s.findings) for s in sentences)
        distractor_total = sum(len(s.distractors) for s in sentences)

        banner = f"  {region_name}  "
        print()
        print("=" * len(banner))
        print(banner)
        print("=" * len(banner))
        print(
            f"{len(sentences)} sentences from "
            f"{len({s.template_index for s in sentences})} third-party templates · "
            f"{gold_total} labelled entities · {distractor_total} unlabelled distractors"
        )

        chosen = (
            {"Hybrid (regex + NLP)": DETECTORS["Hybrid (regex + NLP)"]}
            if args.quick or not us_only
            else DETECTORS
        )
        for name, (scan, scoreable) in chosen.items():
            report, (gold_by_slot, missed), spurious, by_template = run(
                name, scan, scoreable, sentences
            )
            print()
            print(format_report(report, f"{name} — {region_name}"))
            print()
            print("\n".join(_recall_by_slot(gold_by_slot, missed)))
            print("\n".join(_breakdown("False positives, by slot landed on", spurious)))
            if args.detail and by_template:
                templates = benchmark.load_templates()
                print("Templates with the most misses")
                print("-" * 30)
                for index, count in by_template.most_common(8):
                    shape = templates[index].replace("\n", "\\n")[:88]
                    print(f"  {count:>3}  #{index:<4} {shape}")
                print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
