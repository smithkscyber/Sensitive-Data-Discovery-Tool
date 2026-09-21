"""Score a detector against the Phase 2 answer key.

Kept separate from the detectors themselves so Phase 4 can run the identical
scoring over regex-only and regex+Presidio output. A comparison is only
meaningful if both sides are measured with the same ruler.

Spans are compared by *overlap*, not by exact equality. Two detectors can be
equally right about where a value sits and still disagree about its edges --
Presidio may include a middle initial in a PERSON span or trail a ZIP code off
a LOCATION. Demanding identical offsets would score those as simultaneous
false positives and false negatives, punishing a correct detection twice over
a disagreement about punctuation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from src.parsers import parse

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ANSWER_KEY = REPO_ROOT / "data" / "answer_key.json"


@dataclass
class TypeScore:
    """Counts and derived metrics for one PII type."""

    pii_type: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def predicted(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def actual(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def precision(self) -> float:
        """Of everything flagged, what fraction was real?

        Undefined when nothing was flagged. Reported as 1.0 there: a detector
        that stayed silent has made no false accusations.
        """
        if self.predicted == 0:
            return 1.0
        return self.true_positives / self.predicted

    @property
    def recall(self) -> float:
        """Of everything that was really there, what fraction was found?"""
        if self.actual == 0:
            return 1.0
        return self.true_positives / self.actual

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall.

        Harmonic rather than arithmetic because it refuses to be rescued by
        one strong half: flagging everything gives perfect recall and dismal
        precision, and F1 stays low, which is the honest summary.
        """
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)


@dataclass
class SpanOutcome:
    """Which gold findings were missed and which predictions were spurious.

    Returned by ``score_spans`` so a caller can attribute a miss to whatever it
    knows about that finding -- the benchmark uses it to report *which kind of
    placeholder* went unfound. Derived from the same greedy matching that
    produced the counts, so a diagnostic can never disagree with the score it
    is explaining.
    """

    missed: list[int] = field(default_factory=list)
    spurious: list[object] = field(default_factory=list)


@dataclass
class ScoreReport:
    per_type: dict[str, TypeScore] = field(default_factory=dict)
    decoy_hits: list[dict] = field(default_factory=list)
    out_of_scope: dict[str, int] = field(default_factory=dict)
    files_scored: int = 0

    @property
    def totals(self) -> TypeScore:
        combined = TypeScore("ALL")
        for score in self.per_type.values():
            combined.true_positives += score.true_positives
            combined.false_positives += score.false_positives
            combined.false_negatives += score.false_negatives
        return combined


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> int:
    """Number of characters two half-open spans share (0 if disjoint)."""
    return max(0, min(a_end, b_end) - max(a_start, b_start))


def score_spans(
    predictions: Sequence[object],
    gold: Sequence[dict],
    decoys: Sequence[dict],
    report: ScoreReport,
    source: str,
) -> SpanOutcome:
    """Match predictions to gold findings and fold the result into ``report``.

    Greedy by overlap size: each prediction claims the best unclaimed gold
    finding of the same type. Claiming matters -- without it, one prediction
    sprawling across two adjacent values would be credited twice.
    """
    unclaimed = list(range(len(gold)))
    outcome = SpanOutcome()

    for prediction in predictions:
        best_index = None
        best_overlap = 0
        for position, gold_index in enumerate(unclaimed):
            candidate = gold[gold_index]
            if candidate["type"] != prediction.pii_type:
                continue
            shared = _overlaps(
                prediction.start, prediction.end, candidate["start"], candidate["end"]
            )
            if shared > best_overlap:
                best_overlap, best_index = shared, position

        score = report.per_type.setdefault(
            prediction.pii_type, TypeScore(prediction.pii_type)
        )
        if best_index is not None:
            score.true_positives += 1
            unclaimed.pop(best_index)
            continue

        score.false_positives += 1
        outcome.spurious.append(prediction)
        # A false positive landing on a planted decoy is worth calling out by
        # name: it says which near miss fooled the detector, not just that
        # something did.
        for decoy in decoys:
            if _overlaps(
                prediction.start, prediction.end, decoy["start"], decoy["end"]
            ):
                report.decoy_hits.append(
                    {
                        "source": source,
                        "pii_type": prediction.pii_type,
                        "reason": decoy["reason"],
                        "start": prediction.start,
                    }
                )
                break

    for gold_index in unclaimed:
        missed = gold[gold_index]
        score = report.per_type.setdefault(
            missed["type"], TypeScore(missed["type"])
        )
        score.false_negatives += 1
    outcome.missed = list(unclaimed)
    return outcome


def score_corpus(
    scan: Callable[[str], Sequence[object]],
    scoreable_types: Iterable[str],
    answer_key_path: Path = DEFAULT_ANSWER_KEY,
) -> ScoreReport:
    """Run ``scan`` over every file in the answer key and score the results.

    ``scoreable_types`` bounds what the detector is held responsible for. The
    regex engine cannot find a PERSON, so counting those as misses would
    measure the plan rather than the code. They are reported under
    ``out_of_scope`` instead -- visible, but not charged against the score.
    """
    key = json.loads(Path(answer_key_path).read_text(encoding="utf-8"))
    scoreable = set(scoreable_types)
    report = ScoreReport()

    for entry in key["files"]:
        # Via parse(), never read_text(): the answer key's offsets index parsed
        # text, and half the corpus is now binary. Reading bytes here would
        # both crash on .docx and silently mismatch on .csv.
        text = parse(REPO_ROOT / entry["path"])
        gold = [f for f in entry["findings"] if f["type"] in scoreable]
        for finding in entry["findings"]:
            if finding["type"] not in scoreable:
                report.out_of_scope[finding["type"]] = (
                    report.out_of_scope.get(finding["type"], 0) + 1
                )

        score_spans(scan(text), gold, entry["decoys"], report, entry["path"])
        report.files_scored += 1

    return report


def format_report(report: ScoreReport, title: str = "Detector score") -> str:
    """Render a report as a plain-text table. Contains no PII by construction."""
    lines = [title, "=" * len(title), ""]
    header = f"{'TYPE':<16}{'FOUND':>7}{'ACTUAL':>8}{'TP':>6}{'FP':>5}{'FN':>5}{'PREC':>8}{'RECALL':>8}{'F1':>8}"
    lines += [header, "-" * len(header)]

    for pii_type in sorted(report.per_type):
        score = report.per_type[pii_type]
        lines.append(
            f"{pii_type:<16}{score.predicted:>7}{score.actual:>8}"
            f"{score.true_positives:>6}{score.false_positives:>5}"
            f"{score.false_negatives:>5}{score.precision:>8.3f}"
            f"{score.recall:>8.3f}{score.f1:>8.3f}"
        )

    totals = report.totals
    lines += [
        "-" * len(header),
        f"{'ALL':<16}{totals.predicted:>7}{totals.actual:>8}"
        f"{totals.true_positives:>6}{totals.false_positives:>5}"
        f"{totals.false_negatives:>5}{totals.precision:>8.3f}"
        f"{totals.recall:>8.3f}{totals.f1:>8.3f}",
        "",
        f"Files scored: {report.files_scored}",
    ]

    if report.out_of_scope:
        detail = ", ".join(
            f"{name} {count}" for name, count in sorted(report.out_of_scope.items())
        )
        lines.append(f"Out of scope for this detector: {detail}")

    if report.decoy_hits:
        lines.append("")
        lines.append(f"Decoys that fooled the detector ({len(report.decoy_hits)}):")
        for hit in report.decoy_hits:
            lines.append(f"  {hit['pii_type']:<14} {hit['source']} -- {hit['reason']}")

    return "\n".join(lines)
