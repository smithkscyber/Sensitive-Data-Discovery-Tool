"""Turn detector findings into a per-file risk score.

A scan of a real file share returns thousands of findings, and nobody reads
thousands of findings. The point of a score is triage: which files does someone
open first. That makes the scoring rule a judgement about *harm*, not a
statistic, and it should be written down where a reviewer can argue with it.

Scores here are ordinal, not absolute. A file scoring 80 is not "twice as bad"
as one scoring 40 in any measurable sense; it sorts above it, which is all a
queue needs.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

#: Harm if this single value leaked, on a 0-10 scale.
#:
#: The ordering is the substance, and the reasoning is what makes it arguable:
#:
#: US_SSN (10)         permanent and effectively non-reissuable. A leaked SSN
#:                     is a lifetime identity-theft exposure.
#: CREDIT_CARD (9)     direct financial loss, but a card can be cancelled and
#:                     reissued within days, so the harm has a floor.
#: LOCATION (5)        a home address enables physical-world harm and is
#:                     directly identifying in a way contact details are not.
#: EMAIL_ADDRESS (3)   contact detail and account identifier; the hinge for
#:                     password resets, which is why it outranks a phone.
#: IP_ADDRESS (3)      a quasi-identifier -- personal data under GDPR, but of
#:                     little use on its own.
#: PHONE_NUMBER (2)    widely circulated already; a SIM-swap vector, not a
#:                     standalone disclosure.
#: PERSON (2)          a name alone is often public. It scores low on its own
#:                     and matters enormously as the key that makes every other
#:                     value on the page identifying.
RISK_WEIGHTS: Mapping[str, int] = {
    "US_SSN": 10,
    "CREDIT_CARD": 9,
    "LOCATION": 5,
    "EMAIL_ADDRESS": 3,
    "IP_ADDRESS": 3,
    "PHONE_NUMBER": 2,
    "PERSON": 2,
}

#: Applied to a type with no entry above. Mid-scale rather than 0 so that
#: adding a detector without updating this table makes files look more
#: suspicious, not less. Scoring an unknown type as harmless would let a new
#: detector quietly reduce a file's rank.
DEFAULT_WEIGHT = 5

#: Ordered least to most severe; the index is the comparison.
BANDS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

#: Total-score thresholds, lowest band first. Volume escalation lives here.
_BAND_BY_TOTAL = ((100, "CRITICAL"), (30, "HIGH"), (10, "MEDIUM"), (1, "LOW"))

#: Severity floors: the band a file gets for *containing one* of something,
#: whatever the volume. This is what stops a page of email addresses
#: outranking a single leaked SSN.
_BAND_FLOOR_BY_SEVERITY = ((9, "HIGH"), (5, "MEDIUM"), (1, "LOW"))


@dataclass(frozen=True)
class FileRisk:
    """One file's scored result. Carries counts and scores, never values."""

    path: str
    file_format: str
    counts: Mapping[str, int]
    finding_count: int
    risk_score: int
    peak_severity: int
    band: str

    @property
    def name(self) -> str:
        return Path(self.path).name


def weight_for(pii_type: str) -> int:
    return RISK_WEIGHTS.get(pii_type, DEFAULT_WEIGHT)


def band_for(risk_score: int, peak_severity: int) -> str:
    """Classify a file, taking the worse of two views.

    Summing weight x count is the obvious rule and it has an obvious failure:
    volume drowns severity. In this project's own corpus, ``memo_01.txt``
    scores 37 on eleven low-severity findings while ``letter_01.pdf`` scores 33
    while holding a Social Security number *and* a credit card. Sorted by total
    alone, the memo is triaged first, which is the wrong answer.

    So a file is also never ranked below its single most sensitive item: one
    SSN puts a file in HIGH no matter how quiet the rest of it is. Volume can
    still escalate from there -- that is what carries the contact CSVs, three
    hundred values of moderate severity apiece, up into CRITICAL.
    """
    from_total = "NONE"
    for threshold, band in _BAND_BY_TOTAL:
        if risk_score >= threshold:
            from_total = band
            break

    floor = "NONE"
    for threshold, band in _BAND_FLOOR_BY_SEVERITY:
        if peak_severity >= threshold:
            floor = band
            break

    return max(from_total, floor, key=BANDS.index)


def score_counts(counts: Mapping[str, int]) -> int:
    """Weighted sum of findings. Linear in count, by type."""
    return sum(weight_for(pii_type) * n for pii_type, n in counts.items())


def score_file(
    path: Path | str,
    matches: Iterable[object],
    file_format: str | None = None,
) -> FileRisk:
    """Score one file's findings.

    ``matches`` is any iterable of objects with a ``pii_type`` -- the
    ``Match`` objects either detector produces. Only the type is read, so a
    scored result cannot contain a value even by accident.
    """
    file_path = Path(path)
    counts = Counter(match.pii_type for match in matches)
    risk_score = score_counts(counts)
    peak_severity = max((weight_for(t) for t in counts), default=0)

    return FileRisk(
        path=file_path.as_posix(),
        file_format=(file_format or file_path.suffix.lstrip(".")).lower(),
        counts=dict(sorted(counts.items())),
        finding_count=sum(counts.values()),
        risk_score=risk_score,
        peak_severity=peak_severity,
        band=band_for(risk_score, peak_severity),
    )


def rank(results: Sequence[FileRisk]) -> list[FileRisk]:
    """Sort into the order someone should work the queue in.

    Band first, then score, then name. Band leads because it already encodes
    the severity floor; sorting by raw score alone would reintroduce exactly
    the distortion ``band_for`` exists to correct.
    """
    return sorted(
        results,
        key=lambda r: (-BANDS.index(r.band), -r.risk_score, r.name),
    )
