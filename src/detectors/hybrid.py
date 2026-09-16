"""Combine the regex and NLP detectors into one result set.

Neither engine dominates. Measured over the full corpus, each is better at
something the other handles badly:

    type            regex                 Presidio
    US_SSN          P 1.000  R 1.000      P 1.000  R 1.000
    CREDIT_CARD     P 1.000  R 1.000      P 1.000  R 0.750
    EMAIL_ADDRESS   P 1.000  R 1.000      P 1.000  R 1.000
    PHONE_NUMBER    P 1.000  R 1.000      P 0.850  R 0.971
    IP_ADDRESS      P 0.500  R 1.000      not supported
    PERSON          not supported         P 0.682  R 0.968
    LOCATION        not supported         P 0.694  R 0.714

So the merge is not "run both and concatenate". It is a set of rules about who
to believe when they disagree, and those rules follow the table: regex wins on
the structured identifiers, where it is checksum- and format-validated, and
Presidio is the only source for the contextual entities.
"""

from __future__ import annotations

from src.detectors import nlp_detector, regex_detector
from src.detectors.regex_detector import Match

#: Types the regex engine validates structurally -- a Luhn checksum, real SSN
#: issuance rules, octet ranges. Where both engines fire on the same span for
#: one of these, the regex verdict is the better-evidenced one.
REGEX_AUTHORITATIVE = frozenset(regex_detector.SUPPORTED_TYPES)

#: Multi-token entities that Presidio reports in fragments. Presidio reads
#: "123 Main Street, Springfield, IL 62704" as two separate LOCATION spans --
#: the street and the city -- because they are separate noun phrases. One
#: address is one finding, so these are stitched back together.
STITCHABLE = frozenset({nlp_detector.LOCATION})

#: The widest gap that may be bridged when stitching, and what may sit in it.
#: A comma and a space between two LOCATION fragments is a continuing address;
#: anything longer, or containing anything else, is two separate places.
_STITCH_GAP = 2
_STITCH_FILLER = set(", \t")


def _source_rank(match: Match) -> int:
    """Lower sorts first, and sorting first means winning an overlap."""
    if match.pii_type in REGEX_AUTHORITATIVE:
        return 0 if match.source == "regex" else 1
    return 0


def _resolve(matches: list[Match]) -> list[Match]:
    """Keep the best match from each set of overlapping candidates.

    Ordering decides the outcome: preferred source first, then the longer span
    (it explains more of the text), then the more confident score.
    """
    ranked = sorted(
        matches,
        key=lambda m: (_source_rank(m), -(m.end - m.start), -m.score, m.start),
    )
    kept: list[Match] = []
    for candidate in ranked:
        if any(
            candidate.start < other.end and other.start < candidate.end
            for other in kept
        ):
            continue
        kept.append(candidate)
    return sorted(kept, key=lambda m: (m.start, m.pii_type))


def _stitch(matches: list[Match], text: str) -> list[Match]:
    """Join same-type fragments of one entity into a single match.

    Restricted to ``STITCHABLE`` types and to gaps of punctuation. Applying
    this to every type would be actively wrong: two consecutive email
    addresses in a CSV row are separated by exactly one comma, and merging
    them would turn two findings into one.
    """
    if not matches:
        return []

    out: list[Match] = []
    current = matches[0]
    for candidate in matches[1:]:
        gap = text[current.end : candidate.start]
        if (
            candidate.pii_type == current.pii_type
            and current.pii_type in STITCHABLE
            and len(gap) <= _STITCH_GAP
            and set(gap) <= _STITCH_FILLER
        ):
            merged_text = text[current.start : candidate.end]
            current = Match(
                pii_type=current.pii_type,
                start=current.start,
                end=candidate.end,
                redacted=regex_detector.redact(current.pii_type, merged_text),
                source=current.source,
                score=min(current.score, candidate.score),
            )
            continue
        out.append(current)
        current = candidate
    out.append(current)
    return out


def merge(regex_matches: list[Match], nlp_matches: list[Match], text: str) -> list[Match]:
    """Reconcile two detectors' output into one non-overlapping result set."""
    combined = _resolve(list(regex_matches) + list(nlp_matches))
    return _stitch(combined, text)


def scan_text(text: str) -> list[Match]:
    """Run both detectors over ``text`` and return the merged findings.

    This is the entry point Phase 7's scanner calls per file.
    """
    return merge(
        regex_detector.scan_text(text), nlp_detector.scan_text(text), text
    )
