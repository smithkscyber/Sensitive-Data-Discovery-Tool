"""Tests for the merge logic that reconciles the two detectors.

The merge rules are unit-tested with hand-built ``Match`` objects rather than
by running Presidio. Constructing the exact disagreement you want to test is
both faster and far more precise than hoping the model produces it.
"""

from __future__ import annotations

import pytest

from src.detectors import hybrid
from src.detectors.regex_detector import (
    CREDIT_CARD,
    EMAIL_ADDRESS,
    IP_ADDRESS,
    PHONE_NUMBER,
    US_SSN,
    Match,
)

PERSON = "PERSON"
LOCATION = "LOCATION"


def m(pii_type, start, end, source="regex", score=1.0):
    return Match(pii_type, start, end, "[redacted]", source, score)


# ------------------------------------------------------- source arbitration


def test_regex_wins_an_overlap_on_a_structured_type():
    """Both engines see a phone number; the checksum-grade source is kept.

    Regex validated the format explicitly. Presidio guessed from context and
    scored 0.4. On a type regex is authoritative for, the guess loses.
    """
    text = "call 555-123-4567 now"
    merged = hybrid.merge(
        [m(PHONE_NUMBER, 5, 17, "regex")],
        [m(PHONE_NUMBER, 5, 17, "nlp", 0.4)],
        text,
    )
    assert len(merged) == 1
    assert merged[0].source == "regex"


def test_nlp_survives_when_regex_has_no_opinion():
    text = "Ada Lovelace lives here"
    merged = hybrid.merge([], [m(PERSON, 0, 12, "nlp", 0.85)], text)
    assert [x.pii_type for x in merged] == [PERSON]
    assert merged[0].source == "nlp"


def test_nlp_structured_match_is_kept_when_regex_missed_it():
    """Regex authority only settles overlaps -- it is not a veto.

    Presidio finds some values regex's patterns do not cover. Dropping those
    outright would throw away the recall the NLP layer was added for.
    """
    text = "x" * 40
    merged = hybrid.merge(
        [m(US_SSN, 0, 11, "regex")],
        [m(CREDIT_CARD, 20, 36, "nlp", 0.9)],
        text,
    )
    assert {x.pii_type for x in merged} == {US_SSN, CREDIT_CARD}


def test_longer_span_wins_between_equally_trusted_matches():
    """A PERSON inside a LOCATION is a fragment of it, not a second finding."""
    text = "8941 Brian Ports, West Bianca, MH 17414"
    merged = hybrid.merge(
        [],
        [m(LOCATION, 0, 39, "nlp", 0.85), m(PERSON, 18, 29, "nlp", 0.85)],
        text,
    )
    assert [x.pii_type for x in merged] == [LOCATION]


def test_merged_output_never_overlaps():
    text = "y" * 60
    merged = hybrid.merge(
        [m(US_SSN, 0, 11), m(IP_ADDRESS, 20, 33)],
        [m(PERSON, 5, 15, "nlp", 0.8), m(LOCATION, 30, 45, "nlp", 0.8)],
        text,
    )
    for earlier, later in zip(merged, merged[1:]):
        assert earlier.end <= later.start


# ------------------------------------------------------------- stitching


def test_adjacent_location_fragments_are_stitched():
    """Presidio reports one address as several noun phrases.

    "123 Main Street" and "Springfield" arrive as separate LOCATION spans. One
    address should be reported as one finding.
    """
    text = "at 123 Main Street, Springfield, IL today"
    merged = hybrid.merge(
        [], [m(LOCATION, 3, 18, "nlp", 0.85), m(LOCATION, 20, 31, "nlp", 0.85)], text
    )
    assert len(merged) == 1
    assert (merged[0].start, merged[0].end) == (3, 31)


def test_adjacent_emails_are_never_stitched():
    """The case that makes stitching dangerous if applied to every type.

    Two email addresses in adjacent CSV columns are separated by exactly one
    comma -- the same gap that joins address fragments. Merging them would
    silently turn two findings into one.
    """
    text = "alice@example.com,bob@example.org"
    merged = hybrid.merge(
        [m(EMAIL_ADDRESS, 0, 17), m(EMAIL_ADDRESS, 18, 32)], [], text
    )
    assert len(merged) == 2


def test_distant_locations_are_not_stitched():
    text = "Springfield is far from Portland in the west"
    merged = hybrid.merge(
        [], [m(LOCATION, 0, 11, "nlp", 0.85), m(LOCATION, 24, 32, "nlp", 0.85)], text
    )
    assert len(merged) == 2


def test_stitching_requires_punctuation_only_in_the_gap():
    text = "Springfield or Portland"
    merged = hybrid.merge(
        [], [m(LOCATION, 0, 11, "nlp", 0.85), m(LOCATION, 15, 23, "nlp", 0.85)], text
    )
    assert len(merged) == 2


def test_empty_input_merges_to_nothing():
    assert hybrid.merge([], [], "") == []


# ------------------------------------------------- corpus-level comparison


@pytest.fixture(scope="module")
def reports():
    """Score all three detectors once; Presidio is slow to load."""
    from src.detectors import nlp_detector, regex_detector
    from src.evaluation import score_corpus

    all_types = sorted(
        set(regex_detector.SUPPORTED_TYPES) | set(nlp_detector.NLP_ENTITIES)
    )
    return {
        "regex": score_corpus(regex_detector.scan_text, regex_detector.SUPPORTED_TYPES),
        "nlp": score_corpus(nlp_detector.scan_text, nlp_detector.NLP_ENTITIES),
        "hybrid": score_corpus(hybrid.scan_text, all_types),
    }


def test_hybrid_finds_more_than_either_engine_alone(reports):
    """The claim the whole hybrid design rests on, asserted rather than assumed."""
    assert reports["hybrid"].totals.true_positives > reports["regex"].totals.true_positives
    assert reports["hybrid"].totals.true_positives > reports["nlp"].totals.true_positives


def test_hybrid_beats_nlp_alone_on_both_metrics(reports):
    nlp, merged = reports["nlp"].totals, reports["hybrid"].totals
    assert merged.precision > nlp.precision
    assert merged.recall > nlp.recall


def test_regex_authority_rescues_credit_card_recall(reports):
    """Presidio misses 2 of 8 cards; regex finds all 8, and the merge keeps them."""
    assert reports["nlp"].per_type[CREDIT_CARD].recall == 0.75
    assert reports["hybrid"].per_type[CREDIT_CARD].recall == 1.0


def test_regex_authority_removes_nlp_phone_false_positives(reports):
    """Presidio contributes 6 phone false positives; regex authority drops them."""
    assert reports["nlp"].per_type[PHONE_NUMBER].false_positives == 6
    assert reports["hybrid"].per_type[PHONE_NUMBER].false_positives == 0


def test_address_recognizer_makes_location_exact(reports):
    """Every address found, nothing else called an address."""
    location = reports["hybrid"].per_type[LOCATION]
    assert location.precision == 1.0
    assert location.recall == 1.0


def test_merge_is_what_clears_the_person_false_positives(reports):
    """Neither the recognizer nor the merge fixes PERSON precision alone.

    Presidio still emits dozens of spurious PERSON spans -- Faker builds street
    and city names out of personal names ("Darren Locks", "West Bianca"), and the
    NER reads them as people. Adding the address recognizer does not stop it
    doing that; Presidio does not reconcile its own overlapping opinions.

    What removes them is the combination: the recognizer supplies a full
    address span, and the merge's longest-span rule then treats the PERSON
    sitting inside it as a fragment. That is the whole argument for having a
    merge layer rather than trusting one engine's output.

    Asserted as a relationship rather than an exact count. The NLP figure is
    currently 27 and moves for reasons unrelated to this behaviour -- it was 28
    until the CSV parser started stripping quotes, which changed one NER
    decision. Pinning it would turn an unrelated parser change into a failure
    here, while a bound still fails loudly if the merge stops doing its job.
    """
    assert reports["nlp"].per_type[PERSON].false_positives >= 20
    assert reports["hybrid"].per_type[PERSON].false_positives == 0


def test_hybrid_has_no_false_positives_outside_the_ip_decoys(reports):
    """The only remaining false positives are the documented version strings."""
    totals = reports["hybrid"].totals
    assert totals.false_positives == 5
    assert all(hit["pii_type"] == "IP_ADDRESS" for hit in reports["hybrid"].decoy_hits)
