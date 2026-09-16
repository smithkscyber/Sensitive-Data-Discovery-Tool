"""Tests for the Presidio wrapper.

These assert the wrapper's contract -- entity set, threshold, Match shape,
redaction -- not Presidio's model quality. Pinning exact model output would
make the suite fail on an upstream model update that changed nothing about
this code. Accuracy is measured against the corpus in test_hybrid.py instead.
"""

from __future__ import annotations

import pytest

from src.detectors import nlp_detector
from src.detectors.regex_detector import EMAIL_ADDRESS, US_SSN, redact

PERSON = "PERSON"
LOCATION = "LOCATION"

SAMPLE = (
    "Ada Lovelace lives at 123 Main Street, Springfield, IL 62704 "
    "and her SSN is 623-98-0035."
)


@pytest.fixture(scope="module")
def matches():
    return nlp_detector.scan_text(SAMPLE)


def test_detects_a_person(matches):
    assert any(m.pii_type == PERSON for m in matches)


def test_detects_a_location(matches):
    """The capability regex cannot supply at all -- the reason for this module."""
    assert any(m.pii_type == LOCATION for m in matches)


def test_detects_structured_types_too(matches):
    assert any(m.pii_type == US_SSN for m in matches)


def test_matches_are_labelled_with_their_source(matches):
    assert all(m.source == "nlp" for m in matches)


def test_matches_carry_a_confidence_score(matches):
    assert all(0.0 < m.score <= 1.0 for m in matches)


def test_matches_are_sorted_by_position(matches):
    assert [m.start for m in matches] == sorted(m.start for m in matches)


def test_scores_respect_the_threshold(matches):
    assert all(m.score >= nlp_detector.DEFAULT_SCORE_THRESHOLD for m in matches)


def test_raising_the_threshold_cannot_add_matches():
    strict = nlp_detector.scan_text(SAMPLE, score_threshold=0.9)
    assert len(strict) <= len(nlp_detector.scan_text(SAMPLE, score_threshold=0.1))


def test_default_threshold_suppresses_weak_ssn_guesses():
    """At threshold 0 Presidio calls every nine-digit number an SSN.

    It scores those guesses around 0.05. The corpus plants 35 such employee
    numbers, and admitting them took SSN precision to 0.522.
    """
    text = "Employee number 482910375 was updated."
    assert nlp_detector.scan_text(text, score_threshold=0.0) != []
    assert nlp_detector.scan_text(text) == []


def test_empty_text_returns_no_matches():
    assert nlp_detector.scan_text("") == []


def test_analyzer_is_built_once():
    """The engine loads a large language model; per-file rebuilds would be slow."""
    assert nlp_detector.get_analyzer() is nlp_detector.get_analyzer()


def test_requested_entities_bound_the_output(matches):
    assert {m.pii_type for m in matches} <= set(nlp_detector.NLP_ENTITIES)


def test_output_carries_no_raw_values(matches):
    """A finding names a location in the file, never the value found there."""
    for match in matches:
        assert SAMPLE[match.start : match.end] not in match.redacted


def test_person_redaction_keeps_only_initials():
    assert redact(PERSON, "Ada Lovelace") == "A** L*******"


def test_location_redaction_reveals_nothing():
    """A street number alone can identify a household; there is no safe prefix."""
    assert set(redact(LOCATION, "123 Main Street, Springfield")) == {"*"}


def test_email_redaction_is_shared_with_the_regex_detector(matches):
    """Both engines must mask identically, or reports would leak inconsistently."""
    assert redact(EMAIL_ADDRESS, "ada@example.org") == "a**@example.org"
