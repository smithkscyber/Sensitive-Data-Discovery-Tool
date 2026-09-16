"""Tests for the Presidio wrapper.

These assert the wrapper's contract -- entity set, threshold, Match shape,
redaction -- not Presidio's model quality. Pinning exact model output would
make the suite fail on an upstream model update that changed nothing about
this code. Accuracy is measured against the corpus in test_hybrid.py instead.
"""

from __future__ import annotations

import re

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


# ------------------------------------------------- US address recognizer


ADDRESS_PATTERN = re.compile(nlp_detector.US_ADDRESS_REGEX)


@pytest.mark.parametrize(
    "address",
    [
        "123 Main Street, Springfield, IL 62704",
        "450 Oak Ave Apt 3B, Portland, OR 97201-1234",
        "1600 Pennsylvania Avenue NW, Washington, DC 20500",
        "77 Beacon St, Boston, MA 02108",
        "1234 W 5th Ave, New York, NY 10001",
        "900 Grand Blvd Suite 1200, Kansas City, MO 64106",
        "18 Rue St. Charles, St. Paul, MN 55102",
    ],
)
def test_address_pattern_matches_real_addresses(address):
    """Real addresses, none of which appear in the corpus.

    The recognizer was written against Faker output, so the risk worth testing
    is that it learned the generator rather than the convention.
    """
    assert ADDRESS_PATTERN.fullmatch(address)


@pytest.mark.parametrize(
    "text, why",
    [
        ("Invoice 12345 was, oddly, IN 46011", "lower-case words are not a street"),
        ("ticket 4471 opened, closed, BY 10293", "lower-case words are not a street"),
        ("we shipped 500 units, roughly, TO 90210", "lower-case words are not a street"),
        # These isolate the street-token rule: the city, state and ZIP are all
        # well-formed, so only the requirement that a street name be title-case
        # stands between the pattern and a false positive. Without them the
        # suite passed even after that constraint was removed.
        (
            "Invoice 12345 was rejected, Springfield, IL 62704",
            "a lower-case clause is not a street name",
        ),
        (
            "Order 4471 shipped late, Portland, OR 97201",
            "a lower-case clause is not a street name",
        ),
        ("Card: 4720 0566 5876 3761", "a card number has no city or state"),
        ("call 555-123-4567, then, MH 17414", "no street number and street name"),
        ("10.235.204.93", "an IP address is not an address"),
    ],
)
def test_address_pattern_rejects_near_misses(text, why):
    assert ADDRESS_PATTERN.search(text) is None, why


def test_address_pattern_generalizes_beyond_the_committed_corpus():
    """Regression guard against over-fitting.

    Generates addresses from a seed the pattern was never tuned against. A
    change that raises the corpus score by narrowing the pattern onto the
    committed fixtures will fail here.

    This tests generalization across address *instances*, not across address
    *formats* -- these are still Faker's US layout. The hand-written real
    addresses above cover format variation.
    """
    from faker import Faker

    fake = Faker("en_US")
    Faker.seed(999999)
    addresses = [
        f"{fake.street_address()}, {fake.city()}, {fake.state_abbr()} {fake.postcode()}"
        for _ in range(300)
    ]
    missed = [a for a in addresses if not ADDRESS_PATTERN.fullmatch(a)]
    assert missed == [], f"{len(missed)} of 300 unseen addresses missed"


def test_address_pattern_stays_quiet_on_ordinary_prose():
    """False-positive guard on text containing no addresses at all."""
    from faker import Faker

    fake = Faker("en_US")
    Faker.seed(123456)
    paragraphs = [fake.paragraph(nb_sentences=6) for _ in range(200)]
    fired = [p for p in paragraphs if ADDRESS_PATTERN.search(p)]
    assert fired == [], f"fired on {len(fired)} of 200 address-free paragraphs"


def test_recognizer_reports_the_whole_address_as_one_span():
    text = "Mail it to 8941 Brian Ports, West Bianca, MH 17414 by Friday."
    locations = [m for m in nlp_detector.scan_text(text) if m.pii_type == LOCATION]
    assert len(locations) == 1
    assert text[locations[0].start : locations[0].end] == (
        "8941 Brian Ports, West Bianca, MH 17414"
    )


def test_recognizer_outscores_the_models_own_fragments():
    """It must outrank the NER's 0.85 spans to win the merge's tie-breaks."""
    assert nlp_detector.US_ADDRESS_SCORE > 0.85
