"""Tests for the regex detector.

Two layers, and the distinction matters:

* **Unit tests** pin each pattern's behaviour on hand-written cases, including
  the near misses it must reject. They are fast, and they fail with a message
  that says which pattern broke.
* **Corpus tests** score the assembled detector against the Phase 2 answer key.
  They catch what unit tests cannot -- interactions between patterns, and drift
  in overall accuracy -- but a failure says only "the number moved".

The unit cases here deliberately include values the corpus does not contain.
An earlier version of the IP pattern scored perfectly on the corpus while
silently missing every address that ended a sentence, because the generator
happened never to place one there. A corpus proves what it contains and
nothing more.
"""

from __future__ import annotations

import pytest

from src.detectors.regex_detector import (
    CREDIT_CARD,
    EMAIL_ADDRESS,
    IP_ADDRESS,
    PHONE_NUMBER,
    SUPPORTED_TYPES,
    US_SSN,
    find_credit_cards,
    find_emails,
    find_ip_addresses,
    find_phones,
    find_ssns,
    luhn_valid,
    redact,
    scan_text,
)
from src.evaluation import score_corpus


def spans(matches):
    return [(m.start, m.end) for m in matches]


# ---------------------------------------------------------------- SSN


@pytest.mark.parametrize(
    "text",
    [
        "SSN 623-98-0035 on file",
        "623-98-0035",
        "ends the sentence 623-98-0035.",
        "(623-98-0035)",
    ],
)
def test_ssn_found(text):
    assert len(find_ssns(text)) == 1


@pytest.mark.parametrize(
    "text, why",
    [
        ("482910375", "nine digits with no separators is not this pattern"),
        ("000-12-3456", "area 000 is never issued"),
        ("666-12-3456", "area 666 is never issued"),
        ("900-12-3456", "areas 900-999 are never issued"),
        ("123-00-4567", "group 00 is never issued"),
        ("123-45-0000", "serial 0000 is never issued"),
        ("1623-98-0035", "a longer digit run, not an SSN"),
        ("623-98-00351", "a longer digit run, not an SSN"),
        ("623-9-0035", "wrong group length"),
    ],
)
def test_ssn_rejected(text, why):
    assert find_ssns(text) == [], why


# ---------------------------------------------------------------- email


@pytest.mark.parametrize(
    "text",
    [
        "mail zadams@example.org today",
        "at the end: zadams@example.org.",
        "<zadams@example.org>",
        "first.last+tag@sub.example.co.uk",
    ],
)
def test_email_found(text):
    assert len(find_emails(text)) == 1


@pytest.mark.parametrize(
    "text", ["not-an-email@", "@example.org", "plain.text.no.at.sign", "a@b"]
)
def test_email_rejected(text):
    assert find_emails(text) == []


def test_email_stops_at_trailing_period():
    (match,) = find_emails("write to zadams@example.org.")
    assert match.end == len("write to zadams@example.org")


# ---------------------------------------------------------------- phone


@pytest.mark.parametrize(
    "text", ["(555) 123-4567", "555-123-4567", "555.123.4567", "call 555-123-4567."]
)
def test_phone_found(text):
    assert len(find_phones(text)) == 1


@pytest.mark.parametrize(
    "text, why",
    [
        ("623-98-0035", "an SSN is 3-2-4, a phone is 3-3-4"),
        ("12345678901", "an undelimited digit run"),
        ("555-123-45678", "too many trailing digits"),
        ("55-123-4567", "area code too short"),
    ],
)
def test_phone_rejected(text, why):
    assert find_phones(text) == [], why


# ---------------------------------------------------------------- credit card


def test_luhn_accepts_known_valid():
    assert luhn_valid("4720056658763761")


def test_luhn_rejects_altered_digit():
    # Changing one digit of a valid number must break the checksum -- that is
    # the entire point of a check digit.
    assert not luhn_valid("4720056658763762")


@pytest.mark.parametrize(
    "text",
    ["4720 0566 5876 3761", "4720-0566-5876-3761", "4720056658763761"],
)
def test_credit_card_found_in_each_separator_style(text):
    assert len(find_credit_cards(text)) == 1


def test_credit_card_requires_consistent_separators():
    assert find_credit_cards("4720 0566-5876 3761") == []


def test_credit_card_rejects_luhn_failure():
    """The structural pattern matches; the checksum is what turns it away."""
    from src.detectors.regex_detector import CREDIT_CARD_PATTERN

    order_number = "4839201847362519"
    assert CREDIT_CARD_PATTERN.search(order_number), "pattern should match the shape"
    assert not luhn_valid(order_number), "fixture must be a Luhn failure"
    assert find_credit_cards(order_number) == [], "Luhn must reject it"


# ---------------------------------------------------------------- IP address


@pytest.mark.parametrize(
    "text", ["10.235.204.93", "at 192.168.1.1 now", "255.255.255.255"]
)
def test_ip_found(text):
    assert len(find_ip_addresses(text)) == 1


def test_ip_at_end_of_sentence():
    """Regression: a trailing full stop once suppressed the whole match.

    The corpus never placed an address at the end of a sentence, so this
    scored a clean 1.000 while missing a case that is common in real prose.
    """
    assert len(find_ip_addresses("connect to 192.168.1.1.")) == 1


@pytest.mark.parametrize(
    "text, why",
    [
        ("999.1.1.1", "octet above 255"),
        ("256.1.1.1", "octet above 255"),
        ("1.2.3", "only three octets"),
        ("1.10.2.14.3", "five octets is not an address"),
    ],
)
def test_ip_rejected(text, why):
    assert find_ip_addresses(text) == [], why


# ---------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    "pii_type, value",
    [
        (US_SSN, "623-98-0035"),
        (CREDIT_CARD, "4720 0566 5876 3761"),
        (PHONE_NUMBER, "555.123.4567"),
        (EMAIL_ADDRESS, "zadams@example.org"),
        (IP_ADDRESS, "10.235.204.93"),
    ],
)
def test_redaction_never_returns_the_whole_value(pii_type, value):
    assert redact(pii_type, value) != value


def test_redaction_keeps_last_four_digits_only():
    assert redact(US_SSN, "623-98-0035") == "***-**-0035"
    assert redact(CREDIT_CARD, "4720 0566 5876 3761") == "**** **** **** 3761"


def test_redaction_masks_email_local_part():
    assert redact(EMAIL_ADDRESS, "zadams@example.org") == "z*****@example.org"


def test_redaction_drops_the_host_portion_of_an_ip():
    assert redact(IP_ADDRESS, "10.235.204.93") == "10.235.x.x"


def test_match_repr_carries_no_raw_value():
    """Tracebacks and debug logs must not become a second copy of the data."""
    (match,) = find_ssns("SSN 623-98-0035 here")
    assert "623-98" not in repr(match)
    assert "0035" in repr(match)


# ---------------------------------------------------------------- scan_text


def test_scan_text_returns_matches_in_document_order():
    text = "mail a@example.org then call 555-123-4567 then ssn 623-98-0035"
    assert spans(scan_text(text)) == sorted(spans(scan_text(text)))


def test_scan_text_finds_every_supported_type():
    text = (
        "ssn 623-98-0035, card 4720 0566 5876 3761, mail z@example.org, "
        "phone 555-123-4567, host 10.1.2.3"
    )
    assert {m.pii_type for m in scan_text(text)} == set(SUPPORTED_TYPES)


def test_scan_text_reports_no_overlapping_spans():
    text = "ssn 623-98-0035 card 4720-0566-5876-3761 phone (555) 123-4567"
    matches = scan_text(text)
    for earlier, later in zip(matches, matches[1:]):
        assert earlier.end <= later.start


def test_scan_text_on_empty_input():
    assert scan_text("") == []


# ---------------------------------------------------------------- corpus score


@pytest.fixture(scope="module")
def report():
    return score_corpus(scan_text, SUPPORTED_TYPES)


def test_corpus_recall_is_total(report):
    """Every planted value of a supported type must be found.

    Recall is the one metric that should be perfect here: the corpus was
    generated in the formats these patterns target. A drop means a pattern
    regressed, not that the data got harder.
    """
    assert report.totals.false_negatives == 0
    assert report.totals.recall == 1.0


@pytest.mark.parametrize(
    "pii_type", [US_SSN, CREDIT_CARD, EMAIL_ADDRESS, PHONE_NUMBER]
)
def test_corpus_has_no_false_positives_for_structured_types(report, pii_type):
    assert report.per_type[pii_type].false_positives == 0


def test_ip_precision_is_limited_by_decoys(report):
    """A documented limitation, asserted so it cannot change unnoticed.

    Five version strings shaped like addresses are flagged as IPs. The pattern
    is not wrong -- "10.2.14.3" is a valid address -- it simply cannot see that
    the surrounding sentence is about a software build. Distinguishing the two
    needs context, which is what Phase 4 adds.
    """
    ip_score = report.per_type[IP_ADDRESS]
    assert ip_score.false_positives == 5
    assert ip_score.recall == 1.0
    assert all(hit["pii_type"] == IP_ADDRESS for hit in report.decoy_hits)


def test_no_decoy_fools_a_structured_pattern(report):
    """Every decoy except the version strings must be correctly ignored."""
    assert len(report.decoy_hits) == 5


def test_person_and_location_are_out_of_scope(report):
    """Recorded as not-attempted rather than counted as misses.

    These 97 values are what the Phase 4 NLP layer is for. Charging them
    against the regex engine would measure the build plan, not the code.
    """
    import json
    from pathlib import Path
    from collections import Counter

    key = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "answer_key.json").read_text()
    )
    truth = Counter(f["type"] for e in key["files"] for f in e["findings"])
    assert report.out_of_scope == {"PERSON": truth["PERSON"], "LOCATION": truth["LOCATION"]}
