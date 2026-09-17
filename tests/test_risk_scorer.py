"""Tests for risk weighting and banding.

Every file in the corpus contains a Social Security number, so every one of
them scores HIGH or CRITICAL. The corpus therefore cannot exercise the lower
bands at all, and most of what matters here is tested with hand-built inputs
instead.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.reporting.risk_scorer import (
    BANDS,
    DEFAULT_WEIGHT,
    RISK_WEIGHTS,
    band_for,
    rank,
    score_counts,
    score_file,
    weight_for,
)


@dataclass
class FakeMatch:
    pii_type: str


def matches(**counts):
    return [FakeMatch(t) for t, n in counts.items() for _ in range(n)]


# ------------------------------------------------------------- weights


@pytest.mark.parametrize(
    "pii_type, weight",
    [("US_SSN", 10), ("CREDIT_CARD", 9), ("EMAIL_ADDRESS", 3), ("PHONE_NUMBER", 2)],
)
def test_weights_match_the_documented_table(pii_type, weight):
    assert RISK_WEIGHTS[pii_type] == weight


def test_ssn_outranks_every_other_type():
    """The ordering is the substance of the table; pin the top of it."""
    assert RISK_WEIGHTS["US_SSN"] == max(RISK_WEIGHTS.values())


def test_reissuable_credit_card_ranks_below_permanent_ssn():
    assert RISK_WEIGHTS["CREDIT_CARD"] < RISK_WEIGHTS["US_SSN"]


def test_home_address_outranks_contact_details():
    assert RISK_WEIGHTS["LOCATION"] > RISK_WEIGHTS["EMAIL_ADDRESS"]
    assert RISK_WEIGHTS["LOCATION"] > RISK_WEIGHTS["PHONE_NUMBER"]


def test_unknown_type_is_not_treated_as_harmless():
    """A new detector must not be able to quietly lower a file's score.

    Defaulting an unrecognised type to 0 would mean adding a detector could
    make a file look safer than before, which is exactly backwards.
    """
    assert weight_for("PASSPORT_NUMBER") == DEFAULT_WEIGHT
    assert DEFAULT_WEIGHT > 0


# --------------------------------------------------------------- scoring


def test_score_is_weight_times_count_summed():
    assert score_counts({"US_SSN": 2, "PHONE_NUMBER": 3}) == 2 * 10 + 3 * 2


def test_empty_file_scores_zero():
    assert score_counts({}) == 0


def test_score_file_counts_types_not_values():
    result = score_file("a.txt", matches(US_SSN=2, EMAIL_ADDRESS=1))
    assert result.counts == {"EMAIL_ADDRESS": 1, "US_SSN": 2}
    assert result.finding_count == 3
    assert result.risk_score == 23


def test_score_file_infers_format_from_extension():
    assert score_file("notes/report.PDF", []).file_format == "pdf"


def test_score_file_records_peak_severity():
    result = score_file("a.txt", matches(PHONE_NUMBER=9, US_SSN=1))
    assert result.peak_severity == 10


# ---------------------------------------------------------------- bands


def test_clean_file_is_band_none():
    assert score_file("a.txt", []).band == "NONE"


def test_a_single_ssn_is_high_despite_a_low_total():
    """The severity floor, which is the whole reason band_for is not a lookup.

    One SSN totals 10, which the volume thresholds alone would call MEDIUM.
    A leaked Social Security number is not a medium-severity event.
    """
    result = score_file("a.txt", matches(US_SSN=1))
    assert result.risk_score == 10
    assert result.band == "HIGH"


def test_a_single_address_is_at_least_medium():
    assert score_file("a.txt", matches(LOCATION=1)).band == "MEDIUM"


def test_only_contact_details_stays_low():
    assert score_file("a.txt", matches(EMAIL_ADDRESS=1, PHONE_NUMBER=1)).band == "LOW"


def test_volume_still_escalates_the_band():
    """Severity sets a floor; it does not put a ceiling on volume."""
    assert score_file("a.csv", matches(EMAIL_ADDRESS=40)).band == "CRITICAL"


def test_a_pile_of_low_severity_findings_never_outranks_one_ssn():
    """The distortion the design exists to prevent.

    Measured on this project's own corpus: memo_01.txt totals 37 on eleven
    low-severity findings, while letter_01.pdf totals 33 while holding an SSN
    and a credit card. Sorting on the raw total alone triages the memo first.
    Banding on severity as well is what keeps the SSN file from being buried.
    """
    noisy = score_file("noisy.txt", matches(PERSON=8, EMAIL_ADDRESS=4))
    sensitive = score_file("sensitive.txt", matches(US_SSN=1))
    assert noisy.risk_score > sensitive.risk_score
    assert BANDS.index(sensitive.band) >= BANDS.index(noisy.band)


@pytest.mark.parametrize("band", BANDS)
def test_every_band_is_reachable(band):
    """A band no input can produce is dead code pretending to be policy."""
    cases = [
        score_file("f", []),
        score_file("f", matches(EMAIL_ADDRESS=1)),
        score_file("f", matches(LOCATION=1)),
        score_file("f", matches(US_SSN=1)),
        score_file("f", matches(US_SSN=8, CREDIT_CARD=8, LOCATION=8)),
    ]
    assert band in {c.band for c in cases}


def test_band_for_is_monotonic_in_score():
    previous = 0
    for score in range(0, 200, 7):
        current = BANDS.index(band_for(score, 0))
        assert current >= previous
        previous = current


# ----------------------------------------------------------------- rank


def test_rank_puts_the_worst_band_first():
    results = [
        score_file("quiet.txt", matches(EMAIL_ADDRESS=1)),
        score_file("bad.csv", matches(US_SSN=8, CREDIT_CARD=8)),
        score_file("medium.txt", matches(LOCATION=1)),
    ]
    assert [r.name for r in rank(results)] == ["bad.csv", "medium.txt", "quiet.txt"]


def test_rank_breaks_ties_by_name_for_stable_output():
    a = score_file("b.txt", matches(US_SSN=1))
    b = score_file("a.txt", matches(US_SSN=1))
    assert [r.name for r in rank([a, b])] == ["a.txt", "b.txt"]


def test_rank_does_not_mutate_its_input():
    results = [
        score_file("a.txt", matches(EMAIL_ADDRESS=1)),
        score_file("b.txt", matches(US_SSN=1)),
    ]
    before = list(results)
    rank(results)
    assert results == before
