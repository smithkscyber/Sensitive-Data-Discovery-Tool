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
    Match,
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
from src.detectors.regex_detector import _resolve_overlaps
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


def test_ip_version_strings_are_no_longer_flagged(report):
    """Once the detector's last source of false positives.

    "10.2.14.3" is a valid address and an ordinary software version, and
    nothing about the characters separates them -- only the word in front does.
    Suppressing a dotted quad that sits immediately after "build", "version" or
    "firmware" closed the gap without costing any real address.
    """
    ip_score = report.per_type[IP_ADDRESS]
    assert ip_score.false_positives == 0
    assert ip_score.recall == 1.0


def test_no_decoy_fools_any_pattern(report):
    """All forty near misses are correctly ignored."""
    assert report.decoy_hits == []


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


# ------------------------------------------------- gaps found by mutation testing
#
# Each test below exists because `mutmut run` broke a specific line and the
# suite stayed green. A surviving mutant is not a bug -- the code is right --
# it is a line whose correctness nothing was checking, which is the same thing
# as having no test for it. The mutant that motivated each one is named.


def test_luhn_rejects_anything_that_is_not_digits():
    """Mutant: `return False` -> `return True` in the guard.

    With that flipped, a malformed string passes the checksum unexamined, and
    the only evidence separating a card number from an order reference is gone.
    """
    assert not luhn_valid("4720-0566-5876-3761")
    assert not luhn_valid("")
    assert not luhn_valid("not a card")


def test_redaction_of_an_unknown_type_masks_everything():
    """Mutant: the fallback `return "*" * len(value)` rewritten.

    The default branch is what catches a type added later whose redaction
    nobody remembered to write. Failing open there would leak a whole class of
    value silently.
    """
    masked = redact("PASSPORT_NUMBER", "X1234567")
    assert set(masked) == {"*"}
    assert len(masked) == len("X1234567")


def test_a_value_containing_an_at_sign_is_not_redacted_as_an_email():
    """Mutant: `and` -> `or` in the email branch.

    With `or`, any value containing "@" takes the email path whatever its
    type, and the email rule deliberately preserves everything after the "@".
    A location written "Unit 4 @ 12 Mill Road" would come back intact.
    """
    masked = redact("LOCATION", "Unit 4 @ 12 Mill Road")
    assert set(masked) == {"*"}


def test_redaction_masks_a_two_character_mailbox_down_to_its_initial():
    """Mutant: `len(local) < 2` -> `<= 2`.

    The boundary between "mask the lot" and "keep one initial" is exactly
    here, and only a two-character mailbox can tell the two rules apart.
    """
    assert redact(EMAIL_ADDRESS, "ab@example.org") == "a*@example.org"
    assert redact(EMAIL_ADDRESS, "a@example.org") == "*@example.org"


def test_a_value_with_exactly_four_digits_is_masked_completely():
    """Mutant: `> 4` -> `>= 4` in the reveal threshold.

    "Keep the last four" has to mean *keep four of more than four*. At exactly
    four the rule reveals the entire value, which is the opposite of redacting
    it -- and a property test asserting "at most four digits survive" cannot
    catch this, because four digits survived.
    """
    assert redact(US_SSN, "12-34") == "**-**"
    assert redact(PHONE_NUMBER, "(555)") == "(***)"


def test_redaction_reduces_a_person_to_initials():
    """Mutant: the PERSON type literal rewritten, so the branch never fires."""
    assert redact("PERSON", "Fernando Proctor") == "F******* P******"


def test_redaction_of_a_location_reveals_nothing_at_all():
    """Mutant: the LOCATION type literal rewritten, so the branch never fires.

    Unlike every other type this one has no safe partial form: a street number
    on its own can identify a household.
    """
    assert redact("LOCATION", "12 Mill Road") == "*" * len("12 Mill Road")


def test_a_finding_cannot_be_edited_after_it_is_created():
    """Mutant: `frozen=True` -> `frozen=False`.

    A Match is a record of what was found. Anything able to rewrite one after
    the fact could change a report's contents between detection and display.
    """
    finding = Match(US_SSN, 0, 11, "***-**-0035")
    with pytest.raises(Exception):
        finding.start = 5


def test_two_findings_that_merely_touch_both_survive():
    """Mutant: `candidate.start < other.end` -> `<=`.

    Half-open spans mean [0,4) and [4,8) share no character. Treating them as
    overlapping would silently drop the second of any two adjacent values --
    two comma-separated emails in a CSV row, for instance.
    """
    kept = _resolve_overlaps(
        [
            Match(EMAIL_ADDRESS, 0, 4, "****"),
            Match(EMAIL_ADDRESS, 4, 8, "****"),
        ]
    )
    assert len(kept) == 2


def test_a_discarded_overlap_does_not_discard_what_comes_after_it():
    """Mutant: `continue` -> `break` in the overlap loop.

    Skipping one candidate must not abandon the rest of the list. With `break`
    every finding after the first rejected one disappears, which loses data in
    exactly the files that contain the most of it.
    """
    kept = _resolve_overlaps(
        [
            Match(EMAIL_ADDRESS, 0, 20, "*" * 20),   # longest, ranked first
            Match(PHONE_NUMBER, 2, 18, "*" * 16),    # overlaps it, rejected
            Match(US_SSN, 30, 41, "***-**-0035"),    # shortest, must survive
        ]
    )
    assert [m.pii_type for m in kept] == [EMAIL_ADDRESS, US_SSN]


def test_an_ssn_outranks_a_card_number_on_an_equal_length_overlap():
    """Mutant: `US_SSN: 0` -> `1`, which ties it with CREDIT_CARD.

    The tie-break is a deliberate choice, not an accident of dict order: an
    SSN reported as something else understates the risk score, and the more
    sensitive type has to win.
    """
    kept = _resolve_overlaps(
        [
            Match(CREDIT_CARD, 0, 11, "****-**-0035"),
            Match(US_SSN, 0, 11, "***-**-0035"),
        ]
    )
    assert [m.pii_type for m in kept] == [US_SSN]


def test_a_version_string_at_the_very_start_of_a_file_is_still_suppressed():
    """Mutant: `max(0, ...)` -> `max(1, ...)` on the look-back window.

    Off by one at position zero: the window would start one character in, so
    "version:" at the top of a file loses its "v" and stops being a keyword.
    The first line of a release note is exactly where this text appears.
    """
    assert find_ip_addresses("version: 10.1.2.3") == []
    assert find_ip_addresses("v 10.1.2.3") == []


def test_a_suppressed_version_string_does_not_hide_later_addresses():
    """Mutant: `continue` -> `break` in the suppression loop.

    Skipping one dotted quad must not abandon the rest of the file. With
    `break`, a release note that mentions a version before naming a server
    reports nothing at all.
    """
    found = find_ip_addresses("Running firmware 10.2.14.3 on host 192.168.4.7 today")
    assert len(found) == 1
    assert found[0].redacted == "192.168.x.x"


def test_a_value_with_exactly_five_digits_keeps_only_its_last_four():
    """Mutant: `> 4` -> `> 5` in the reveal threshold.

    Five digits is the first length at which "keep the last four" conceals
    anything, so it is the only length that separates the two rules.
    """
    assert redact(US_SSN, "12345") == "*2345"


def test_ip_redaction_masks_anything_that_is_not_a_dotted_quad():
    """Mutant: the fail-closed branch rewritten.

    Discarding the last two octets only conceals something when there are four
    to begin with. Given "10.0" the old code returned "10.0.x.x" -- the whole
    value, decorated.
    """
    assert redact(IP_ADDRESS, "10.0") == "****"
    assert redact(IP_ADDRESS, "10.235.204.93") == "10.235.x.x"


def test_a_finding_defaults_to_the_regex_source_at_full_confidence():
    """Mutants: the `source` and `score` defaults rewritten.

    Both are load-bearing one layer up. The merge in hybrid.py grants regex
    findings authority over the model's by reading exactly this string, so a
    changed default would silently demote every structurally validated
    finding -- the Phase 6 bug, arriving through the back door.
    """
    finding = Match(US_SSN, 0, 11, "***-**-0035")
    assert finding.source == "regex"
    assert finding.score == 1.0


def test_the_longer_of_two_overlapping_matches_wins():
    """Mutant: the sort key `end - start` -> `end + start`.

    Ranking by position instead of length would let a short match at the end
    of a line displace the long one it sits inside. Length is the tie-break
    that matters: the longer span explains more of the text.
    """
    kept = _resolve_overlaps(
        [
            Match(EMAIL_ADDRESS, 0, 20, "*" * 20),
            Match(PHONE_NUMBER, 18, 24, "*" * 6),
        ]
    )
    assert [m.pii_type for m in kept] == [EMAIL_ADDRESS]


def test_a_shorter_match_ending_where_a_longer_one_begins_survives():
    """Mutant: `other.start < candidate.end` -> `<=`.

    The mirror of the touching-spans case, and it needs the longer span to be
    ranked first for the second half of the overlap test to be reached at all.
    Half-open spans [0,4) and [4,20) share no character.
    """
    kept = _resolve_overlaps(
        [
            Match(EMAIL_ADDRESS, 4, 20, "*" * 16),
            Match(EMAIL_ADDRESS, 0, 4, "****"),
        ]
    )
    assert len(kept) == 2
