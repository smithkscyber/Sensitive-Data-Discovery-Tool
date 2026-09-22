"""Tests for the third-party benchmark renderer.

A benchmark whose answer key is wrong is worse than no benchmark: it produces
numbers that look like measurements and are not. The corpus generator learned
this in Phase 2, when five names went unrecorded and the detector was scored
against a key that quietly disagreed with the text. The same invariants are
asserted here, plus one the corpus does not need -- that the vendored inputs
are still the bytes that were vendored.
"""

from __future__ import annotations

import hashlib

import pytest

from src import benchmark
from src.detectors.nlp_detector import LOCATION, PERSON
from src.detectors.regex_detector import US_SSN

#: Recorded in data/external/SOURCE.md. Asserted here because a held-out
#: benchmark stops being held-out the moment its inputs can be edited to suit
#: the result -- that is the single most tempting way to fake a good score, and
#: it should break the build rather than pass quietly.
EXPECTED_DIGESTS = {
    "presidio_templates.txt":
        "f8b04ff8c5c24d17fcac2e666767f6ba80841b69ee2ea3c1cfe089a676a766ef",
    "fake_name_generator_3000.csv":
        "d1337ba8d085612ca989cc64cc64bb8b44ab5121e9d94de2b534a49e921c8170",
}


# ------------------------------------------------------------ vendored data


@pytest.mark.parametrize("name, digest", sorted(EXPECTED_DIGESTS.items()))
def test_vendored_input_is_unmodified(name, digest):
    data = (benchmark.EXTERNAL / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest


def test_templates_load():
    templates = benchmark.load_templates()
    assert len(templates) >= 200
    assert any("{{credit_card_number}}" in t for t in templates)


def test_escaped_newlines_become_real_ones():
    """Mailing-address templates are stored on one physical line.

    Offsets measured before the escapes are expanded would be wrong for every
    span after the first one.
    """
    templates = benchmark.load_templates()
    assert any("\n" in t for t in templates)
    assert not any("\\n" in t for t in templates)


def test_us_identities_are_us_only():
    rows = benchmark.load_identities(us_only=True)
    assert rows and {row["Country"] for row in rows} == {"US"}


def test_the_scope_probe_excludes_us_identities():
    rows = benchmark.load_identities(us_only=False)
    assert rows and "US" not in {row["Country"] for row in rows}


def test_no_us_identity_is_missing_a_field_the_renderer_reads():
    """A blank column would leave a raw {{placeholder}} in the sentence."""
    needed = ("GivenName", "Surname", "StreetAddress", "City", "State",
              "ZipCode", "TelephoneNumber", "EmailAddress", "NationalID")
    for row in benchmark.load_identities(us_only=True):
        assert all(row[field].strip() for field in needed)


# -------------------------------------------------------- answer-key rigour


def test_every_gold_span_holds_the_value_it_claims():
    for sentence in benchmark.build(limit=400):
        sentence.verify()


def test_gold_spans_never_overlap():
    for sentence in benchmark.build(limit=400):
        spans = sorted((f["start"], f["end"]) for f in sentence.findings)
        for (_, earlier_end), (later_start, _) in zip(spans, spans[1:]):
            assert earlier_end <= later_start


def test_distractor_spans_hold_their_values_too():
    """Unlabelled slots are how false positives get attributed to a cause.

    If their offsets drift, every "landed on {{organization}}" line in the
    report is pointing at the wrong thing.
    """
    for sentence in benchmark.build(limit=400):
        for item in sentence.distractors:
            assert sentence.text[item["start"] : item["end"]] == item["value"]


def test_no_placeholder_survives_into_a_rendered_us_sentence():
    for sentence in benchmark.build(limit=400):
        assert "{{" not in sentence.text


def test_rendering_is_deterministic():
    """Two runs must agree, or a reported figure cannot be reproduced."""
    first = benchmark.build(limit=120)
    second = benchmark.build(limit=120)
    assert [s.text for s in first] == [s.text for s in second]
    assert [s.findings for s in first] == [s.findings for s in second]


def test_the_seed_actually_changes_the_output():
    """Guards against a determinism claim that holds because nothing varies."""
    baseline = benchmark.build(limit=120)
    shifted = benchmark.build(limit=120, seed=benchmark.SEED + 1)
    assert [s.text for s in baseline] != [s.text for s in shifted]


def test_every_template_is_exercised():
    sentences = benchmark.build(limit=None)
    assert len({s.template_index for s in sentences}) == len(benchmark.load_templates())


# --------------------------------------------------------- labelling policy


def test_out_of_scope_slots_are_distractors_not_gold():
    """A company name is not a type this tool claims to find.

    It is still written into the sentence, so a detector that reports it as a
    PERSON is charged for it -- which is the correct accounting, because that
    is exactly what would appear in a report handed to an operator.
    """
    for slot in ("organization", "job", "url", "iban", "date_of_birth", "age"):
        assert slot not in benchmark.TYPE_OF


def test_inline_location_fragments_merge_into_one_span():
    """Gold follows the same stitching rule the detector's merge does.

    Holding gold to a different convention than predictions would manufacture
    false negatives out of a disagreement about punctuation.
    """
    values = benchmark._Values(benchmark.SEED)
    row = benchmark.load_identities(us_only=True)[0]
    sentence = benchmark.render("{{city}} {{state_abbr}} {{zipcode}}", row, values)
    assert len(sentence.findings) == 1
    assert sentence.findings[0]["type"] == LOCATION


def test_location_fragments_on_separate_lines_stay_separate():
    """A block address is several spans to a line-oriented detector.

    Merging across the newline would let one prediction claim credit for
    entities it never found.
    """
    values = benchmark._Values(benchmark.SEED)
    row = benchmark.load_identities(us_only=True)[0]
    sentence = benchmark.render("{{city}}\n{{zipcode}}", row, values)
    assert len(sentence.findings) == 2


def test_a_full_name_is_one_person_span():
    values = benchmark._Values(benchmark.SEED)
    row = benchmark.load_identities(us_only=True)[0]
    sentence = benchmark.render("Contact {{person}} today.", row, values)
    assert [f["type"] for f in sentence.findings] == [PERSON]
    assert sentence.findings[0]["value"].count(" ") == 1


def test_ssn_values_come_from_the_vendored_file_not_from_faker():
    """The claim in SOURCE.md, asserted rather than asserted-in-prose."""
    values = benchmark._Values(benchmark.SEED)
    row = benchmark.load_identities(us_only=True)[0]
    sentence = benchmark.render("SSN: {{ssn}}", row, values)
    assert sentence.findings[0]["type"] == US_SSN
    assert sentence.findings[0]["value"] == row["NationalID"]


def test_an_unresolvable_placeholder_is_left_visible_not_deleted():
    """Silently dropping it would change the context the detector reads."""
    values = benchmark._Values(benchmark.SEED)
    row = benchmark.load_identities(us_only=True)[0]
    sentence = benchmark.render("Ref {{not_a_real_slot}} ends.", row, values)
    assert "{{not_a_real_slot}}" in sentence.text
    assert sentence.findings == []
