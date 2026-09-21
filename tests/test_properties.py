"""Property-based tests: invariants checked against generated inputs.

Every other test file in this project asserts behaviour on examples somebody
chose. That is the weakness the external benchmark exposes at the accuracy
level, and it applies to the unit tests too: an example test can only fail on a
case its author thought of.

Hypothesis inverts that. Each test below states a property that must hold for
*all* inputs of some shape, and the library goes looking for a counterexample
-- hundreds per run, biased toward the awkward edges (empty strings, lone
surrogates, spans that touch at a single character). When it finds one it
shrinks it to the smallest input that still fails, so a failure arrives as a
minimal reproduction rather than a pile of noise.

These properties are the ones where a violation would be a real defect:
offsets that do not address the text, a merge that emits overlapping spans, a
validated finding discarded by the merge (the Phase 6 bug), a redaction that
leaks, or a crash on a file somebody uploads.
"""

from __future__ import annotations

import string

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from src.detectors import hybrid, nlp_detector, regex_detector
from src.detectors.regex_detector import (
    CREDIT_CARD,
    EMAIL_ADDRESS,
    IP_ADDRESS,
    PHONE_NUMBER,
    US_SSN,
    Match,
    luhn_valid,
    redact,
)

#: spaCy is slow enough that the default 100 examples would dominate the suite,
#: and its first call loads a 560MB model, which blows any per-example deadline.
NLP_SETTINGS = settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

#: Filler that cannot accidentally create or destroy a match: no digits (which
#: would break the detectors' digit boundaries), no "@" (which would form an
#: address), no "." adjoining a quad.
FILLER = st.text(alphabet=string.ascii_letters + " \n\t,;:!?()", max_size=80)


# --------------------------------------------------------------- strategies


@st.composite
def valid_ssns(draw) -> str:
    """An SSN obeying the SSA issuance rules, built from those rules only.

    Deliberately not built from the detector's own pattern -- a generator
    derived from the thing under test would make the recall property
    tautological.
    """
    area = draw(st.integers(min_value=1, max_value=899).filter(lambda n: n != 666))
    group = draw(st.integers(min_value=1, max_value=99))
    serial = draw(st.integers(min_value=1, max_value=9999))
    return f"{area:03d}-{group:02d}-{serial:04d}"


@st.composite
def luhn_cards(draw) -> str:
    """Sixteen digits that satisfy Luhn, formatted the three ways cards are."""
    prefix = draw(st.sampled_from("45"))
    body = draw(st.lists(st.integers(0, 9), min_size=14, max_size=14))
    digits = prefix + "".join(str(d) for d in body)
    for check in "0123456789":
        if luhn_valid(digits + check):
            digits += check
            break
    groups = [digits[i : i + 4] for i in range(0, 16, 4)]
    return draw(st.sampled_from([" ", "-", ""])).join(groups)


@st.composite
def matches(draw) -> Match:
    """An arbitrary detector finding, for exercising the merge directly."""
    start = draw(st.integers(min_value=0, max_value=200))
    length = draw(st.integers(min_value=1, max_value=40))
    pii_type = draw(
        st.sampled_from(
            list(regex_detector.SUPPORTED_TYPES)
            + [nlp_detector.PERSON, nlp_detector.LOCATION]
        )
    )
    source = draw(st.sampled_from(["regex", "nlp"]))
    return Match(
        pii_type=pii_type,
        start=start,
        end=start + length,
        redacted="*" * length,
        source=source,
        score=draw(st.floats(min_value=0.1, max_value=1.0)),
    )


# ------------------------------------------------------- offsets and bounds


@given(FILLER)
def test_regex_offsets_always_address_the_text(text):
    for match in regex_detector.scan_text(text):
        assert 0 <= match.start < match.end <= len(text)


@given(st.text(max_size=300))
@NLP_SETTINGS
def test_hybrid_offsets_always_address_the_text(text):
    """Includes lone surrogates and unassigned code points on purpose.

    Uploaded files contain whatever they contain, and an offset that runs past
    the end of the string is how a scan turns into a stack trace in front of a
    user.
    """
    for match in hybrid.scan_text(text):
        assert 0 <= match.start < match.end <= len(text)


@given(st.text(max_size=300))
@NLP_SETTINGS
def test_scanning_arbitrary_text_never_raises(text):
    hybrid.scan_text(text)


@given(FILLER, valid_ssns())
def test_regex_detection_does_not_depend_on_absolute_position(prefix, ssn):
    """Shifting the text must shift every finding by exactly that much.

    A pattern that behaved differently at offset 0 than at offset 400 would
    mean findings depend on where in a file a value happens to sit. The IP
    rule's backward-looking context window is the kind of code that could
    break this by accident.
    """
    assume("\n" not in prefix)
    body = f"Reference {ssn} on file."
    shift = len(prefix)
    base = regex_detector.scan_text(body)
    shifted = regex_detector.scan_text(prefix + body)
    assert [(m.pii_type, m.start + shift, m.end + shift) for m in base] == [
        (m.pii_type, m.start, m.end) for m in shifted
    ]


# ------------------------------------------------------------ recall floors


@given(valid_ssns(), FILLER, FILLER)
def test_every_structurally_valid_ssn_is_found(ssn, before, after):
    """Generated from the SSA rules, not from the pattern. See valid_ssns."""
    assume(not before.endswith(tuple(string.ascii_letters)))
    assume(not after.startswith(tuple(string.ascii_letters)))
    text = f"{before} {ssn} {after}"
    found = [m for m in regex_detector.scan_text(text) if m.pii_type == US_SSN]
    assert len(found) == 1
    assert text[found[0].start : found[0].end] == ssn


@given(luhn_cards(), FILLER)
def test_every_luhn_valid_card_is_found(card, after):
    assume(not after.startswith(tuple(string.ascii_letters + string.digits)))
    text = f"Card on file {card} {after}"
    found = [m for m in regex_detector.scan_text(text) if m.pii_type == CREDIT_CARD]
    assert len(found) == 1


@given(st.lists(st.integers(0, 9), min_size=16, max_size=16))
def test_a_number_failing_luhn_is_never_reported_as_a_card(digits):
    """The half of card detection that format alone cannot do.

    Sixteen digits in four groups look exactly like a card number. Only the
    checksum separates a real one from an order reference, and generated
    digits fail it about nine times in ten -- so this property spends most of
    its examples on precisely the case that matters.
    """
    number = "".join(str(d) for d in digits)
    assume(not luhn_valid(number))
    text = f"Order {number[:4]}-{number[4:8]}-{number[8:12]}-{number[12:]} shipped"
    assert not [
        m for m in regex_detector.scan_text(text) if m.pii_type == CREDIT_CARD
    ]


# ------------------------------------------------------------- merge safety


@given(st.lists(matches(), max_size=25))
def test_merged_findings_never_overlap(candidates):
    """One character of text belongs to at most one finding.

    Overlapping spans would double-count a value in the risk score and produce
    two rows in a report for one piece of data.
    """
    merged = hybrid.merge(
        [m for m in candidates if m.source == "regex"],
        [m for m in candidates if m.source == "nlp"],
        "x" * 400,
    )
    spans = sorted((m.start, m.end) for m in merged)
    for (_, earlier_end), (later_start, _) in zip(spans, spans[1:]):
        assert earlier_end <= later_start


@given(st.lists(matches(), max_size=25))
def test_merge_invents_nothing(candidates):
    """Every surviving span is one that a detector actually proposed.

    Stitching is the exception and only widens LOCATION, so any other type
    must come through with its boundaries intact.
    """
    merged = hybrid.merge(
        [m for m in candidates if m.source == "regex"],
        [m for m in candidates if m.source == "nlp"],
        "x" * 400,
    )
    proposed = {(m.pii_type, m.start, m.end) for m in candidates}
    for match in merged:
        if match.pii_type != nlp_detector.LOCATION:
            assert (match.pii_type, match.start, match.end) in proposed


@given(st.lists(matches(), max_size=25))
def test_a_validated_finding_only_ever_loses_to_another_validated_finding(candidates):
    """The Phase 6 bug, stated as a property.

    A checksum-validated card number used to be discarded when a longer PERSON
    span happened to overlap it. Ranking by authority fixed that, and this is
    the invariant the fix has to satisfy for every arrangement of spans, not
    just the one that was noticed.
    """
    regex_side = [m for m in candidates if m.source == "regex"]
    merged = hybrid.merge(regex_side, [m for m in candidates if m.source == "nlp"], "x" * 400)
    kept = {(m.pii_type, m.start, m.end, m.source) for m in merged}

    authoritative = [
        m for m in regex_side if m.pii_type in hybrid.REGEX_AUTHORITATIVE
    ]
    survivors = [m for m in merged if _authoritative(m)]
    for dropped in authoritative:
        if (dropped.pii_type, dropped.start, dropped.end, dropped.source) in kept:
            continue
        assert any(
            dropped.start < other.end and other.start < dropped.end
            for other in survivors
        ), "a structurally validated finding was discarded by a weaker one"


def _authoritative(match: Match) -> bool:
    return match.source == "regex" and match.pii_type in hybrid.REGEX_AUTHORITATIVE


# --------------------------------------------------------------- redaction
#
# Two of these types reveal part of their value on purpose, and the properties
# below have to say so or they would be asserting something the code has never
# claimed. An IP keeps its first two octets, because a subnet is what makes a
# finding actionable and the host portion is what identifies a machine. An
# email keeps its domain, because "someone at a competitor" is the fact an
# analyst needs and the mailbox is the part that names a person. Everything
# else masks unconditionally.


@st.composite
def redactable(draw):
    """A type paired with a value of the shape that type actually receives.

    Feeding a detector's redactor a value it could never be handed proves
    nothing: the SSN branch preserves letters because an SSN has none, and a
    property that punished it for that would be testing the test.
    """
    pii_type = draw(
        st.sampled_from([US_SSN, CREDIT_CARD, PHONE_NUMBER, EMAIL_ADDRESS,
                         IP_ADDRESS, nlp_detector.PERSON, nlp_detector.LOCATION])
    )
    word = st.text(alphabet=string.ascii_lowercase, min_size=2, max_size=9)
    if pii_type == US_SSN:
        return pii_type, draw(valid_ssns())
    if pii_type == CREDIT_CARD:
        return pii_type, draw(luhn_cards())
    if pii_type == PHONE_NUMBER:
        digits = draw(st.integers(min_value=2000000000, max_value=9899999999))
        return pii_type, f"{str(digits)[:3]}-{str(digits)[3:6]}-{str(digits)[6:]}"
    if pii_type == EMAIL_ADDRESS:
        return pii_type, f"{draw(word)}@{draw(word)}.org"
    if pii_type == IP_ADDRESS:
        octets = draw(st.lists(st.integers(0, 255), min_size=4, max_size=4))
        return pii_type, ".".join(str(o) for o in octets)
    names = draw(st.lists(word, min_size=1, max_size=3))
    return pii_type, " ".join(n.capitalize() for n in names)


@given(redactable())
def test_a_match_never_prints_its_own_value(pair):
    """__repr__ is overridden so a traceback cannot become a data leak.

    Any logging call, debugger session or unhandled exception renders a Match
    through repr. If the raw value survived that, the project's rule against
    ever printing PII would hold only until the first crash.

    This found a real one: a mailbox of a single character had no tail to
    mask, so ``a@example.org`` redacted to itself.
    """
    pii_type, value = pair
    match = Match(pii_type, 0, len(value), redact(pii_type, value))
    assert value not in repr(match)


@given(
    st.sampled_from([US_SSN, CREDIT_CARD, PHONE_NUMBER]),
    st.text(alphabet=string.digits + " -.()", max_size=30),
)
def test_a_masked_identifier_never_leaves_more_than_four_digits(pii_type, value):
    """Holds for any input, not just well-formed ones.

    Hypothesis found the gap here too. "Keep the last four" conceals something
    only when there are more than four to keep, so a short value came back
    untouched. The rule now masks everything below that threshold.
    """
    masked = redact(pii_type, value)
    assert len(masked) == len(value)
    assert sum(char.isdigit() for char in masked) <= 4
    # Separators survive on purpose: the shape of the value is what lets an
    # analyst tell a card from a phone number in a report.
    assert [c for c in masked if not c.isdigit() and c != "*"] == [
        c for c in value if not c.isdigit()
    ]


@given(valid_ssns())
def test_a_redacted_ssn_keeps_four_digits_at_most(ssn):
    masked = redact(US_SSN, ssn)
    assert len(masked) == len(ssn)
    assert sum(char.isdigit() for char in masked) <= 4
    assert masked != ssn


@given(luhn_cards())
def test_a_redacted_card_keeps_four_digits_at_most(card):
    masked = redact(CREDIT_CARD, card)
    assert len(masked) == len(card)
    assert sum(char.isdigit() for char in masked) <= 4


@given(st.text(alphabet=string.ascii_letters + string.digits + " ,.", min_size=1, max_size=40))
def test_a_redacted_location_reveals_nothing(value):
    """No "last four" equivalent exists for an address. See redact().

    A street number alone can identify a household, so unlike every other type
    this one has no partial form that stays safe.
    """
    masked = redact(nlp_detector.LOCATION, value)
    assert set(masked) <= {"*"}
    assert len(masked) == len(value)


@given(st.lists(
    st.text(alphabet=string.ascii_letters, min_size=1, max_size=10),
    min_size=1, max_size=4,
))
def test_a_redacted_person_reveals_one_initial_per_word(names):
    """Enough to correlate two findings about one person, not to name them."""
    value = " ".join(names)
    masked = redact(nlp_detector.PERSON, value)
    for original, shown in zip(names, masked.split(" ")):
        assert shown[0] == original[0]
        assert set(shown[1:]) <= {"*"}


@given(
    st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=12),
    st.text(alphabet=string.ascii_lowercase, min_size=2, max_size=12),
)
def test_email_redaction_keeps_the_domain_and_never_the_mailbox(local, domain):
    """The deliberate partial reveal, pinned so it stays deliberate.

    The domain is kept because it is the actionable half. The mailbox names a
    person and must not survive -- including when it is a single character,
    which is the case that used to slip through.
    """
    masked = redact(EMAIL_ADDRESS, f"{local}@{domain}.com")
    assert masked.endswith(f"@{domain}.com")

    mailbox = masked.partition("@")[0]
    assert len(mailbox) == len(local)
    assert set(mailbox[1:]) <= {"*"}
    if len(local) == 1:
        assert mailbox == "*"
    else:
        assert mailbox[0] == local[0]


@given(st.lists(st.integers(0, 255), min_size=4, max_size=4))
def test_ip_redaction_keeps_the_subnet_and_never_the_host(octets):
    """Also deliberate: the subnet locates the finding, the host identifies."""
    value = ".".join(str(o) for o in octets)
    masked = redact(IP_ADDRESS, value)
    assert masked == f"{octets[0]}.{octets[1]}.x.x"


@given(st.text(max_size=20).filter(lambda v: v.count(".") != 3))
def test_ip_redaction_fails_closed_on_anything_that_is_not_a_quad(value):
    """A redaction that trusts its caller to have validated first is a leak.

    Every value reaching this branch today comes from IP_PATTERN and is a
    dotted quad, so discarding the last two octets discards half of it. Given
    "10.0" the old code returned "10.0.x.x" -- the whole value, plus decoration.
    """
    assert set(redact(IP_ADDRESS, value)) <= {"*"}
