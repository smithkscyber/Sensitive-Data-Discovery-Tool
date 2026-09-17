"""Presidio NLP detection: the half of the problem regex cannot reach.

Regex matches shape. Presidio matches *meaning* -- it runs a spaCy named-entity
model, so it can tell that "Heath" is a surname in one sentence and a moor in
another. That is what makes PERSON and LOCATION detectable at all, and it is
the entire reason this module exists alongside the regex baseline rather than
replacing it.

The engine is expensive to construct (it loads a ~560MB language model), so it
is built once on first use and cached. Importing this module costs nothing.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from src.detectors.regex_detector import (
    CREDIT_CARD,
    EMAIL_ADDRESS,
    PHONE_NUMBER,
    US_SSN,
    Match,
    redact,
)

PERSON = "PERSON"
LOCATION = "LOCATION"

#: Entities Presidio is asked for. PERSON and LOCATION are the ones only it can
#: supply; the structured four are requested as well so the merge in
#: ``hybrid.py`` has two independent opinions to reconcile.
NLP_ENTITIES = (
    PERSON,
    LOCATION,
    US_SSN,
    EMAIL_ADDRESS,
    PHONE_NUMBER,
    CREDIT_CARD,
)

#: Presidio scores every result 0-1. The default threshold of 0 lets very weak
#: guesses through: on this corpus it reported all 35 nine-digit employee
#: numbers as US_SSN with score 0.05, taking SSN precision to 0.522.
#:
#: Measured over the full corpus:
#:
#:   threshold   overall precision   overall recall
#:   0.00        0.725               0.931
#:   0.35        0.819               0.931
#:   0.50        0.819               0.812
#:
#: 0.35 discards those 32 false positives at no cost to recall. Raising it to
#: 0.50 collapses PHONE_NUMBER recall from 0.971 to 0.229, because Presidio
#: scores many phone formats at exactly 0.4. The floor is chosen from that
#: measurement, not from taste.
DEFAULT_SCORE_THRESHOLD = 0.35


# A full US mailing address: number, street, city, two-letter state, ZIP.
#
# This exists because the NER alone reads an address as loose fragments and
# frequently mislabels the parts. Street and city names are drawn from personal
# names in the real world as much as in Faker -- Washington, Jackson, Madison --
# so "Darren Locks" is not an unreasonable thing for a model to call a person.
# Structure resolves what context cannot: no person's name is followed by a
# comma, a state code and a ZIP.
#
# Tokens must be title-case, which is what separates an address from a sentence
# that happens to contain commas and digits. Without that constraint "Invoice
# 12345 was, oddly, IN 46011" matches; with it, that and every other
# adversarial case tested comes back clean.
_STREET_TOKEN = r"[A-Z0-9][A-Za-z0-9.'#/-]*"
_CITY_TOKEN = r"[A-Z][A-Za-z.'-]*"
US_ADDRESS_REGEX = (
    rf"\b\d{{1,6}}[ \t]"
    rf"(?:{_STREET_TOKEN}[ \t]){{0,5}}{_STREET_TOKEN}"
    rf",[ \t]?"
    rf"(?:{_CITY_TOKEN}[ \t]){{0,3}}{_CITY_TOKEN}"
    rf",[ \t]?"
    rf"[A-Z]{{2}}[ \t]\d{{5}}(?:-\d{{4}})?\b"
)

#: High, because the pattern is highly specific -- five structural elements in
#: a fixed order. It needs to outrank the fragmentary PERSON and LOCATION spans
#: the NER produces over the same text, which score 0.85.
US_ADDRESS_SCORE = 0.9


def build_address_recognizer():
    """A pattern recognizer for complete US mailing addresses.

    Registered as a source of LOCATION alongside the model's own predictions.
    The merge in ``hybrid.py`` prefers the longest span, so a whole address
    supersedes the fragments the NER found inside it.
    """
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        supported_entity=LOCATION,
        name="UsStreetAddressRecognizer",
        patterns=[
            Pattern(
                name="us_street_address",
                regex=US_ADDRESS_REGEX,
                score=US_ADDRESS_SCORE,
            )
        ],
    )


# --------------------------------------------------------------------------
# Correspondents: names the NER misses because of where they sit
# --------------------------------------------------------------------------
#
# Two real misses on this corpus, with two different causes:
#
#   "To:      Jennifer Brown <...>"  the run of padding spaces breaks the
#                                    tokenizer; with one space it is found
#   "Dear Fernando Proctor,"         the model tags the first mention of a
#                                    name in a letter and not the second
#
# Neither is fixable by tuning a threshold -- the entity scores nothing at
# all, so there is no confidence to raise. What both cases do have is
# position: a name on a "To:" line or after "Dear" is a name because of where
# it sits, not because of what it looks like. That is a pattern, and it is the
# same move the address recognizer makes.

#: A capitalised token that can form part of a name.
_NAME_TOKEN = r"[A-Z][A-Za-z'\u2019.-]+"

#: Two to four capitalised tokens: a first and last name, allowing a middle
#: name or a suffix. One token is too loose -- "To: Facilities" is a desk.
_FULL_NAME = rf"{_NAME_TOKEN}(?:[ \t]+{_NAME_TOKEN}){{1,3}}"

CORRESPONDENT_PATTERNS = (
    # A correspondence header, with any amount of padding after the colon.
    rf"(?:^|\n)[ \t]*(?:To|From|Cc|Bcc|Attn|Attention)[ \t]*:[ \t]*(?P<target>{_FULL_NAME})",
    # A salutation.
    rf"\bDear[ \t]+(?P<target>{_FULL_NAME})",
)

#: Words that make a capitalised phrase a role or a department rather than a
#: person. "Dear Hiring Manager" and "To: Facilities Desk" both look exactly
#: like a name to the pattern above, and neither is one.
NON_PERSON_TOKENS = frozenset(
    {
        "sir", "madam", "customer", "customers", "client", "colleague",
        "colleagues", "team", "all", "everyone", "manager", "hiring",
        "recruiter", "desk", "department", "support", "admin", "administrator",
        "owner", "resident", "occupant", "member", "members", "valued",
        "friend", "user", "subscriber", "whom", "concerned", "services",
        "office", "committee", "board", "group", "staff", "payroll",
    }
)

#: Below the NER's 0.85. This recognizer is a positional inference, not an
#: observation about the characters, so where the model does have an opinion
#: its own should carry more weight.
CORRESPONDENT_SCORE = 0.6


def looks_like_a_person(name: str) -> bool:
    """Reject capitalised phrases that name a role rather than a person."""
    return not any(token.lower() in NON_PERSON_TOKENS for token in name.split())


def build_correspondent_recognizer():
    """Report the *name* in a header or salutation, not the whole line.

    Presidio's PatternRecognizer returns ``match.span()``, which here would
    include the "Dear " or "To: " that identified the name in the first place.
    A recognizer that tagged the prefix would report a span the report then
    quotes back with punctuation in it, and would overlap-suppress a correct
    NER span sitting inside it. So this one reports a named capture group.
    """
    import re

    from presidio_analyzer import EntityRecognizer, RecognizerResult

    class CorrespondentRecognizer(EntityRecognizer):
        def __init__(self) -> None:
            super().__init__(
                supported_entities=[PERSON], name="CorrespondentRecognizer"
            )
            self._patterns = [
                re.compile(pattern) for pattern in CORRESPONDENT_PATTERNS
            ]

        def load(self) -> None:  # required by the interface; nothing to load
            return None

        def analyze(self, text, entities, nlp_artifacts=None):
            if PERSON not in entities:
                return []
            results = []
            for pattern in self._patterns:
                for match in pattern.finditer(text):
                    start, end = match.span("target")
                    if looks_like_a_person(text[start:end]):
                        results.append(
                            RecognizerResult(
                                entity_type=PERSON,
                                start=start,
                                end=end,
                                score=CORRESPONDENT_SCORE,
                            )
                        )
            return results

    return CorrespondentRecognizer()


@lru_cache(maxsize=1)
def get_analyzer():
    """Build the Presidio engine once and reuse it.

    Constructing an ``AnalyzerEngine`` loads the spaCy model, which takes
    several seconds. Scanning a folder of files must not pay that per file.
    """
    # Presidio's URL/email recognisers use tldextract, which tries to fetch a
    # current public-suffix list on first use. Behind a proxy that fetch fails
    # noisily and dumps a traceback, then falls back to its bundled snapshot
    # and carries on correctly. Silence the report of a failure that is already
    # handled; it is not an error the operator can act on.
    logging.getLogger("tldextract").setLevel(logging.CRITICAL)

    from presidio_analyzer import AnalyzerEngine

    analyzer = AnalyzerEngine()
    analyzer.registry.add_recognizer(build_address_recognizer())
    analyzer.registry.add_recognizer(build_correspondent_recognizer())
    return analyzer


def scan_text(
    text: str,
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
    entities: tuple[str, ...] = NLP_ENTITIES,
) -> list[Match]:
    """Detect entities in ``text`` and return them as :class:`Match` objects.

    Converting to the same ``Match`` type the regex detector emits is what lets
    ``hybrid.merge`` treat both sources uniformly, and what lets one scoring
    function measure either engine.
    """
    if not text:
        return []

    results = get_analyzer().analyze(
        text=text,
        entities=list(entities),
        language="en",
        score_threshold=score_threshold,
    )
    matches = [
        Match(
            pii_type=result.entity_type,
            start=result.start,
            end=result.end,
            redacted=redact(result.entity_type, text[result.start : result.end]),
            source="nlp",
            score=result.score,
        )
        for result in results
    ]
    return sorted(matches, key=lambda m: (m.start, m.pii_type))
