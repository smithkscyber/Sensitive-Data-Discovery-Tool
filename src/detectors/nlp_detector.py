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

    return AnalyzerEngine()


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
