"""Regex-based PII detection: the baseline every later phase is measured against.

Regex is the right tool for identifiers with *structure* -- an SSN is three
digits, a dash, two digits, a dash, four digits, and nothing about the
surrounding sentence changes that. It is the wrong tool for entities defined by
*context*: "Brooks" is a surname in one sentence and a creek in another, and no
pattern over characters can tell them apart. That gap is what Phase 4's NLP
layer exists to close, and keeping this module deliberately regex-only is what
makes the before/after comparison meaningful.

Matches never carry the raw matched text. ``Match.redacted`` holds a masked
preview and ``start``/``end`` say where to look if the real value is genuinely
needed. A scanner that logs what it finds should not be the reason sensitive
data ends up in a log file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

US_SSN = "US_SSN"
CREDIT_CARD = "CREDIT_CARD"
EMAIL_ADDRESS = "EMAIL_ADDRESS"
PHONE_NUMBER = "PHONE_NUMBER"
IP_ADDRESS = "IP_ADDRESS"

#: Types this module can find. PERSON and LOCATION are absent by design --
#: they need the NLP detector added in Phase 4.
SUPPORTED_TYPES = (US_SSN, CREDIT_CARD, EMAIL_ADDRESS, PHONE_NUMBER, IP_ADDRESS)


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------
# Several patterns use (?<!\d) / (?!\d) rather than \b. A word boundary is a
# transition between a word and a non-word character, so \b fails in front of
# "(555) 123-4567" -- the space before "(" is non-word and "(" is non-word, so
# there is no boundary there at all. Digit lookarounds express the actual
# intent: do not match a fragment of a longer run of digits.

# Area numbers 000, 666 and 900-999 are never issued; group 00 and serial 0000
# are never issued either. Encoding that costs one line and removes a whole
# class of false positive. Verified against the corpus: all 35 planted SSNs
# comply, so this tightening does not cost recall.
SSN_PATTERN = re.compile(
    r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"
)

# Pragmatic, not RFC 5322. The full grammar permits quoted strings, comments
# and nested parentheses; implementing it faithfully yields a pattern no one
# can maintain and that matches addresses no mail system accepts anyway.
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}"
)

# Three common US shapes: (555) 123-4567, 555-123-4567, 555.123.4567.
# Deliberately narrow. Real-world phone detection also has to cope with
# country codes, extensions and international formats; this corpus does not
# contain them, and pretending otherwise would inflate the scores.
PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\(\d{3}\)\s?\d{3}[-.]\d{4}|\d{3}[-.]\d{3}[-.]\d{4})(?!\d)"
)

# The backreference \1 forces one consistent separator, so "4111 1111-1111 1111"
# is not treated as a card number. Structure alone is weak here -- any sixteen
# digits match -- which is why every hit is then checked against Luhn below.
CREDIT_CARD_PATTERN = re.compile(r"(?<!\d)\d{4}([ -]?)\d{4}\1\d{4}\1\d{4}(?!\d)")

# Validating each octet is 0-255 in the pattern itself, rather than accepting
# \d{1,3} and letting 999.999.999.999 through.
#
# The trailing guard is (?!\.?\d), not (?![\d.]). Rejecting any following dot
# would also reject an address ending a sentence -- "connect to 192.168.1.1."
# -- because the sentence's full stop looks identical to an address separator.
# What actually needs excluding is a *further octet*, so the guard rejects a
# digit, or a dot followed by a digit, and lets ordinary punctuation through.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
IP_PATTERN = re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\.?\d)")


@dataclass(frozen=True)
class Match:
    """One detection. Carries a location and a masked preview, never the value.

    ``start`` and ``end`` are half-open character offsets into the scanned
    text, the same coordinates ``re`` reports and the same ones the Phase 2
    answer key records, so the two compare directly.

    ``source`` and ``score`` record which engine found this and how sure it
    was. Both default to the regex detector's situation -- it either matched or
    it did not, so its confidence is always 1.0 -- which keeps this constructor
    unchanged for the patterns above while giving the Phase 4 merge what it
    needs to arbitrate between two engines.
    """

    pii_type: str
    start: int
    end: int
    redacted: str
    source: str = "regex"
    score: float = 1.0

    def __repr__(self) -> str:  # keeps raw PII out of tracebacks and logs
        return (
            f"Match({self.pii_type}, {self.start}:{self.end}, "
            f"{self.redacted!r}, via {self.source})"
        )


def luhn_valid(digits: str) -> bool:
    """Luhn checksum, the validation every real card number satisfies.

    Double every second digit from the right, subtract 9 from any result above
    9, and a valid number sums to a multiple of 10. Roughly nine in ten random
    sixteen-digit strings fail it, which makes this the single largest
    precision win available to the credit card pattern.
    """
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def redact(pii_type: str, value: str) -> str:
    """Mask a value for display, keeping just enough to be actionable.

    Analysts need to recognise a record ("the card ending 3761") without the
    report itself becoming a second copy of the data.
    """
    if pii_type == EMAIL_ADDRESS and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[0]}{'*' * (len(local) - 1)}@{domain}"
    if pii_type == IP_ADDRESS:
        octets = value.split(".")
        return ".".join(octets[:2] + ["x"] * 2)
    if pii_type == "PERSON":
        # Initials are enough to correlate two findings about the same person
        # without the report naming them.
        return " ".join(
            word[0] + "*" * (len(word) - 1) for word in value.split() if word
        )
    if pii_type == "LOCATION":
        # No partial reveal: a street number alone can identify a household,
        # and there is no equivalent of "last four" that stays safe.
        return "*" * len(value)
    if pii_type in (US_SSN, CREDIT_CARD, PHONE_NUMBER):
        # Keep the last four digits and every separator; mask the rest, so the
        # shape of the value survives but its content does not.
        kept = 0
        out = []
        for char in reversed(value):
            if char.isdigit() and kept < 4:
                out.append(char)
                kept += 1
            elif char.isdigit():
                out.append("*")
            else:
                out.append(char)
        return "".join(reversed(out))
    return "*" * len(value)


def _find(pattern: re.Pattern[str], pii_type: str, text: str) -> list[Match]:
    return [
        Match(pii_type, m.start(), m.end(), redact(pii_type, m.group()))
        for m in pattern.finditer(text)
    ]


def find_ssns(text: str) -> list[Match]:
    return _find(SSN_PATTERN, US_SSN, text)


def find_emails(text: str) -> list[Match]:
    return _find(EMAIL_PATTERN, EMAIL_ADDRESS, text)


def find_phones(text: str) -> list[Match]:
    return _find(PHONE_PATTERN, PHONE_NUMBER, text)


def find_ip_addresses(text: str) -> list[Match]:
    return _find(IP_PATTERN, IP_ADDRESS, text)


def find_credit_cards(text: str) -> list[Match]:
    """Structural match followed by a Luhn check.

    The pattern proposes; Luhn disposes. Without the second step every
    sixteen-digit purchase order in the corpus would be reported as a card.
    """
    matches = []
    for m in CREDIT_CARD_PATTERN.finditer(text):
        raw = m.group()
        if luhn_valid(re.sub(r"[ -]", "", raw)):
            matches.append(
                Match(CREDIT_CARD, m.start(), m.end(), redact(CREDIT_CARD, raw))
            )
    return matches


#: Consulted only when two matches overlap. An SSN misreported as a phone
#: number understates risk, so the more sensitive type wins the tie.
_PRIORITY = {
    US_SSN: 0,
    CREDIT_CARD: 1,
    EMAIL_ADDRESS: 2,
    PHONE_NUMBER: 3,
    IP_ADDRESS: 4,
}


def _resolve_overlaps(matches: list[Match]) -> list[Match]:
    """Drop matches that overlap a already-accepted, better match.

    Patterns are written independently and can both fire on one span. Emitting
    both would double-count a single value in the Phase 6 risk score. Longer
    matches win first (they explain more of the text), then the more sensitive
    type.
    """
    ranked = sorted(
        matches, key=lambda m: (-(m.end - m.start), _PRIORITY[m.pii_type], m.start)
    )
    kept: list[Match] = []
    for candidate in ranked:
        if any(
            candidate.start < other.end and other.start < candidate.end
            for other in kept
        ):
            continue
        kept.append(candidate)
    return sorted(kept, key=lambda m: (m.start, m.pii_type))


def scan_text(text: str) -> list[Match]:
    """Find every supported PII type in ``text``.

    Returns matches sorted by position, with overlaps resolved. This is the
    entry point Phase 4 merges Presidio results into and Phase 7's scanner
    calls per file.
    """
    matches = (
        find_ssns(text)
        + find_credit_cards(text)
        + find_emails(text)
        + find_phones(text)
        + find_ip_addresses(text)
    )
    return _resolve_overlaps(matches)
