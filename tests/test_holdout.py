"""Scoring against the held-out file, and the two accuracy fixes.

The main corpus has been tuned against repeatedly across every phase of this
project. A perfect score on it means no *known* failure mode remains -- it is
not evidence the detector is perfect, because the detector was shaped by that
corpus. These tests cover the file that was written once, scored once, and is
never used to adjust a pattern.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.detectors import hybrid, nlp_detector, regex_detector
from src.detectors.nlp_detector import looks_like_a_person
from src.detectors.regex_detector import find_ip_addresses
from src.evaluation import score_corpus

REPO_ROOT = Path(__file__).resolve().parents[1]
HOLDOUT_KEY = REPO_ROOT / "data" / "holdout_key.json"
ALL_TYPES = sorted(
    set(regex_detector.SUPPORTED_TYPES) | set(nlp_detector.NLP_ENTITIES)
)


@pytest.fixture(scope="module")
def holdout():
    return score_corpus(hybrid.scan_text, ALL_TYPES, answer_key_path=HOLDOUT_KEY)


def test_the_holdout_file_is_hand_written_not_generated():
    """If the generator ever produced it, it would stop being held out."""
    key = json.loads(HOLDOUT_KEY.read_text())
    assert "generator" not in key
    assert "held-out" in key["purpose"]


def test_the_holdout_file_covers_every_pii_type():
    key = json.loads(HOLDOUT_KEY.read_text())
    assert set(key["contents"]["pii"]) == set(ALL_TYPES)


def test_holdout_recall(holdout):
    assert holdout.totals.false_negatives == 0


def test_holdout_precision(holdout):
    assert holdout.totals.false_positives == 0


def test_every_holdout_decoy_is_rejected(holdout):
    """Three near misses: a claim reference, a policy number, a build number."""
    assert holdout.decoy_hits == []


# ------------------------------------------- IP version-string suppression


@pytest.mark.parametrize(
    "text",
    [
        "running client build 10.2.14.3.",
        "upgraded to v10.2.14.3",
        "firmware 1.2.3.4 shipped",
        "schema 2.0.1.5 applied",
        "release 3.4.5.6 is out",
        "driver: 2.1.0.4",
    ],
)
def test_a_version_string_is_not_an_ip_address(text):
    assert find_ip_addresses(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "the workstation at 10.235.204.93",
        "connect to 192.168.1.1.",
        "host 172.31.114.91 responded",
        "gateway is 10.0.0.1",
        "ssh 192.168.5.20 as root",
        # The keyword must sit immediately before the number. A looser window
        # suppressed this one, where "build" describes the server and the
        # address is entirely real -- the over-fitting this rule invites.
        "the build server at 10.1.2.3 is down",
        "release notes list the host 10.9.8.7 for staging",
        "after the upgrade, reach it at 172.16.0.5",
    ],
)
def test_a_real_address_survives_nearby_version_words(text):
    assert find_ip_addresses(text) != []


# ----------------------------------------------- correspondent recognizer


@pytest.mark.parametrize(
    "text, expected",
    [
        ("To:      Jennifer Brown <a@example.org>", "Jennifer Brown"),
        ("To: Jennifer Brown", "Jennifer Brown"),
        ("From:    Stacey Diaz", "Stacey Diaz"),
        ("Dear Fernando Proctor,", "Fernando Proctor"),
        ("Attn: Marcus Whitfield", "Marcus Whitfield"),
    ],
)
def test_a_name_is_found_by_where_it_sits(text, expected):
    """The padded header was a real miss: with one space the NER finds the
    name, with six it finds nothing. Position is the signal, not spelling."""
    found = [
        text[m.start : m.end]
        for m in nlp_detector.scan_text(text)
        if m.pii_type == "PERSON"
    ]
    assert expected in found


@pytest.mark.parametrize(
    "text",
    [
        "Dear Hiring Manager,",
        "To: Facilities Desk",
        "Dear Sir,",
        "Dear Valued Customer,",
        "To: Payroll Department",
        "Dear Team,",
    ],
)
def test_a_role_is_not_mistaken_for_a_person(text):
    found = [m for m in nlp_detector.scan_text(text) if m.pii_type == "PERSON"]
    assert found == [], "a role or department is not a person"


@pytest.mark.parametrize(
    "name, is_person",
    [
        ("Jennifer Brown", True),
        ("Marcus Whitfield", True),
        ("Hiring Manager", False),
        ("Facilities Desk", False),
        ("Valued Customer", False),
        ("Payroll Department", False),
    ],
)
def test_role_words_are_filtered(name, is_person):
    assert looks_like_a_person(name) is is_person
