"""Evaluate the detectors against third-party data instead of our own corpus.

Every accuracy figure in the README so far was measured on ``data/raw`` -- a
corpus this project generated, using sentence shapes this project chose. That
is a fair test of the code but a weak test of the *design*: a detector tuned
against phrasings it was also built from will score well on them, and the
number says less than it looks like it does. It is self-assessment.

This module measures the same detectors against text whose structure came
from somewhere else entirely:

* **Sentence templates** -- 209 of them, from Microsoft's ``presidio-research``
  project. These are the contexts the PII sits in: complaints to a bank, a
  block-formatted mailing address, a quoted email reply, a SQL injection
  string. Nobody on this project wrote them, and they were not consulted while
  the detectors were built.
* **Identities** -- 3,000 fabricated people from FakeNameGenerator, shipped in
  the same package. Names, streets, cities, phone numbers, emails and national
  IDs all come from that file. Notably the names are drawn from many locales,
  so even the US-resident rows carry surnames like ``Szûts`` and ``Gyarmaty``
  that an English NER model has far less reason to recognise than the Anglo
  names Faker's ``en_US`` locale produces.

Both files are vendored verbatim under ``data/external`` -- see the
``SOURCE.md`` there for provenance and checksums. The package itself is not a
dependency: it requires ``transformers``, ``scikit-learn`` and ``plotly`` at
unpinned lower bounds, which would pull several hundred megabytes into the
environment and fight every pin in ``requirements.txt`` for the sake of two
data files.

Two values still have to be generated here, and the docstring on
``_GENERATED`` says why.

The rendering follows the corpus generator's record-as-you-write rule: offsets
are captured as each value is written into the string, never recovered
afterwards with ``.find()``. A value that appears twice in one sentence would
make the second approach silently wrong.
"""

from __future__ import annotations

import csv
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

from faker import Faker

from src.detectors.nlp_detector import LOCATION, PERSON
from src.detectors.regex_detector import (
    CREDIT_CARD,
    EMAIL_ADDRESS,
    IP_ADDRESS,
    PHONE_NUMBER,
    US_SSN,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = REPO_ROOT / "data" / "external"
TEMPLATES_PATH = EXTERNAL / "presidio_templates.txt"
IDENTITIES_PATH = EXTERNAL / "fake_name_generator_3000.csv"

#: Fixed so a reported figure can be reproduced exactly. Changing it changes
#: which identity fills which template and therefore every number below.
SEED = 20260921

_PLACEHOLDER = re.compile(r"\{\{([a-z_]+)\}\}")

#: Gold spans of the same type separated only by these characters are one
#: entity, not two. The rule is deliberately identical to the one
#: ``hybrid._stitch`` applies to predictions: "793 Buena Vista Avenue" is a
#: single address whether the tool reports it as one span or as a stitched
#: pair, and holding gold to a different convention than predictions would
#: manufacture false negatives out of a formatting disagreement.
#:
#: Newlines are excluded on both sides. A block mailing address really is
#: several separate spans to a line-oriented detector, and pretending
#: otherwise would let one prediction claim credit for four gold entities.
_INLINE_FILLER = set(", \t")
_MAX_INLINE_GAP = 2


@dataclass
class Sentence:
    """One rendered template: the text, and exactly what is in it."""

    text: str
    findings: list[dict] = field(default_factory=list)
    #: Spans of the placeholders that carry no label -- a company name, a job
    #: title, a URL, an IBAN, a nationality. They are the benchmark's decoys,
    #: except that nobody chose them to be tempting. Recording where they sit
    #: is what lets a false positive be reported as "landed on {{organization}}"
    #: rather than as an anonymous count, without printing the text itself.
    distractors: list[dict] = field(default_factory=list)
    template_index: int = -1
    identity_index: int = -1

    def verify(self) -> None:
        """Assert the invariants every gold span must satisfy.

        The corpus generator learned this the hard way: a fixture whose answer
        key is subtly wrong produces accuracy figures that measure nothing, and
        looks exactly like a fixture whose answer key is right.
        """
        for item in self.findings:
            actual = self.text[item["start"] : item["end"]]
            if actual != item["value"]:
                raise AssertionError(
                    f"span {item['start']}:{item['end']} holds a different "
                    f"value than recorded (template {self.template_index})"
                )
        ordered = sorted(self.findings, key=lambda f: f["start"])
        for earlier, later in zip(ordered, ordered[1:]):
            if earlier["end"] > later["start"]:
                raise AssertionError(
                    f"overlapping gold spans in template {self.template_index}"
                )


# ------------------------------------------------------------ value sources


def _street_name(street_address: str) -> str:
    """"2071 Maryland Avenue" -> "Maryland Avenue"."""
    head, _, tail = street_address.partition(" ")
    return tail if head.isdigit() and tail else street_address


def _building_number(street_address: str) -> str:
    head, _, tail = street_address.partition(" ")
    return head if head.isdigit() and tail else "1"


#: Placeholders whose value cannot come from the vendored data.
#:
#: ``CCNumber`` in the identity file was saved through a spreadsheet and is
#: stored in scientific notation -- "4.55689E+15" -- so the real digits are
#: gone and no Luhn check could pass. There is no IP column at all. Both are
#: therefore minted by Faker, exactly as the corpus does it. This is worth
#: naming because it bounds the claim: the *contexts* in this benchmark are
#: entirely third-party, and so are the names, addresses, phones, emails and
#: SSNs, but two of the seven identifier types are still locally generated.
_GENERATED = frozenset({"credit_card_number", "ip_address", "iban",
                        "us_driver_license", "year", "date_time", "day_of_week"})


class _Values:
    """Resolves one placeholder against one identity row."""

    _DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")

    def __init__(self, seed: int) -> None:
        Faker.seed(seed)
        self.fake = Faker("en_US")
        self.rng = random.Random(seed)

    def resolve(self, name: str, row: dict[str, str]) -> str | None:
        """Return the text for ``{{name}}``, or None if it has no source.

        A placeholder with no source is left in the sentence verbatim. That is
        visible in the output rather than silently dropped, because a
        placeholder quietly deleted would change the surrounding context the
        detector reads.
        """
        given, surname = row["GivenName"], row["Surname"]
        full = f"{given} {surname}"
        street = row["StreetAddress"]

        simple = {
            "person": full,
            "name": full,
            "name_female": full,
            "name_male": full,
            "first_name": given,
            "first_name_male": given,
            "first_name_female": given,
            "first_name_nonbinary": given,
            "last_name": surname,
            "last_name_male": surname,
            "last_name_female": surname,
            "prefix": row["Title"],
            "prefix_male": row["Title"],
            "prefix_female": row["Title"],
            "city": row["City"],
            "state_abbr": row["State"],
            "zipcode": row["ZipCode"],
            "postcode": row["ZipCode"],
            "country": row["CountryFull"],
            "nationality": row["NameSet"],
            "nation_woman": row["NameSet"],
            "nation_plural": row["NameSet"],
            "street_name": _street_name(street),
            "building_number": _building_number(street),
            "email": row["EmailAddress"],
            "phone_number": row["TelephoneNumber"],
            "ssn": row["NationalID"],
            "organization": row["Company"],
            "job": row["Occupation"],
            "age": row["Age"],
            "date_of_birth": row["Birthday"],
            "url": f"www.{row['Domain']}",
            "address": (
                f"{street}, {row['City']}, {row['State']} {row['ZipCode']}"
            ),
            "secondary_address": f"Apt. {self.rng.randint(1, 940)}",
        }
        if name in simple:
            return simple[name] or None

        if name == "credit_card_number":
            digits = self.fake.credit_card_number(
                card_type=self.rng.choice(["visa16", "mastercard"])
            )
            groups = [digits[i : i + 4] for i in range(0, 16, 4)]
            return self.rng.choice([" ", "-", ""]).join(groups)
        if name == "ip_address":
            return self.fake.ipv4_private()
        if name == "iban":
            return self.fake.iban()
        if name == "us_driver_license":
            return f"{self.rng.randint(100000000, 999999999)}"
        if name == "year":
            return str(self.rng.randint(1995, 2024))
        if name == "date_time":
            return self.fake.date_time().strftime("%Y-%m-%d %H:%M")
        if name == "day_of_week":
            return self.rng.choice(self._DAYS)
        return None


#: What each placeholder is, in this tool's vocabulary.
#:
#: Anything absent is **out of scope and unlabelled**: the value is still
#: written into the sentence, so the detector has to cope with it, but nothing
#: about it is gold. A company name, a job title, a URL, an IBAN, a date of
#: birth and a nationality all sit in that bucket. If the detector reports one
#: of them as a PERSON or a LOCATION, that counts as a false positive -- which
#: is the correct accounting, because it is exactly what would appear in a
#: report handed to an operator.
#:
#: This is a stricter bar than the corpus applies. The corpus decoys were
#: written by the same person who wrote the patterns, so they probe the traps
#: that were already anticipated. These distractors were not chosen at all.
TYPE_OF = {
    "person": PERSON,
    "name": PERSON,
    "name_female": PERSON,
    "name_male": PERSON,
    "first_name": PERSON,
    "first_name_male": PERSON,
    "first_name_female": PERSON,
    "first_name_nonbinary": PERSON,
    "last_name": PERSON,
    "last_name_male": PERSON,
    "last_name_female": PERSON,
    "address": LOCATION,
    "street_name": LOCATION,
    "building_number": LOCATION,
    "secondary_address": LOCATION,
    "city": LOCATION,
    "state_abbr": LOCATION,
    "zipcode": LOCATION,
    "postcode": LOCATION,
    "country": LOCATION,
    "email": EMAIL_ADDRESS,
    "phone_number": PHONE_NUMBER,
    "ssn": US_SSN,
    "credit_card_number": CREDIT_CARD,
    "ip_address": IP_ADDRESS,
}

SCOREABLE_TYPES = frozenset(TYPE_OF.values())


# ---------------------------------------------------------------- rendering


def _unescape(template: str) -> str:
    r"""Turn the file's literal ``\n`` sequences into real characters.

    The templates store multi-line mailing addresses on one physical line, so
    the escapes have to be expanded before anything measures an offset.
    """
    out = template.replace("\\n", "\n").replace("\\t", "\t")
    return re.sub(r"\\([,|])", r"\1", out)


def load_templates(path: Path = TEMPLATES_PATH) -> list[str]:
    """The third-party sentence shapes, unescaped, blank lines dropped."""
    raw = path.read_text(encoding="utf-8")
    return [_unescape(line) for line in raw.splitlines() if line.strip()]


def load_identities(path: Path = IDENTITIES_PATH, *, us_only: bool = True) -> list[dict]:
    """The third-party identities, optionally narrowed to US residents.

    The split matters and is the point of the flag. This tool targets US
    formats explicitly -- the SSN pattern encodes SSA issuance rules, the
    address recognizer expects "City, ST 12345", the phone pattern expects a
    North American number. Measuring it against Cypriot postcodes and
    six-digit Greenlandic phone numbers would produce a low score that says
    nothing about the code's quality and everything about a scope decision
    made on purpose.

    So the headline number is measured on the US rows, and the international
    rows are measured separately as a scope probe. Both are reported. Hiding
    the second one would be the dishonest choice; letting it set the headline
    would be the misleading one.
    """
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if us_only:
        return [row for row in rows if row["Country"] == "US"]
    return [row for row in rows if row["Country"] != "US"]


def _merge_inline(findings: list[dict], text: str) -> list[dict]:
    """Join same-type gold spans that are adjacent on one line. See _INLINE_FILLER."""
    merged: list[dict] = []
    for item in sorted(findings, key=lambda f: f["start"]):
        if merged:
            previous = merged[-1]
            gap = text[previous["end"] : item["start"]]
            if (
                previous["type"] == item["type"] == LOCATION
                and len(gap) <= _MAX_INLINE_GAP
                and set(gap) <= _INLINE_FILLER
            ):
                previous["end"] = item["end"]
                previous["value"] = text[previous["start"] : previous["end"]]
                previous["placeholder"] += "+" + item["placeholder"]
                continue
        merged.append(dict(item))
    return merged


def render(
    template: str,
    row: dict[str, str],
    values: _Values,
    template_index: int = -1,
    identity_index: int = -1,
) -> Sentence:
    """Fill one template from one identity, recording offsets as it writes."""
    pieces: list[str] = []
    findings: list[dict] = []
    distractors: list[dict] = []
    position = 0
    cursor = 0

    for match in _PLACEHOLDER.finditer(template):
        literal = template[cursor : match.start()]
        pieces.append(literal)
        position += len(literal)

        name = match.group(1)
        value = values.resolve(name, row)
        # An unresolvable placeholder stays in the text verbatim rather than
        # vanishing: deleting it would change the context the detector reads.
        pii_type = TYPE_OF.get(name) if value is not None else None
        if value is None:
            value = match.group(0)

        start = position
        pieces.append(value)
        position += len(value)
        record = {
            "type": pii_type,
            "start": start,
            "end": position,
            "value": value,
            "placeholder": name,
        }
        (findings if pii_type is not None else distractors).append(record)
        cursor = match.end()

    pieces.append(template[cursor:])
    text = "".join(pieces)

    sentence = Sentence(
        text=text,
        findings=_merge_inline(findings, text),
        distractors=distractors,
        template_index=template_index,
        identity_index=identity_index,
    )
    sentence.verify()
    return sentence


def build(*, limit: int | None = None, us_only: bool = True, seed: int = SEED) -> list[Sentence]:
    """Render the benchmark set: every template, cycled against identities.

    Templates are walked in order so each one is exercised the same number of
    times; identities advance by a stride coprime with the row count so the
    pairing does not repeat until the whole grid is used.
    """
    templates = load_templates()
    identities = load_identities(us_only=us_only)
    if not identities:
        raise RuntimeError("no identities matched the requested region")

    values = _Values(seed)
    total = limit if limit is not None else len(templates)
    stride = 7  # coprime with 103 (US rows) and with 2,897 (the rest)

    out: list[Sentence] = []
    for index in range(total):
        template_index = index % len(templates)
        identity_index = (index * stride) % len(identities)
        out.append(
            render(
                templates[template_index],
                identities[identity_index],
                values,
                template_index,
                identity_index,
            )
        )
    return out
