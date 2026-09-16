# Sensitive Data Discovery Tool

Python based detection tool combining regex pattern matching and Microsoft Presidio's NLP engine to identify SSNs, credit card numbers, emails, phone numbers, and addresses across document sets, modeling data governance workflows used in e-discovery and compliance.

> **Status:** in progress. Scaffold (Phase 1), synthetic corpus and answer key (Phase 2), regex baseline (Phase 3), and hybrid regex+NLP detection (Phase 4) are complete; multi-format parsing, risk scoring, CLI, and UI are still being built.

## Planned capabilities

- **Hybrid detection** — a regex baseline for structured identifiers (SSN, credit card, email, phone, IP) merged with Presidio NLP results for contextual entities (`PERSON`, `LOCATION`).
- **Multi-format parsing** — `.txt`, `.csv`, `.pdf`, and `.docx` files, dispatched by extension.
- **Risk scoring** — weighted per PII type, aggregated into a per-file risk score.
- **Reporting** — pandas-backed CSV and JSON reports.
- **Two front ends** — an `argparse` CLI and a Streamlit UI.

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/smithkscyber/Sensitive-Data-Discovery-Tool.git
cd Sensitive-Data-Discovery-Tool

python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

pip install -r requirements.txt
python -m spacy download en_core_web_lg    # ~560MB language model
```

Verify the scaffold runs:

```bash
python main.py
```

## Project structure

```
Sensitive-Data-Discovery-Tool/
├── data/
│   ├── raw/              # synthetic test files (no real PII, ever)
│   ├── pending/          # source text for docx/pdf fixtures (Phase 5)
│   └── answer_key.json   # ground truth: types + character offsets
├── src/
│   ├── detectors/        # regex_detector, nlp_detector, hybrid merge
│   ├── parsers/          # per-format text extraction
│   ├── reporting/        # risk scoring and report building
│   └── evaluation.py     # precision/recall against the answer key
├── scripts/
│   ├── generate_test_data.py
│   ├── score_detector.py
│   └── compare_detectors.py
├── tests/
├── app.py                # Streamlit entry point
├── main.py               # CLI entry point
├── requirements.txt
└── README.md
```

## Detection

Two engines, because neither is sufficient alone.

**`regex_detector.py`** matches shape. Good for identifiers with fixed structure, and validated beyond the pattern where possible:

| Type | Notes |
|---|---|
| `US_SSN` | Encodes real issuance rules — areas `000`, `666`, `900–999`, group `00`, serial `0000` are never issued |
| `CREDIT_CARD` | Structural match, then a Luhn checksum. The checksum is what rejects sixteen-digit order numbers |
| `EMAIL_ADDRESS` | Pragmatic pattern, not full RFC 5322 |
| `PHONE_NUMBER` | Three common US formats |
| `IP_ADDRESS` | Octets validated `0–255` |

**`nlp_detector.py`** wraps Presidio's `AnalyzerEngine`, which runs a spaCy NER model and so can use context. It is the only source for `PERSON` — an entity defined by meaning rather than shape, which no character pattern can reach.

It also registers a **custom US address recognizer**. The NER alone reads an address as loose fragments and mislabels the parts, because street and city names are drawn from personal names in the real world as much as in Faker — Washington, Jackson, Madison. Structure resolves what context cannot: no person's name is followed by a comma, a state code and a ZIP. Tokens must be title-case, which is what separates an address from a sentence that happens to contain commas and digits.

**`hybrid.py`** merges them. Not a concatenation: a set of rules about who to believe.

- **Regex is authoritative** for the five structured types, where it is checksum- and format-validated. Where both engines fire on one span, the regex verdict wins.
- **Authority is not a veto.** A Presidio match that regex simply missed is still kept — dropping it would discard the recall the NLP layer was added for.
- **Longer spans win** between equally trusted matches, so a `PERSON` detected *inside* an address is treated as a fragment of it rather than a second finding.
- **`LOCATION` fragments are stitched.** Presidio reads `123 Main Street, Springfield, IL` as two separate spans. One address should be one finding. Stitching is restricted to `LOCATION` and to gaps of punctuation — applying it to every type would merge two adjacent emails in a CSV row into one.

Matches never carry the raw matched text, from either engine. A `Match` holds the type, the span, a masked preview, its source, and a confidence score.

### Scoring

```bash
python scripts/compare_detectors.py    # all three detectors side by side
python scripts/score_detector.py       # regex baseline only
python -m pytest tests/                # 118 unit + corpus tests
```

Measured over all 14 corpus files:

```
DETECTOR                   PRECISION    RECALL        F1    TP    FP    FN
Regex only                     0.962     1.000     0.981   126     5     0
Presidio NLP only              0.862     0.977     0.916   213    34     5
Hybrid (regex + NLP)           0.978     0.991     0.984   221     5     2
```

Per type, the hybrid:

```
TYPE              FOUND  ACTUAL    TP   FP   FN    PREC  RECALL      F1
CREDIT_CARD           8       8     8    0    0   1.000   1.000   1.000
EMAIL_ADDRESS        43      43    43    0    0   1.000   1.000   1.000
IP_ADDRESS           10       5     5    5    0   0.500   1.000   0.667
LOCATION             35      35    35    0    0   1.000   1.000   1.000
PERSON               60      62    60    0    2   1.000   0.968   0.984
PHONE_NUMBER         35      35    35    0    0   1.000   1.000   1.000
US_SSN               35      35    35    0    0   1.000   1.000   1.000
```

**Read the TP column, not the F1 column.** Regex scores the highest F1 — but only because it is graded on the 126 findings it is capable of attempting, ignoring the 97 `PERSON` and `LOCATION` values it cannot see. The hybrid is measured on all 223 and finds 221 of them. Comparing F1 across detectors with different scopes compares the difficulty of the subset, not the quality of the engine.

Against the fair comparison — NLP alone, scored on the same entity set — the merge improves **both** precision (0.862 → 0.978) and recall (0.977 → 0.991). Those gains are traceable to specific rules:

| Row | Effect of the merge |
|---|---|
| `CREDIT_CARD` | Presidio finds 6 of 8; regex finds all 8, and authority keeps them → recall 0.750 → 1.000 |
| `PHONE_NUMBER` | Presidio contributes 6 false positives; regex authority drops them → precision 0.850 → 1.000 |
| `PERSON` | Presidio emits 28 spurious spans inside addresses; the longest-span rule discards them → precision 0.682 → 1.000 |

That `PERSON` row is the clearest argument for having a merge layer at all. **Neither piece fixes it alone.** Presidio still emits all 28 spurious spans even with the address recognizer installed — it does not reconcile its own overlapping opinions. What removes them is the combination: the recognizer supplies a full-address span, and the merge then treats a `PERSON` sitting inside one as a fragment of it.

### Guarding against over-fitting

A custom pattern written against the corpus it is then scored on is the classic way to manufacture good numbers. The address recognizer is held to two checks that the corpus score cannot provide, both in the test suite:

- **300 addresses from a seed the pattern was never tuned against** — all matched in full. A change that raises the corpus score by narrowing onto the committed fixtures fails this test.
- **200 paragraphs of address-free prose** — zero false positives.

Plus seven hand-written real addresses (`1600 Pennsylvania Avenue NW, Washington, DC 20500`, `18 Rue St. Charles, St. Paul, MN 55102`) that cover format variation the generator never produces, and six adversarial near misses that must stay clean.

The honest limit: the 300-address check tests generalization across address *instances*, not across address *formats*. Those are still Faker's US layout. The hand-written cases cover format variation, but seven examples is seven examples.

### Known limitations

**Two `PERSON` values are still missed** — one in a `To:` header, one in a `Dear ...` salutation. Plain NER misses, unrelated to addresses.

**`IP_ADDRESS` precision is 0.500**, unchanged from Phase 3. Presidio does not detect IPs in the configured entity set, so the merge has no second opinion to bring, and the version-string decoys still fool the pattern.

**These numbers are tied to the pinned versions.** Presidio's accuracy comes from a spaCy model; upgrading `en_core_web_lg` changes which entities are found and how their spans are bounded.

### What these numbers do not mean

The phone patterns cover three formats because the corpus contains three. Real-world phone detection also faces country codes, extensions, and international formats. Recall of 1.000 here means "found everything in a corpus built from these formats", not "solved phone detection".

## Test data and the answer key

All test data is synthetic, generated with [Faker](https://faker.readthedocs.io/). No real personal data is used in this repository — not in commits, not in test fixtures, not in examples. Generated email addresses use only RFC 2606 reserved domains (`example.com` and friends), so no address can reach a real mailbox.

Regenerate the corpus with:

```bash
python scripts/generate_test_data.py
```

| Path | Contents |
|---|---|
| `data/raw/` | 5 `.txt` memos and 3 `.csv` contact lists — scannable today |
| `data/pending/` | Source text for 3 `.docx` contracts and 3 `.pdf` letters, converted to their real formats in Phase 5 |
| `data/answer_key.json` | Ground truth: every planted value, its type, and its character offsets |

### Why the answer key records offsets

Each finding carries a half-open `[start, end)` character span into the UTF-8 decoded file text — the same coordinate space Python's `re` reports matches in. That makes it possible to measure real precision and recall in Phase 3, rather than only asking "did this file contain an SSN somewhere."

Each file also carries a `text_sha256`. If a file drifts out of sync with the key, the hash catches it before the offsets start silently pointing at the wrong text.

### Decoys

The corpus deliberately plants values that *resemble* PII but are not sensitive — nine-digit employee numbers, sixteen-digit purchase orders that fail the Luhn checksum, a software version string shaped like an IP address. They are recorded separately under `decoys`. Without them a detector that flags every digit string would score perfect recall and never be penalised for it.

### Determinism

The generator is seeded, and `requirements.txt` pins exact versions. Faker reproduces the same fake people only within a given version — an unpinned upgrade would change the generated text, shift every offset, and invalidate the key. Upgrade deliberately, then regenerate the corpus and key together.

The generator refuses to write a corpus it cannot verify: it asserts every recorded span holds the value it claims, that no spans overlap, and that no planted value appears in the text more times than it was recorded.

### Redaction

Values appear in the answer key because scoring needs them and every one is fabricated. That is not a licence for the tool itself — detector and report output redacts matched values, showing type, position, and at most a partial value.

## License

MIT — see [LICENSE](LICENSE).
