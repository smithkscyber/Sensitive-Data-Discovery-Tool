# Sensitive Data Discovery Tool

Python based detection tool combining regex pattern matching and Microsoft Presidio's NLP engine to identify SSNs, credit card numbers, emails, phone numbers, and addresses across document sets, modeling data governance workflows used in e-discovery and compliance.

> **Status:** in progress. Scaffold (Phase 1), synthetic corpus and answer key (Phase 2), regex baseline (Phase 3), hybrid regex+NLP detection (Phase 4), multi-format parsing (Phase 5), and risk scoring and reporting (Phase 6) are complete; the CLI and UI are still being built.

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
│   ├── raw/              # synthetic .txt/.csv/.docx/.pdf (no real PII, ever)
│   └── answer_key.json   # ground truth: types + character offsets
├── src/
│   ├── detectors/        # regex_detector, nlp_detector, hybrid merge
│   ├── parsers/          # text/csv/docx/pdf extraction + dispatcher
│   ├── reporting/        # risk_scorer, report_builder
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
python -m pytest tests/                # 223 unit + corpus tests
```

Measured over all 14 corpus files:

```
DETECTOR                   PRECISION    RECALL        F1    TP    FP    FN
Regex only                     0.962     1.000     0.981   126     5     0
Presidio NLP only              0.866     0.977     0.918   213    33     5
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

Against the fair comparison — NLP alone, scored on the same entity set — the merge improves **both** precision (0.866 → 0.978) and recall (0.977 → 0.991). Those gains are traceable to specific rules:

| Row | Effect of the merge |
|---|---|
| `CREDIT_CARD` | Presidio finds 6 of 8; regex finds all 8, and authority keeps them → recall 0.750 → 1.000 |
| `PHONE_NUMBER` | Presidio contributes 6 false positives; regex authority drops them → precision 0.850 → 1.000 |
| `PERSON` | Presidio emits 27 spurious spans inside addresses; the longest-span rule discards them → precision 0.690 → 1.000 |

That `PERSON` row is the clearest argument for having a merge layer at all. **Neither piece fixes it alone.** Presidio still emits all 27 spurious spans even with the address recognizer installed — it does not reconcile its own overlapping opinions. What removes them is the combination: the recognizer supplies a full-address span, and the merge then treats a `PERSON` sitting inside one as a fragment of it.

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

## Parsing

`src/parsers/` extracts text per format and dispatches on extension:

| Format | Extractor | Round-trip fidelity |
|---|---|---|
| `.txt` | direct read | Exact |
| `.csv` | `pandas`, flattened to text | Lossless, but reflowed |
| `.docx` | `python-docx`, paragraphs + tables | Exact |
| `.pdf` | `pdfplumber`, page by page | **Lossy** — blank lines disappear |

An unknown extension raises rather than returning `""`. Silence would make an unreadable file indistinguishable from a clean one, which is the most dangerous result this tool can produce.

### The invariant: offsets index parsed text, not bytes

Every offset in the answer key is derived by running the finished file back through the same `parse()` the scanner uses. This matters because for three of the four formats, the text on disk is not the text a detector sees:

```
FILE                FMT    RAW BYTES   PARSED CHARS
memo_01.txt         txt          731            731     identical
contacts_01.csv     csv         1051           1079     quotes dropped, cells rejoined
contract_01.docx    docx       37104            755     a ZIP of XML
letter_01.pdf       pdf         1489            682     blank lines gone
```

A PDF stores glyphs at coordinates, not text. Extraction reconstructs reading order from positions — and a blank line paints nothing, so it leaves nothing to find. Had the source offsets been kept, every one would have been wrong:

```
using the OLD offsets against the converted file:
  [  53:69  ] expected 'Fernando Proctor'    got 'ernando Proctor\n'    WRONG
  [ 126:142 ] expected 'Fernando Proctor'    got 'rnando Proctor,\n'    WRONG
```

The CSV shifted too (+5 to +28 characters), which is the less obvious half: it is easy to anticipate that PDF mangles layout and forget that flattening a table does the same thing.

Detection accuracy is **unchanged** after the conversion — precision 0.978, recall 0.991, exactly as in Phase 4. That is the point. The corpus got harder to read; the offsets were re-derived correctly; the numbers held.

## Risk scoring and reporting

A scan of a real file share returns thousands of findings, and nobody reads thousands of findings. The score exists for triage — which file does someone open first — so the rule is a judgement about harm, written where a reviewer can argue with it.

| Type | Weight | Why |
|---|---|---|
| `US_SSN` | 10 | Permanent and effectively non-reissuable — a lifetime identity-theft exposure |
| `CREDIT_CARD` | 9 | Direct financial loss, but a card is cancelled and reissued in days, so the harm has a floor |
| `LOCATION` | 5 | A home address enables physical-world harm and is directly identifying |
| `EMAIL_ADDRESS` | 3 | Contact detail *and* account identifier — the hinge for password resets |
| `IP_ADDRESS` | 3 | A quasi-identifier: personal data under GDPR, little use alone |
| `PHONE_NUMBER` | 2 | Widely circulated already; a SIM-swap vector, not a standalone disclosure |
| `PERSON` | 2 | A name alone is often public; it matters as the key that makes everything else on the page identifying |

An unrecognised type scores 5, not 0. Scoring the unknown as harmless would let adding a new detector make a file look *safer* than before.

### Why the score is not just a weighted sum

`weight × count`, summed, is the obvious rule — and it has an obvious failure: **volume drowns severity.** Straight from this project's own corpus:

```
 37  memo_01.txt     (11 findings, no card, no volume of anything serious)
 33  letter_01.pdf   ( 7 findings, holds an SSN *and* a credit card)
```

Sorted by total, the memo gets triaged first. That is the wrong answer.

So a file is never ranked below its single most sensitive item. One SSN puts a file in `HIGH` however quiet the rest of it is; volume escalates from there, which is what carries the contact CSVs up into `CRITICAL`.

| Band | Reached by |
|---|---|
| `CRITICAL` | Total ≥ 100 |
| `HIGH` | Total ≥ 30, **or** containing any SSN / credit card |
| `MEDIUM` | Total ≥ 10, **or** containing any home address |
| `LOW` | Anything found at all |
| `NONE` | Clean |

### Two frames

```
FILE              FMT   FINDINGS   RISK  PEAK  BAND
contacts_01.csv   csv         40    176    10  CRITICAL
memo_02.txt       txt         12     46    10  HIGH
contract_01.docx  docx         9     38    10  HIGH
letter_01.pdf     pdf          7     33    10  HIGH
```

`write_reports()` emits both views in the format you ask for — `report.csv` (one row per file, triage order) and `report.findings.csv` beside it (one row per file and PII type). Both export to CSV or JSON.

A clean file still gets a row. A file missing from a report is indistinguishable from a file that was never scanned.

### Reports contain no PII

Only types, counts and scores cross into a report — never a matched value, not even redacted. A report should be safe to attach to a ticket or mail to a reviewer without becoming a second copy of the data it exists to warn about.

That is enforced by a test that scans the real corpus, writes a real report, and asserts that not one of the 223 planted values appears anywhere in the output.

*Caveat on the bands:* every file in this corpus contains an SSN, so every one scores `HIGH` or `CRITICAL`. The corpus cannot exercise `LOW`, `MEDIUM` or `NONE` at all — those paths are covered by unit tests instead.

## Test data and the answer key

All test data is synthetic, generated with [Faker](https://faker.readthedocs.io/). No real personal data is used in this repository — not in commits, not in test fixtures, not in examples. Generated email addresses use only RFC 2606 reserved domains (`example.com` and friends), so no address can reach a real mailbox.

Regenerate the corpus with:

```bash
python scripts/generate_test_data.py
```

| Path | Contents |
|---|---|
| `data/raw/` | 5 `.txt` memos, 3 `.csv` contact lists, 3 `.docx` contracts, 3 `.pdf` letters |
| `data/answer_key.json` | Ground truth: every planted value, its type, and its character offsets |

### Why the answer key records offsets

Each finding carries a half-open `[start, end)` character span into the UTF-8 decoded file text — the same coordinate space Python's `re` reports matches in. That makes it possible to measure real precision and recall in Phase 3, rather than only asking "did this file contain an SSN somewhere."

Each file also carries a `text_sha256`. If a file drifts out of sync with the key, the hash catches it before the offsets start silently pointing at the wrong text.

### Decoys

The corpus deliberately plants values that *resemble* PII but are not sensitive — nine-digit employee numbers, sixteen-digit purchase orders that fail the Luhn checksum, a software version string shaped like an IP address. They are recorded separately under `decoys`. Without them a detector that flags every digit string would score perfect recall and never be penalised for it.

### Determinism

The generator is seeded, and `requirements.txt` pins exact versions. Faker reproduces the same fake people only within a given version — an unpinned upgrade would change the generated text, shift every offset, and invalidate the key. Upgrade deliberately, then regenerate the corpus and key together.

`.txt` and `.csv` fixtures are byte-identical run to run. The `.docx` and `.pdf` fixtures carry fixed metadata timestamps so regenerating does not produce spurious diffs, but their compressed bytes are not guaranteed identical across library versions. What *is* guaranteed stable is the text their parsers extract — which is what the offsets index, and what the `text_sha256` in the key hashes.

The generator refuses to write a corpus it cannot verify: it asserts every recorded span holds the value it claims, that no spans overlap, and that no planted value appears in the text more times than it was recorded.

### Redaction

Values appear in the answer key because scoring needs them and every one is fabricated. That is not a licence for the tool itself — detector and report output redacts matched values, showing type, position, and at most a partial value.

## License

MIT — see [LICENSE](LICENSE).
