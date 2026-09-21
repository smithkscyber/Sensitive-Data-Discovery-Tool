# Sensitive Data Discovery Tool

Python based detection tool combining regex pattern matching and Microsoft Presidio's NLP engine to identify SSNs, credit card numbers, emails, phone numbers, and addresses across document sets, modeling data governance workflows used in e-discovery and compliance.

> **Status:** feature-complete and tested. 374 tests, CI on every push. A final README restructure is the last item outstanding.

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

pip install -r requirements.lock.txt      # or requirements.txt for looser pins
python -m spacy download en_core_web_lg   # ~560MB language model
```

For OCR — needed to read scanned documents and images — also install Tesseract, which is a system binary rather than a Python package:

```bash
sudo apt-get install tesseract-ocr        # Debian/Ubuntu
brew install tesseract                    # macOS
```

Without it the tool still runs; scanned files are reported as producing no text instead of being read.

Then scan something:

```bash
python main.py --input data/raw --output report.csv
```

## Project structure

```
Sensitive-Data-Discovery-Tool/
├── data/
│   ├── raw/              # generated corpus (no real PII, ever)
│   ├── holdout/          # one hand-written file, never tuned against
│   ├── edge_cases/       # deliberately unreadable fixtures
│   ├── external/         # third-party benchmark data, vendored verbatim
│   ├── answer_key.json   # ground truth: types + character offsets
│   └── holdout_key.json  # ground truth for the held-out file
├── src/
│   ├── access.py         # confines server-side scans to a scan root
│   ├── detectors/        # regex_detector, nlp_detector, hybrid merge
│   ├── parsers/          # 18 formats + OCR, behind one dispatcher
│   ├── reporting/        # risk_scorer, report_builder
│   ├── benchmark.py      # renders the third-party benchmark, with offsets
│   ├── evaluation.py     # precision/recall against the answer key
│   ├── scanner.py        # walks a path: parse -> detect -> score
│   └── uploads.py        # stages uploaded files, then deletes them
├── scripts/
│   ├── generate_test_data.py
│   ├── score_detector.py
│   ├── compare_detectors.py
│   └── benchmark_external.py
├── tests/
├── setup.cfg             # mutation-testing configuration
├── app.py                # Streamlit entry point
├── main.py               # CLI entry point
├── requirements.txt      # direct dependencies, with the reasoning
├── requirements.lock.txt # the full resolved tree
└── README.md
```

## Usage

```bash
python main.py --input data/raw --output report.csv
```

```
FILE              FMT   FINDINGS   RISK  PEAK  BAND
contacts_01.csv   csv         40    176    10  CRITICAL
contacts_02.csv   csv         40    176    10  CRITICAL
memo_02.txt       txt         12     46    10  HIGH
contract_01.docx  docx         9     38    10  HIGH
letter_01.pdf     pdf          7     33    10  HIGH
site_note_01.txt  txt          1      5     5  MEDIUM
bulletin_01.txt   txt          2      5     3  LOW
retention_01.txt  txt          0      0     0  NONE
...
17 files, 229 findings  (NONE 1, LOW 1, MEDIUM 1, HIGH 11, CRITICAL 3)
```

| Flag | Meaning |
|---|---|
| `--input`, `-i` | File or directory to scan (required) |
| `--output`, `-o` | Report path, `.csv` or `.json` (default `report.csv`) |
| `--no-recursive` | Stay at the top level |
| `--quiet`, `-q` | Write reports without printing the table |

Two reports are written: `report.csv` (one row per file, triage order) and `report.findings.csv` beside it (one row per file and PII type).

### Web UI

```bash
streamlit run app.py
```

Two ways in, one code path behind them: **drag files onto the uploader**, or point it at a folder on the machine running the app.

**The folder field is confined to a scan root** — `SDD_SCAN_ROOT`, defaulting to the working directory. Paths are resolved before the check, so neither `../../etc` nor a symlink planted inside the root escapes it. Unrestricted, that text box would let anyone who can reach the page read any file on the server. The CLI is deliberately *not* confined: whoever runs it already has their shell's access, and fencing that in would be theatre. Both call `scanner.scan_path()` — no detection logic lives in the UI, so the CLI and the web app can never disagree about what the tool found.

The results view carries the same four metrics as the CLI summary, a per-file table with the band colour-coded, a findings-by-type chart, and CSV/JSON downloads. Unreadable files get their own section rather than being dropped.

**Uploads never persist.** Streamlit hands over bytes in memory while every parser needs a real path, so uploads are written to a `TemporaryDirectory` that is removed when the scan returns — including when it raises. A tool whose job is finding sensitive data should not be the reason copies of it accumulate in `/tmp`. Result rows are relabelled with the original filenames, so a report names the file you dropped rather than a temp path, and never discloses the server's filesystem layout.

That staging logic lives in `src/uploads.py`, not in `app.py`: it has a contract worth testing, and a Streamlit script cannot be imported outside a Streamlit runtime.

### OCR: reading scanned documents

A scanned contract has no text layer — it is an image of a page. Every parser above returns `""`, so the file scores clean. Scanned documents are routine in e-discovery, so this was the most dangerous gap in the tool:

```
before:  extracted ''  ->  0 findings, band NONE, exit 0
after:   OCR         ->  2 findings, band HIGH
```

`.png`, `.jpg`, `.tif` and `.bmp` are scanned the same way.

**OCR runs only where there is no text layer, and only on the pages that need it.** A digital PDF parses in 0.02s and never touches OCR; a mixed document with two scanned inserts pays for two pages, not for the whole file. Pass `use_ocr=False` to skip it entirely on large shares.

**What OCR costs you:** structured detection is only as good as the characters it is handed. On a poor-quality scan Tesseract reads `SSN: 623-98-0035` as `SSSN-623-98 0035` — the separators are mangled, so the SSN pattern no longer matches even though OCR "worked". The NLP layer is more forgiving, which is the same regex-versus-context trade the whole detector rests on. There is a test documenting this rather than hiding it.

### Three outcomes, all reported

Pointed at a directory nobody curated, every file lands in exactly one state:

| State | Meaning |
|---|---|
| **scored** | Read and scanned — findings may be zero |
| **skipped** | No extractor for that extension (`.zip`) — listed on stderr |
| **failed** | An extractor was tried and raised (corrupt PDF, broken DOCX, **password-protected** file) — listed on stderr |

Scored files that yielded **no text at all** are additionally listed. That case matters because it used to be invisible: a scanned PDF is a picture of a page, so extraction *succeeds* and returns nothing, and the file scores zero findings with a `NONE` band — indistinguishable from a genuinely clean document. OCR now recovers most of those; when it cannot, the fact stays visible.

The distinction between the last two and *"scored, nothing found"* is the point. **A file the tool could not read is not a clean file**, and a clean result is exactly what nobody investigates. One bad file never aborts a scan, and never disappears from it either:

```
Failed to read 2 file(s):
  messy/broken.docx: PackageNotFoundError: Package not found at 'messy/broken.docx'
  messy/corrupt.pdf: PdfminerException: No /Root object! - Is this really a PDF?
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every file was read, whether or not anything was found |
| `1` | At least one file could not be read |
| `2` | Bad arguments, or the input path does not exist |

A scan that found nothing and a scan that could not read half the share must not look the same to a caller, so an unreadable file is a non-zero exit rather than a line of output somebody might miss. Skipped files do *not* make a scan incomplete — having no extractor for `.zip` is an honest answer; failing to read a `.pdf` you claimed to support is a gap in coverage.

### End-to-end against the answer key

The full CLI run, per-type totals compared against ground truth:

```
TYPE              TRUTH  REPORT  DELTA  explanation
CREDIT_CARD           8       8     +0
EMAIL_ADDRESS        43      43     +0
IP_ADDRESS            5      10     +5   5 planted version-string decoys, by design
LOCATION             35      35     +0
PERSON               62      60     -2   2 known NER misses (To: header, Dear salutation)
PHONE_NUMBER         35      35     +0
US_SSN               35      35     +0
```

Five of seven types exact; both deltas are the known, documented discrepancies, asserted in the test suite so they cannot drift silently.

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

- **Regex is authoritative** for the five structured types, where it is checksum- and format-validated, and its boundaries are exact. A validated match beats *any* overlapping NLP span, not just one claiming the same type — an earlier version ranked by source only within a type, which let a mis-bounded `PERSON` span discard a Luhn-validated credit card purely by being longer.
- **Authority is not a veto.** A Presidio match that regex simply missed is still kept — dropping it would discard the recall the NLP layer was added for.
- **Longer spans win** between equally trusted matches, so a `PERSON` detected *inside* an address is treated as a fragment of it rather than a second finding.
- **`LOCATION` fragments are stitched.** Presidio reads `123 Main Street, Springfield, IL` as two separate spans. One address should be one finding. Stitching is restricted to `LOCATION` and to gaps of punctuation — applying it to every type would merge two adjacent emails in a CSV row into one.

Matches never carry the raw matched text, from either engine. A `Match` holds the type, the span, a masked preview, its source, and a confidence score.

### Scoring

```bash
python scripts/compare_detectors.py    # all three detectors side by side
python scripts/score_detector.py       # regex baseline only
python -m pytest tests/                # 431 unit, corpus and property tests
python scripts/benchmark_external.py   # third-party data, not ours
```

Measured over all 17 corpus files:

```
DETECTOR                   PRECISION    RECALL        F1    TP    FP    FN
Regex only                     1.000     1.000     1.000   128     0     0
Presidio NLP only              0.868     0.982     0.921   217    33     4
Hybrid (regex + NLP)           1.000     1.000     1.000   226     0     0
-------------------------------------------------------------------------
Held-out (not tuned on)        1.000     1.000     1.000     9     0     0
```

**Read the last row first, and treat the ones above it sceptically.** The corpus
was tuned against across every phase of this project — patterns were adjusted
until it scored well. A perfect score on it means *no known failure mode
remains*, which is a weaker claim than it looks. `data/holdout/` holds one
hand-written file that was scored once and is never used to adjust a pattern;
that row is evidence, the rest is a detector grading its own homework.

One hand-written file is thin evidence, though, so the next section measures
the same detectors against 1,045 sentences built from templates and identities
this project did not write. **That is the number to judge the tool by:
precision 0.927, recall 0.816.**

Per type, the hybrid:

```
TYPE              FOUND  ACTUAL    TP   FP   FN    PREC  RECALL      F1
CREDIT_CARD           8       8     8    0    0   1.000   1.000   1.000
EMAIL_ADDRESS        44      44    44    0    0   1.000   1.000   1.000
IP_ADDRESS            5       5     5    0    0   1.000   1.000   1.000
LOCATION             36      36    36    0    0   1.000   1.000   1.000
PERSON               62      62    62    0    0   1.000   1.000   1.000
PHONE_NUMBER         36      36    36    0    0   1.000   1.000   1.000
US_SSN               35      35    35    0    0   1.000   1.000   1.000
```

**Read the TP column, not the F1 column.** Regex scores the highest F1 — but only because it is graded on the 126 findings it is capable of attempting, ignoring the 98 `PERSON` and `LOCATION` values it cannot see. The hybrid is measured on all 226 and finds every one. Comparing F1 across detectors with different scopes compares the difficulty of the subset, not the quality of the engine.

Against the fair comparison — NLP alone, scored on the same entity set — the merge improves **both** precision (0.868 → 1.000) and recall (0.982 → 1.000). Those gains are traceable to specific rules:

| Row | Effect of the merge |
|---|---|
| `CREDIT_CARD` | Presidio finds 6 of 8; regex finds all 8, and authority keeps them → recall 0.750 → 1.000 |
| `PHONE_NUMBER` | Presidio contributes 6 false positives; regex authority drops them → precision 0.850 → 1.000 |
| `PERSON` | Presidio emits 27 spurious spans inside addresses; the longest-span rule discards them → precision 0.690 → 1.000 |

That `PERSON` row is the clearest argument for having a merge layer at all. **Neither piece fixes it alone.** Presidio still emits all 27 spurious spans even with the address recognizer installed — it does not reconcile its own overlapping opinions. What removes them is the combination: the recognizer supplies a full-address span, and the merge then treats a `PERSON` sitting inside one as a fragment of it.

### Measured against third-party data

```bash
python scripts/benchmark_external.py            # both regions, all detectors
python scripts/benchmark_external.py --detail   # plus the worst templates
```

The corpus above was written by the same person who wrote the detectors, so a
perfect score on it proves the code does what it was built to do and not much
more. `data/external/` holds two files from Microsoft's `presidio-research`
project, vendored verbatim with checksums: **209 sentence templates** and
**3,000 fabricated identities**. Neither was consulted while the detectors were
written, and nothing is ever tuned against them — the moment a pattern is
adjusted to raise a number measured here, this stops being a held-out test.

1,045 sentences, 1,428 labelled entities, 444 unlabelled distractors
(company names, job titles, URLs, IBANs — a hit on one of those is charged as
a false positive):

```
DETECTOR                   PRECISION    RECALL        F1    TP    FP    FN
Regex only                     1.000     1.000     1.000   225     0     0
Presidio NLP only              0.877     0.791     0.832  1121   157   297
Hybrid (regex + NLP)           0.927     0.816     0.868  1165    92   263
```

The regex row is graded on the 225 findings it can attempt and ignores the
1,203 names and places it cannot see, so its 1.000 is a statement about
difficulty, not quality — the same caveat as on the corpus table above.

Two things survive contact with somebody else's sentences:

- **The structured types hold at 1.000 across the board.** SSNs, card numbers,
  emails, phone numbers and IP addresses score exactly as they do on the
  corpus, because their formats are defined by external standards — a Luhn
  checksum and SSA issuance rules do not care who wrote the sentence around
  them.
- **The merge still earns its place.** Against the fair comparison, it takes
  `CREDIT_CARD` recall from 0.642 to 1.000 (regex authority reinstates the 34
  cards Presidio's confidence threshold dropped), `PHONE_NUMBER` precision from
  0.909 to 1.000, and `PERSON` precision from 0.836 to 0.893.

What does *not* survive is the perfect score. `PERSON` falls to 0.893/0.832 and
`LOCATION` to 0.933/0.728. The breakdown says exactly why:

| What it is looking at | Recall | Found |
|---|---|---|
| Complete US address (`123 Main St, Springfield, IL 62704`) | **1.000** | 160/160 |
| Card number, SSN, email, phone, IP | **1.000** | 225/225 |
| Country name | **1.000** | 80/80 |
| Full name in prose (`Contact Marika Szûts about…`) | 0.939 | 155/165 |
| Surname alone | 0.861 | 68/79 |
| Street line of a block address | 0.440 | 22/50 |
| City name alone | 0.679 | 91/134 |
| Bare ZIP code | 0.000 | 0/15 |
| Apartment or unit number (`Apt. 511`) | 0.000 | 0/35 |

**The pattern is structure.** Where a value carries its own evidence — a
checksum, a fixed layout, a comma-state-ZIP tail — detection is exact and
transfers unchanged to text nobody here wrote. Where the only evidence is
context, accuracy tracks how much context there is: a name in a sentence is
found 94% of the time, a surname on its own 86%, a ZIP code sitting alone on a
line never. A block mailing address is the hard case precisely because the line
breaks strip the structure out of it:

```
Marika Szûts
1481 Maud Street          <- found alone 44% of the time
Apt. 511                  <- never found
Wilmington                <- found 68% of the time
United States 19801
```

The same address on one line is found every time. Nothing about the words
changed; only the punctuation holding them together did.

False positives concentrate just as narrowly: **39 of 92 land on company
names**, which a person-name model has every reason to read as people —
`Wilson's Jewelers` and `White Hen Pantry` are not obviously organisations to a
statistical tagger. Bare ZIPs and apartment numbers are counted strictly here
even though the tool never claimed them; excluding them would raise `LOCATION`
recall from 0.728 to 0.803, and pretending they are out of scope after seeing the
result is how benchmarks get gamed.

#### The scope probe

The same 209 templates, filled from the **non-US** identities in the same file:

```
TYPE              PREC  RECALL   |  US rows, for comparison
LOCATION         0.855   0.382   |  0.933 / 0.728
PHONE_NUMBER     0.918   0.562   |  1.000 / 1.000
US_SSN           1.000   0.000   |  1.000 / 1.000
CREDIT_CARD      1.000   1.000   |  1.000 / 1.000
-------------------------------------------------------
ALL              0.817   0.639   |  0.927 / 0.816
```

This is not a defect, it is the documented scope arriving as a number. The SSN
pattern encodes US issuance rules, the address recognizer expects
`City, ST 12345`, the phone pattern expects a North American number — so
Cypriot postcodes and six-digit Greenlandic phone numbers are missed by design.
Credit cards and emails are unaffected, because those formats are
international to begin with. The row worth noticing is `PERSON` precision
falling from 0.893 to 0.757: the model is less certain about names it has seen
less often, and it resolves that uncertainty by guessing more.

### Testing the tests

Accuracy figures measure the detectors. Two other techniques measure whether
the *tests* would notice if the detectors broke.

**Property-based testing** (`tests/test_properties.py`, hypothesis). Instead of
asserting behaviour on chosen examples, each test states something that must
hold for every input of some shape and lets the library hunt for a
counterexample, shrinking any it finds to the smallest failing case. The
properties are the ones where a violation would be a real defect: offsets
always address the text, the merge never emits overlapping spans, a
structurally validated finding is never discarded by a weaker one (the Phase 6
bug, stated as an invariant rather than an anecdote), every Luhn-valid card is
found and no Luhn-invalid one is reported, and `repr()` on a finding never
prints the value it found.

It found two leaks in the redaction code on the first run:

```
redact(EMAIL_ADDRESS, "a@example.org")  ->  "a@example.org"
redact(US_SSN,        "12-34")          ->  "12-34"
```

A one-character mailbox has no tail to mask, and "keep the last four digits"
conceals nothing when there are only four. Neither is reachable from the corpus
— every fixture has a longer mailbox and a nine-digit SSN — and neither would
ever have been written as an example test, because the whole point is that
nobody thought of them. Both now fail closed.

**Mutation testing** (`setup.cfg`, mutmut). Breaks the code on purpose — flips
a comparison, deletes a guard, swaps an operator — and re-runs the tests
against each broken version. A mutant the tests still pass is a line nothing is
actually checking.

```
152 mutants of src/detectors/regex_detector.py
142 killed, 10 survived  ->  93.4%
```

The first run scored 69.7%, and the 46 survivors were a to-do list. Among them:
`continue` became `break` in the overlap loop, so every finding after the first
rejected one vanished, and the tests did not care. `<` became `<=` in the
overlap test, which would silently drop the second of any two adjacent values —
two comma-separated emails in a CSV row. `US_SSN: 0` became `1`, erasing the
tie-break that makes an SSN outrank a card number on an equal-length overlap.
None is a bug; all three are lines whose correctness nothing was checking,
which amounts to the same thing. Eighteen tests were added to close them, each
naming the mutant that motivated it.

The remaining ten are documented rather than chased, because they are
unkillable or not worth killing:

| Survivor | Why it stays |
|---|---|
| `total += value` → `-=` in Luhn | `(-t) % 10 == 0` exactly when `t % 10 == 0` — arithmetically equivalent |
| `value > 9` → `>= 9` in Luhn | Doubled digits are always even, so 9 never occurs |
| `CREDIT_CARD: 1` → `2` (and three more) | Shifts one priority value while preserving the ordering |
| `"LOCATION"` → a different literal | The branch falls through to a fallback that returns the same thing |
| `VERSION_CONTEXT_WINDOW = 24` → `25` | A tuning constant; a test pinning its exact value would make it untunable |
| Two `repr()` format literals | Cosmetic — the invariant that matters, that the value never appears, is a property test |

Scope is the honest part of this figure: it covers the regex detector, not the
Presidio one. Scoring the NLP layer this way would reload a 560MB language
model once per mutant. That half is covered by the corpus score, the external
benchmark, and mutations run by hand during development.

### Guarding against over-fitting

A custom pattern written against the corpus it is then scored on is the classic way to manufacture good numbers. The address recognizer is held to two checks that the corpus score cannot provide, both in the test suite:

- **300 addresses from a seed the pattern was never tuned against** — all matched in full. A change that raises the corpus score by narrowing onto the committed fixtures fails this test.
- **200 paragraphs of address-free prose** — zero false positives.

Plus seven hand-written real addresses (`1600 Pennsylvania Avenue NW, Washington, DC 20500`, `18 Rue St. Charles, St. Paul, MN 55102`) that cover format variation the generator never produces, and six adversarial near misses that must stay clean.

The honest limit: the 300-address check tests generalization across address *instances*, not across address *formats*. Those are still Faker's US layout. The hand-written cases cover format variation, but seven examples is seven examples.

### Two fixes that took the corpus to 1.000

**Version strings that look like addresses.** `10.2.14.3` is a valid IP *and* an ordinary software version, and nothing about the characters separates them — only the word in front does. A dotted quad sitting immediately after `build`, `version`, `firmware` or `release` is now suppressed.

The first attempt looked back 40 characters for any of those words, and a held-out case caught it: *"the build server at 10.1.2.3 is down"* lost a real address, because `build` described the server. Requiring the keyword to sit **immediately** before the number — nothing but whitespace or punctuation between — fixes it. In a version string the number follows the word directly; in prose it does not.

**Names the model could not see.** Two real misses, two different causes:

```
"To:      Jennifer Brown <...>"   the run of padding spaces breaks the
                                  tokenizer; with one space it is found
"Dear Fernando Proctor,"          the model tags the first mention of a
                                  name in a letter and not the second
```

Neither is a threshold problem — the entity scores *nothing*, so there is no confidence to raise. What both have is **position**: a name on a `To:` line or after `Dear` is a name because of where it sits. A recognizer for correspondence conventions finds them, with a stop-list so `Dear Hiring Manager` and `To: Facilities Desk` stay unflagged.

### Known limitations

**English-only**, **US-only addresses**, **three US phone formats** in the regex layer (the NLP layer covers more) — the scope probe above puts numbers on all three. **No `.doc`, `.pptx`, or archive recursion.** **OCR degrades on poor scans** — see above. **The UI has no authentication**; it is a local tool. Full register in the caveats section of the project notes.

**These numbers are tied to the pinned versions.** Presidio's accuracy comes from a spaCy model; upgrading `en_core_web_lg` changes which entities are found and how their spans are bounded.

### What these numbers do not mean

The phone patterns cover three formats because the corpus contains three. Real-world phone detection also faces country codes, extensions, and international formats. Recall of 1.000 there means "found everything in a corpus built from these formats", not "solved phone detection" — and the scope probe shows what that is worth: the same patterns recall 0.562 on non-US numbers.

The third-party figures are better evidence but still not a field measurement. The sentences are synthetic, the identities are fabricated, and the two files were chosen because they existed and were redistributable, not because they represent any particular organisation's documents. What they establish is narrower and worth stating exactly: **the detectors were not fitted to the text they are scored on.** Real documents bring scanning artefacts, inconsistent formatting, domain jargon and file types this tool does not open at all.

## Parsing

`src/parsers/` extracts text per format and dispatches on extension:

| Format | Extractor | Notes |
|---|---|---|
| `.txt` `.md` | direct read | Exact |
| `.csv` | `pandas`, flattened | Lossless, but reflowed |
| `.docx` | `python-docx`, paragraphs + tables | Exact |
| `.pdf` | `pdfplumber`, then OCR where there is no text layer | **Lossy** — blank lines disappear |
| `.xlsx` `.xlsm` | `openpyxl`, every sheet | Formula *results*, not formula text |
| `.eml` | stdlib `email` | Headers, body **and** text attachments |
| `.html` `.htm` | stdlib `html.parser` | Visible text; `<script>`/`<style>` ignored |
| `.json` | stdlib `json` | Flattened to `path.to.key: value` |
| `.png` `.jpg` `.tif` `.bmp` | OCR | No text layer exists at all |

Spreadsheets and email carry most of the bulk personal data in real shares, and an email hides it in three places at once — headers, body, and whatever is attached. Reading only the body would miss the recipient list entirely.

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

Detection accuracy was **unchanged** by the conversion — identical precision and recall before and after. That is the point. The corpus got harder to read; the offsets were re-derived correctly; the numbers held.

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

The corpus exercises all five bands — a contact-only bulletin (`LOW`), an address-only site note (`MEDIUM`) and a genuinely clean retention notice (`NONE`) sit alongside the severe files, so the banding logic is validated by real data and not by unit tests alone.

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

Every fixture is byte-identical run to run, binary formats included, and CI enforces it: a build regenerates the corpus and fails if `git diff` on `data/` is non-empty. If the generator and the committed fixtures ever drift apart, every accuracy figure here is measuring something no longer in the repository.

Getting there took more than setting the documents' metadata timestamps. A `.docx` is a ZIP, and `python-docx` stamps each *archive member* with the wall clock at save time — one level above `docProps/core.xml`, so the document properties were fixed while the file still changed on every run. The archive is now rewritten with frozen member timestamps. (An earlier version of this README claimed the binaries were already stable; that check had simply run twice within the same second.)

The generator refuses to write a corpus it cannot verify: it asserts every recorded span holds the value it claims, that no spans overlap, and that no planted value appears in the text more times than it was recorded.

### Redaction

Values appear in the answer key because scoring needs them and every one is fabricated. That is not a licence for the tool itself — detector and report output redacts matched values, showing type, position, and at most a partial value.

## License

MIT — see [LICENSE](LICENSE).
