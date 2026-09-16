# Sensitive Data Discovery Tool

Python based detection tool combining regex pattern matching and Microsoft Presidio's NLP engine to identify SSNs, credit card numbers, emails, phone numbers, and addresses across document sets, modeling data governance workflows used in e-discovery and compliance.

> **Status:** in progress. Scaffold (Phase 1) and the synthetic corpus with its ground-truth answer key (Phase 2) are complete; detection, parsing, scoring, CLI, and UI are still being built.

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
│   ├── detectors/        # regex + Presidio detection engines
│   ├── parsers/          # per-format text extraction
│   └── reporting/        # risk scoring and report building
├── scripts/
│   └── generate_test_data.py
├── tests/
├── app.py                # Streamlit entry point
├── main.py               # CLI entry point
├── requirements.txt
└── README.md
```

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
