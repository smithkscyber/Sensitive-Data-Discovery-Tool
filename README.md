# Sensitive Data Discovery Tool

Python based detection tool combining regex pattern matching and Microsoft Presidio's NLP engine to identify SSNs, credit card numbers, emails, phone numbers, and addresses across document sets, modeling data governance workflows used in e-discovery and compliance.

> **Status:** in progress. Project scaffold and environment are set up (Phase 1); detection, parsing, scoring, CLI, and UI are still being built.

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
│   └── raw/              # synthetic test files (no real PII, ever)
├── src/
│   ├── detectors/        # regex + Presidio detection engines
│   ├── parsers/          # per-format text extraction
│   └── reporting/        # risk scoring and report building
├── tests/
├── app.py                # Streamlit entry point
├── main.py               # CLI entry point
├── requirements.txt
└── README.md
```

## A note on test data

All test data in `data/raw/` is synthetic, generated with [Faker](https://faker.readthedocs.io/). No real personal data is used in this repository — not in commits, not in test fixtures, not in examples. Tool output redacts matched values (type, position, and a partial value only) rather than echoing them back.

## License

MIT — see [LICENSE](LICENSE).
