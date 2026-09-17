# Edge-case fixtures

Files here are **deliberately unreadable**. They are kept out of `data/raw/`
because a scan of the main corpus should come back complete — these would make
it exit non-zero, which is correct behaviour but a poor demonstration.

| File | What it proves |
|---|---|
| `password_protected_personnel_record.pdf` | A well-formed PDF full of PII that the tool cannot open. It must be reported as **failed** with the reason named — never as clean. |

The distinction matters more here than anywhere else in the project. A file the
scanner could not read is not a clean file, and a clean result is exactly what
nobody investigates.
