# Third-party evaluation data

These two files were **not produced by this project**. That is the entire
reason they are here.

Every accuracy figure measured against `data/raw` is this project grading its
own homework: the sentences were written by the same person who wrote the
detectors, so a pattern and the text it is tested on share an author. A perfect
score on that corpus proves the code does what it was built to do. It does not
prove the design survives contact with text nobody here chose.

`scripts/benchmark_external.py` renders these files into sentences and scores
the detectors on them. Nothing in this directory was consulted while the
detectors were written, and **nothing may be tuned against it** — the moment a
pattern is adjusted to raise a number measured here, this stops being a
held-out test and becomes another corpus we grade ourselves.

## Files

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `presidio_templates.txt` | 18,066 | `f8b04ff8c5c24d17fcac2e666767f6ba80841b69ee2ea3c1cfe089a676a766ef` |
| `fake_name_generator_3000.csv` | 817,366 | `d1337ba8d085612ca989cc64cc64bb8b44ab5121e9d94de2b534a49e921c8170` |

Both are byte-for-byte as shipped. The checksums are recorded so that claim can
be checked rather than taken on trust, and `tests/test_benchmark.py` asserts
them on every run — if either file is edited, the suite fails. Editing the
inputs to a held-out benchmark is exactly the failure mode the checksums exist
to catch.

### `presidio_templates.txt`

209 sentence templates with `{{placeholder}}` slots, from Microsoft's
[presidio-research](https://github.com/microsoft/presidio-research) project
(`presidio_evaluator/data_generator/raw_data/templates.txt`, package version
0.3.2). They are the *contexts*: customer-service complaints, block-formatted
mailing addresses, quoted email replies, a SQL injection payload with an IP
address in it. Several are deliberately awkward — one is a mailing address
prefixed with `>` quote markers, another with `???` — and those are the ones
the detectors do worst on, which is the kind of thing a self-written corpus
never surfaces because nobody writes a test case they expect to fail.

### `fake_name_generator_3000.csv`

3,000 fabricated identities, shipped in the same package, originally from
[FakeNameGenerator](https://www.fakenamegenerator.com/). Names, street
addresses, cities, postcodes, phone numbers, email addresses and national IDs
all come from this file.

The names matter more than they look. The rows are drawn from many locales, so
even the 103 US-resident rows carry surnames like `Szûts`, `Gyarmaty` and
`Waltari` — names an English NER model has far less reason to recognise than
the Anglo-leaning names Faker's `en_US` locale produces for `data/raw`. That
gap is visible in the results and is a real property of the tool, not an
artefact of the test.

No value in this file belongs to a real person. It is a fake-identity
generator's output, which is why it can be redistributed and committed here at
all — the project's rule against ever handling real PII applies to the
benchmark exactly as it applies to the corpus.

Two identifier types could **not** be taken from this file and are minted by
Faker instead, which bounds the claim this benchmark can make:

* `CCNumber` was saved through a spreadsheet and is stored in scientific
  notation (`4.55689E+15`), so the real digits are gone and no Luhn check could
  ever pass.
* There is no IP address column at all.

Everything else a sentence contains — the context, the name, the address, the
phone, the email, the SSN — came from outside this project.

## Licence

`presidio-research` is MIT licensed; the licence text is in
`LICENSE.presidio-research`. The package itself is deliberately **not** a
dependency: it requires `transformers`, `scikit-learn` and `plotly` at
unpinned lower bounds, which would pull several hundred megabytes into the
environment and override every pin in `requirements.txt` — for the sake of two
static data files. Vendoring them verbatim, with checksums, gets the same data
with none of that.
