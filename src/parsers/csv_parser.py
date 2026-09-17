"""CSV extraction: flatten rows into scannable text.

A detector works on prose, not on cells, so the table has to be linearised.
Doing that through pandas rather than by reading the raw file handles the parts
of the CSV format that are easy to get wrong by hand -- quoted fields
containing commas, embedded newlines, escaped quotes.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

#: Between cells. A comma and a space reads like an ordinary list, which keeps
#: the text natural enough for the NLP layer to use context around a name.
CELL_SEPARATOR = ", "


def extract(path: Path | str) -> str:
    """Return every cell of the CSV as text, one row per line.

    ``dtype=str`` and ``keep_default_na=False`` are what make this lossless,
    and both are load-bearing. Left to infer types, pandas reads a column of
    ZIP codes as integers and turns ``03592`` into ``3592``, and reads an empty
    cell as the float ``nan``, so the text handed to the detector would no
    longer be the text in the file. Type inference is a convenience for
    analysis and a corruption bug for scanning.
    """
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)

    lines = [CELL_SEPARATOR.join(str(column) for column in frame.columns)]
    lines.extend(
        CELL_SEPARATOR.join(str(cell) for cell in row)
        for row in frame.itertuples(index=False, name=None)
    )
    return "\n".join(lines)
