"""XLSX extraction: every cell of every sheet, flattened to text.

Spreadsheets are where bulk personal data actually lives -- an exported
contact list or payroll extract holds more records than any memo, which makes
this one of the higher-value formats for the workflows this project models.
"""

from __future__ import annotations

from pathlib import Path

import openpyxl

#: Between cells on a row, matching the CSV parser so both tabular formats
#: present the same shape to the detectors.
CELL_SEPARATOR = ", "


def extract(path: Path | str) -> str:
    """Return every populated cell, one row per line, sheets in order.

    ``read_only`` streams rows instead of building the whole workbook in
    memory, and ``data_only`` takes the cached result of a formula rather than
    the formula text -- a cell reading ``=VLOOKUP(...)`` tells a detector
    nothing, while its computed value may be a Social Security number.
    """
    workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        lines: list[str] = []
        for sheet in workbook.worksheets:
            if len(workbook.worksheets) > 1:
                lines.append(f"[{sheet.title}]")
            for row in sheet.iter_rows(values_only=True):
                cells = [str(value) for value in row if value is not None]
                if cells:
                    lines.append(CELL_SEPARATOR.join(cells))
        return "\n".join(lines)
    finally:
        workbook.close()
