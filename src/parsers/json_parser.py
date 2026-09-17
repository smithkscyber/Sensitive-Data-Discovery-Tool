"""JSON extraction: keys and values flattened to lines.

API exports and log dumps arrive as JSON, and the structure matters to a
detector: ``"ssn": "623-98-0035"`` gives the NLP layer the context word that
raises its confidence, so the key is worth keeping next to its value.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _flatten(node: Any, prefix: str, lines: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _flatten(value, f"{prefix}.{key}" if prefix else str(key), lines)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _flatten(value, f"{prefix}[{index}]", lines)
    elif node is not None:
        lines.append(f"{prefix}: {node}" if prefix else str(node))


def extract(path: Path | str) -> str:
    """Return one ``path.to.key: value`` line per leaf.

    Malformed JSON raises rather than being salvaged. A partially parsed file
    would be scanned partially and reported as though it were scanned whole.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    lines: list[str] = []
    _flatten(data, "", lines)
    return "\n".join(lines)
