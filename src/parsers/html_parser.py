"""HTML extraction: visible text, without the markup.

Exported mail, saved web pages and report templates all arrive as HTML, and
the tags would otherwise be scanned as content -- a detector reading
``<a href="mailto:...">`` sees the address twice.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

#: Elements whose content is never shown to a reader. Their text is code, not
#: prose, and scanning it produces findings nobody can act on.
INVISIBLE = {"script", "style", "head", "meta", "noscript"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._suppressed = 0

    def handle_starttag(self, tag, attrs):
        if tag in INVISIBLE:
            self._suppressed += 1

    def handle_endtag(self, tag):
        if tag in INVISIBLE and self._suppressed:
            self._suppressed -= 1
        elif tag in ("p", "div", "br", "tr", "li", "h1", "h2", "h3"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._suppressed:
            self.parts.append(data)


def strip_tags(markup: str) -> str:
    """Return the visible text of an HTML fragment."""
    extractor = _TextExtractor()
    extractor.feed(markup)
    extractor.close()
    text = "".join(extractor.parts)
    # Collapse the blank-line pile-up that block-level tags leave behind,
    # without touching intentional single breaks.
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def extract(path: Path | str) -> str:
    return strip_tags(Path(path).read_text(encoding="utf-8", errors="replace"))
