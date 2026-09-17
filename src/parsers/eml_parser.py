"""Email extraction: headers, body, and the text of any attachments.

Email is the dominant artefact in e-discovery, and it hides PII in three
different places at once -- the headers, the body, and whatever is attached.
Reading only the body would miss the recipient list entirely.
"""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from pathlib import Path

#: Headers worth scanning. To, From and Cc are addresses and names by
#: definition; Subject routinely carries a case or account number.
SCANNED_HEADERS = ("From", "To", "Cc", "Bcc", "Reply-To", "Subject", "Date")


def extract(path: Path | str) -> str:
    """Return an .eml message as text.

    ``policy.default`` decodes RFC 2047 encoded-word headers, so a name
    written as ``=?utf-8?B?...?=`` on the wire is scanned as the name it
    actually is rather than as base64 noise.
    """
    with open(path, "rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    lines = [
        f"{header}: {message[header]}"
        for header in SCANNED_HEADERS
        if message[header]
    ]

    body = message.get_body(preferencelist=("plain", "html"))
    if body is not None:
        content = body.get_content()
        if body.get_content_subtype() == "html":
            from src.parsers.html_parser import strip_tags

            content = strip_tags(content)
        lines.append("")
        lines.append(content)

    # Attachments are scanned as text where they are text. Binary attachments
    # are named but not decoded -- routing them back through the dispatcher
    # would mean writing them to disk, which this parser has no business doing.
    for part in message.iter_attachments():
        filename = part.get_filename() or "(unnamed attachment)"
        lines.append(f"\n[attachment: {filename}]")
        if part.get_content_maintype() == "text":
            try:
                lines.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                pass

    return "\n".join(lines)
