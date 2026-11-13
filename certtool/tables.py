"""Parser for the ASCII tables printed by sapccm.

sapccm has no machine readable output format. Its tables look like this
(every column is padded to the widest cell plus two spaces)::

    CERTIFICATE CODE  NAME          ISSUER            EXPIRATION DATE
    abc123            my cert name  Let's Encrypt R3  2027-01-01T00:00Z

Header names only contain single spaces, columns are separated by at least
two spaces. Each column therefore starts exactly at the offset of its header,
which allows parsing cell values that contain spaces themselves.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

_HEADER_COLUMN = re.compile(r"\S+(?: \S+)*")


def parse_table(text: str, first_header: str) -> Optional[List[Dict[str, str]]]:
    """Parse the table whose header line starts with ``first_header``.

    Returns ``None`` when no such header is found (e.g. "No certificates
    found"), otherwise a list of rows (dict header -> stripped cell value).
    """
    lines = [line.rstrip("\r\n") for line in text.splitlines()]
    header_index = next(
        (i for i, line in enumerate(lines)
         if line.startswith(first_header + "  ") or line.rstrip() == first_header
         or first_header in [m.group(0) for m in _HEADER_COLUMN.finditer(line)]), None
    )
    if header_index is None:
        return None

    header_line = lines[header_index]
    columns = [(m.group(0), m.start()) for m in _HEADER_COLUMN.finditer(header_line)]
    rows: List[Dict[str, str]] = []
    for line in lines[header_index + 1:]:
        if not line.strip():
            # an empty line terminates the table
            if rows:
                break
            continue
        row = {}
        for idx, (name, start) in enumerate(columns):
            end = columns[idx + 1][1] if idx + 1 < len(columns) else None
            row[name] = line[start:end].strip() if end is not None else line[start:].strip()
        rows.append(row)
    return rows


def parse_details(text: str) -> Dict[str, str]:
    """Parse a PROPERTY/VALUE details table (e.g. ``endpoint show``)."""
    rows = parse_table(text, "PROPERTY") or []
    return {row.get("PROPERTY", ""): row.get("VALUE", "") for row in rows}
