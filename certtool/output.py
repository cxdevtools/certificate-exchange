"""Console rendering: tables, headings, key/value blocks and colors (stdlib only).

* Box drawing characters are used when stdout can encode them, ASCII otherwise.
* Colors are only emitted for interactive terminals and can be disabled with NO_COLOR
  (https://no-color.org) or TERM=dumb.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, List, Optional, Sequence, Tuple, Union

# A cell is plain text or (text, color). Text may contain line breaks.
Cell = Union[str, Tuple[str, Optional[str]]]

_COLORS = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}

_UNICODE = dict(tl="┌", tm="┬", tr="┐", ml="├", mm="┼", mr="┤", bl="└", bm="┴", br="┘", h="─", v="│")
_ASCII = dict(tl="+", tm="+", tr="+", ml="+", mm="+", mr="+", bl="+", bm="+", br="+", h="-", v="|")


def _stream():
    return sys.stdout


def use_color() -> bool:
    stream = _stream()
    return (hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ
            and os.environ.get("TERM") != "dumb")


def use_unicode() -> bool:
    encoding = (getattr(_stream(), "encoding", None) or "").lower()
    return "utf" in encoding


def style(text: str, color: Optional[str]) -> str:
    if not color or not use_color():
        return text
    codes = ";".join(_COLORS[c] for c in color.split("+") if c in _COLORS)
    return f"\x1b[{codes}m{text}\x1b[0m" if codes else text


def heading(text: str) -> None:
    print()
    print(style(text, "bold"))


def key_values(pairs: Sequence[Tuple[str, str]], indent: int = 2) -> None:
    width = max((len(k) for k, _ in pairs), default=0)
    for key, value in pairs:
        print(" " * indent + style(key.ljust(width), "dim") + "  " + value)


def _split(cell: Cell) -> Tuple[List[str], Optional[str]]:
    text, color = (cell if isinstance(cell, tuple) else (cell, None))
    return (str(text) if text is not None else "").split("\n"), color


def table(headers: Sequence[str], rows: Iterable[Sequence[Cell]], indent: int = 2) -> None:
    """Print a bordered table. Rows may contain multi-line and colored cells."""
    box = _UNICODE if use_unicode() else _ASCII
    prepared = [[_split(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in prepared:
        for i, (lines, _) in enumerate(row):
            widths[i] = max(widths[i], *(len(line) for line in lines))

    pad = " " * indent

    def border(left: str, mid: str, right: str) -> str:
        return pad + left + mid.join(box["h"] * (w + 2) for w in widths) + right

    def line(cells: Sequence[Tuple[str, Optional[str]]]) -> str:
        parts = [" " + style(text.ljust(widths[i]), color) + " " for i, (text, color) in enumerate(cells)]
        return pad + box["v"] + box["v"].join(parts) + box["v"]

    print(border(box["tl"], box["tm"], box["tr"]))
    print(line([(h, "bold") for h in headers]))
    print(border(box["ml"], box["mm"], box["mr"]))
    if not prepared:
        print(line([("(none)", "dim")] + [("", None)] * (len(headers) - 1)))
    for row in prepared:
        height = max(len(lines) for lines, _ in row)
        for n in range(height):
            print(line([(lines[n] if n < len(lines) else "", color) for lines, color in row]))
    print(border(box["bl"], box["bm"], box["br"]))


def problems(entries: Sequence[Tuple[str, str]]) -> None:
    """Print detailed error messages collected while building a table."""
    if not entries:
        return
    heading("Details")
    for subject, message in entries:
        first, *rest = message.strip().splitlines() or [""]
        print(f"  {style('!', 'red')} {subject}: {first}")
        for extra in rest:
            print(f"      {extra.strip()}")


def summary(text: str, ok: bool = True) -> None:
    print()
    print(style(text, "green" if ok else "red"))
