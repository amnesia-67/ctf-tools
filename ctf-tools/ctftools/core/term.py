"""Minimal ANSI colouring and table rendering.

Colour is disabled automatically when stdout is not a terminal, when
``NO_COLOR`` is set, or when a tool is run with ``--no-color``.
"""

from __future__ import annotations

import os
import sys

_FORCE: bool | None = None

_CODES = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "grey": "\x1b[90m",
}


def set_color(enabled: bool | None) -> None:
    """Force colour on (True), off (False) or back to auto-detect (None)."""
    global _FORCE
    _FORCE = enabled


def color_enabled() -> bool:
    if _FORCE is not None:
        return _FORCE
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def c(text: str, *styles: str) -> str:
    """Wrap *text* in the given styles, if colour is enabled."""
    if not color_enabled() or not styles:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}"


def visible_len(text: str) -> int:
    """Length of *text* ignoring ANSI escapes."""
    out, i = 0, 0
    while i < len(text):
        if text[i] == "\x1b":
            end = text.find("m", i)
            if end == -1:
                break
            i = end + 1
            continue
        out += 1
        i += 1
    return out


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - visible_len(text))


def table(rows, headers=None, indent: int = 2) -> str:
    """Render *rows* (a sequence of sequences) as an aligned plain table."""
    rows = [[str(cell) for cell in row] for row in rows]
    if not rows and not headers:
        return ""
    ncols = max(len(r) for r in (rows or [[]])) if rows else len(headers or [])
    if headers:
        ncols = max(ncols, len(headers))
    widths = [0] * ncols
    body = list(rows)
    if headers:
        body = [list(headers)] + body
    for row in body:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], visible_len(cell))
    lines = []
    sp = " " * indent
    if headers:
        head = "  ".join(pad(c(h, "bold"), widths[i]) for i, h in enumerate(headers))
        lines.append(sp + head.rstrip())
        lines.append(sp + c("  ".join("-" * w for w in widths[: len(headers)]), "grey"))
    for row in rows:
        lines.append(sp + "  ".join(pad(cell, widths[i]) for i, cell in enumerate(row)).rstrip())
    return "\n".join(lines)


def heading(text: str) -> str:
    return c(f"\n{text}", "bold", "cyan")


def good(text: str) -> str:
    return c(text, "green")


def bad(text: str) -> str:
    return c(text, "red")


def warn(text: str) -> str:
    return c(text, "yellow")


def dim(text: str) -> str:
    return c(text, "grey")
