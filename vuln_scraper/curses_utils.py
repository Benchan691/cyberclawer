from __future__ import annotations

import curses
from typing import Any


def _sanitize_curses_text(text: str) -> str:
    return "".join(char if char in "\t" or ord(char) >= 32 else " " for char in str(text))


def safe_addnstr(
    stdscr: Any,
    row: int,
    col: int,
    text: str,
    attr: int = curses.A_NORMAL,
    *,
    width: int | None = None,
) -> None:
    height, term_width = stdscr.getmaxyx()
    if width is None:
        width = term_width
    if row < 0 or row >= height or col < 0 or col >= width:
        return
    max_chars = width - col - 1
    if max_chars <= 0:
        return
    try:
        stdscr.addnstr(row, col, _sanitize_curses_text(text), max_chars, attr)
    except curses.error:
        return
