from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

from bs4 import BeautifulSoup, Tag


WHITESPACE_RE = re.compile(r"\s+")


def extract_raw_tables(detail_content: Any) -> list[list[list[str]]]:
    """Extract detail-response HTML tables as rectangular text grids."""
    tables: list[list[list[str]]] = []
    for html in _html_fragments(detail_content, seen=set()):
        parsed = BeautifulSoup(html, "lxml")
        tables.extend(_table_grid(table) for table in parsed.find_all("table"))
    return tables


def _html_fragments(value: Any, *, seen: set[int]) -> Iterator[str]:
    if isinstance(value, str):
        if "<table" in value.casefold():
            yield value
        return

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for item in value.values():
            yield from _html_fragments(item, seen=seen)
        return

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for item in value:
            yield from _html_fragments(item, seen=seen)


def _table_grid(table: Tag) -> list[list[str]]:
    row_nodes = [
        row
        for row in table.find_all("tr")
        if row.find_parent("table") is table
    ]
    grid: list[list[str]] = []
    active_spans: dict[int, tuple[str, int]] = {}

    for row_index, row_node in enumerate(row_nodes):
        values_by_column: dict[int, str] = {}
        occupied: set[int] = set()
        next_spans: dict[int, tuple[str, int]] = {}

        for column, (value, rows_left) in active_spans.items():
            values_by_column[column] = value
            occupied.add(column)
            if rows_left > 1:
                next_spans[column] = (value, rows_left - 1)

        column = 0
        cells = [
            cell
            for cell in row_node.find_all(["th", "td"])
            if cell.find_parent("tr") is row_node and cell.find_parent("table") is table
        ]
        for cell in cells:
            colspan = _positive_span(cell.get("colspan"))
            while any(column + offset in occupied for offset in range(colspan)):
                column += 1

            value = _cell_text(cell)
            rowspan = _rowspan(cell.get("rowspan"), rows_remaining=len(row_nodes) - row_index)
            for offset in range(colspan):
                target = column + offset
                values_by_column[target] = value
                occupied.add(target)
                if rowspan > 1:
                    next_spans[target] = (value, rowspan - 1)
            column += colspan

        width = max(occupied, default=-1) + 1
        grid.append([values_by_column.get(index, "") for index in range(width)])
        active_spans = next_spans

    width = max((len(row) for row in grid), default=0)
    return [row + [""] * (width - len(row)) for row in grid]


def _cell_text(cell: Tag) -> str:
    return WHITESPACE_RE.sub(" ", cell.get_text(" ", strip=True)).strip()


def _positive_span(value: Any) -> int:
    try:
        return max(1, int(str(value)))
    except (TypeError, ValueError):
        return 1


def _rowspan(value: Any, *, rows_remaining: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return 1
    if parsed == 0:
        return max(1, rows_remaining)
    return max(1, parsed)
