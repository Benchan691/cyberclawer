from __future__ import annotations

import argparse
import curses
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_MONGO_CONFIG_FILE,
    ScraperSettings,
    mongo_collections_from_config,
    mongo_filtered_output_file,
    provider_for_mongo_collection,
    resolve_mongo_export_path,
)
from .mongo import collection_from_settings
from .mongo_filter import (
    MongoFilterState,
    available_categorical_fields,
    distinct_values,
    export_filtered_results,
    fetch_filtered_page,
    filter_fields_for_provider,
)


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


def run_mongo_filter_tui(settings: ScraperSettings) -> None:
    if settings.mongo_collection:
        collection_name = settings.normalized().mongo_collection
        provider_key = provider_for_mongo_collection(collection_name or "", settings.mongo_config_file)
    else:
        provider_key, collection_name = curses.wrapper(
            CollectionPickerTUI(
                tuple(mongo_collections_from_config(settings.mongo_config_file).items())
            ).run
        )

    normalized = replace(settings, mongo_collection=collection_name).normalized()
    client, collection = collection_from_settings(normalized)
    try:
        base_categorical_fields, text_fields, dynamic_path = filter_fields_for_provider(provider_key or "")
        categorical_fields = available_categorical_fields(
            collection,
            base_fields=base_categorical_fields,
            dynamic_object_path=dynamic_path,
        )
        app = MongoFilterTUI(
            collection,
            settings=normalized,
            provider_key=provider_key,
            collection_name=collection_name or "",
            categorical_fields=categorical_fields,
            text_fields=text_fields,
            export_path=mongo_filtered_output_file(normalized.data_dir, collection_name or ""),
        )
        curses.wrapper(app.run)
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()


class CollectionPickerTUI:
    def __init__(self, choices: tuple[tuple[str, str], ...]) -> None:
        self.choices = choices
        self.index = 0

    def run(self, stdscr: Any) -> tuple[str, str]:
        curses.curs_set(0)
        stdscr.keypad(True)
        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            safe_addnstr(
                stdscr,
                0,
                0,
                "Pick MongoDB collection (Enter, q quit)",
                curses.A_BOLD,
                width=width,
            )
            for row, (provider_key, collection_name) in enumerate(self.choices, start=2):
                if row >= height:
                    break
                marker = ">" if row - 2 == self.index else " "
                attr = curses.A_REVERSE if marker == ">" else curses.A_NORMAL
                label = f"{marker} {provider_key} / {collection_name}"
                safe_addnstr(stdscr, row, 0, label, attr, width=width)
            stdscr.refresh()

            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                raise SystemExit(0)
            if key in (curses.KEY_UP, ord("k")):
                self.index = max(0, self.index - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.index = min(len(self.choices) - 1, self.index + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return self.choices[self.index]


class MongoFilterTUI:
    def __init__(
        self,
        collection: Any,
        *,
        settings: ScraperSettings,
        provider_key: str | None,
        collection_name: str,
        categorical_fields: tuple[str, ...],
        text_fields: tuple[str, ...],
        export_path: Path,
    ) -> None:
        self.collection = collection
        self.settings = settings
        self.provider_key = provider_key
        self.collection_name = collection_name
        self.categorical_fields = categorical_fields
        self.text_fields = text_fields
        self.export_path = export_path
        self.fields = _dedupe_fields((*categorical_fields, *text_fields))
        self.state = MongoFilterState()
        self.mode = "fields"
        self.field_index = 0
        self.value_index = 0
        self.result_index = 0
        self.read_scroll = 0
        self.current_values: list[str] = []
        self.message = ""
        self.result_total = 0
        self.results: list[dict[str, Any]] = []
        self.read_lines: list[str] = []

    def run(self, stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        while True:
            self._render(stdscr)
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                return
            if self.mode == "fields":
                self._handle_fields_key(stdscr, key)
            elif self.mode == "values":
                self._handle_values_key(key)
            elif self.mode == "results":
                self._handle_results_key(key)
            else:
                self._handle_read_key(key)

    def _handle_fields_key(self, stdscr: Any, key: int) -> None:
        if key in (curses.KEY_UP, ord("k")):
            self.field_index = max(0, self.field_index - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.field_index = min(len(self.fields) - 1, self.field_index + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            self._open_selected_field(stdscr)
        elif key in (ord("c"), ord("C")):
            self.state.clear_field(self.fields[self.field_index])
            self.message = f"Cleared {self.fields[self.field_index]}"
        elif key in (ord("r"), ord("R")):
            self._load_results()
            self.result_index = 0
            self.mode = "results"
        elif key in (ord("e"), ord("E")):
            self._export_results(stdscr)

    def _handle_values_key(self, key: int) -> None:
        field_name = self.fields[self.field_index]
        if key in (curses.KEY_UP, ord("k")):
            self.value_index = max(0, self.value_index - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.value_index = min(len(self.current_values) - 1, self.value_index + 1)
        elif key == ord(" "):
            if self.current_values:
                self.state.toggle_value(field_name, self.current_values[self.value_index])
        elif key in (27, curses.KEY_BACKSPACE, 127, curses.KEY_ENTER, 10, 13):
            self.mode = "fields"

    def _handle_results_key(self, key: int) -> None:
        max_page = max(0, (self.result_total - 1) // self.state.page_size)
        if key in (curses.KEY_UP, ord("k")):
            self.result_index = max(0, self.result_index - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.result_index = min(max(0, len(self.results) - 1), self.result_index + 1)
        elif key in (ord("n"), curses.KEY_RIGHT):
            self.state.page = min(max_page, self.state.page + 1)
            self._load_results()
            self.result_index = 0
        elif key in (ord("p"), curses.KEY_LEFT):
            self.state.page = max(0, self.state.page - 1)
            self._load_results()
            self.result_index = 0
        elif key in (curses.KEY_ENTER, 10, 13):
            self._open_selected_result()
        elif key in (ord("e"), ord("E")):
            self._export_results(stdscr)
        elif key in (ord("b"), 27, curses.KEY_BACKSPACE, 127):
            self.mode = "fields"

    def _handle_read_key(self, key: int) -> None:
        if key in (curses.KEY_UP, ord("k")):
            self.read_scroll = max(0, self.read_scroll - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.read_scroll = min(max(0, len(self.read_lines) - 1), self.read_scroll + 1)
        elif key in (ord("b"), 27, curses.KEY_BACKSPACE, 127):
            self.mode = "results"

    def _open_selected_result(self) -> None:
        if not self.results:
            return
        record = self.results[self.result_index]
        self.read_lines = json.dumps(record, ensure_ascii=False, indent=2).splitlines()
        self.read_scroll = 0
        self.mode = "read"

    def _export_results(self, stdscr: Any) -> None:
        output_path = self._prompt_export_path(stdscr)
        if output_path is None:
            self.message = "Export cancelled"
            return

        payload = export_filtered_results(
            self.collection,
            self.state,
            output_path=output_path,
            mongo_uri=self.settings.mongo_uri or "",
            mongo_database=self.settings.mongo_database or "",
            mongo_collection=self.settings.mongo_collection or "",
        )
        self.export_path = output_path
        self.message = f"Exported {payload['result_count']} records to {output_path}"

    def _prompt_export_path(self, stdscr: Any) -> Path | None:
        default_name = self.export_path.name
        while True:
            name = self._prompt(stdscr, "Export JSON filename", default_name)
            output_path = resolve_mongo_export_path(
                self.settings.data_dir,
                name,
                default_name=default_name,
            )
            if not output_path.exists():
                return output_path

            action = self._prompt_export_conflict(stdscr, output_path)
            if action == "replace":
                return output_path
            if action == "cancel":
                return None

    def _prompt_export_conflict(self, stdscr: Any, output_path: Path) -> str:
        height, width = stdscr.getmaxyx()
        message = f"{output_path.name} exists in data/. r replace, n rename, esc cancel"
        self._write(stdscr, height - 1, 0, " " * max(0, width - 1))
        self._write(stdscr, height - 1, 0, message, curses.A_BOLD, width)
        stdscr.refresh()
        while True:
            key = stdscr.getch()
            if key in (ord("r"), ord("R")):
                return "replace"
            if key in (ord("n"), ord("N")):
                return "rename"
            if key == 27:
                return "cancel"

    def _open_selected_field(self, stdscr: Any) -> None:
        field_name = self.fields[self.field_index]
        if field_name in self.categorical_fields:
            self.current_values = distinct_values(self.collection, field_name)
            self.value_index = 0
            self.mode = "values"
            self.message = f"{len(self.current_values)} values for {field_name}"
            return

        current = self.state.text_filters.get(field_name, "")
        value = self._prompt(stdscr, f"{field_name} contains", current)
        self.state.set_text_filter(field_name, value)
        self.message = f"Set text filter for {field_name}" if value else f"Cleared {field_name}"

    def _load_results(self) -> None:
        self.result_total, self.results = fetch_filtered_page(self.collection, self.state)
        self.message = f"{self.result_total} matching records"

    def _render(self, stdscr: Any) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        title = f"MongoDB Filter: {self.provider_key or '?'} / {self.collection_name}"
        self._write(stdscr, 0, 0, title, curses.A_BOLD)
        self._write(stdscr, 1, 0, "q quit | enter open | c clear | r results | e export")
        self._write(stdscr, 2, 0, self.message[: max(0, width - 1)])
        if self.mode == "fields":
            self._render_fields(stdscr, height, width)
        elif self.mode == "values":
            self._render_values(stdscr, height, width)
        elif self.mode == "results":
            self._render_results(stdscr, height, width)
        else:
            self._render_read(stdscr, height, width)
        stdscr.refresh()

    def _render_fields(self, stdscr: Any, height: int, width: int) -> None:
        start = max(0, self.field_index - max(0, height - 8))
        for row, field_name in enumerate(self.fields[start:], start=4):
            if row >= height:
                break
            selected = self._field_summary(field_name)
            marker = ">" if start + row - 4 == self.field_index else " "
            attr = curses.A_REVERSE if marker == ">" else curses.A_NORMAL
            self._write(stdscr, row, 0, f"{marker} {field_name} {selected}", attr, width)

    def _render_values(self, stdscr: Any, height: int, width: int) -> None:
        field_name = self.fields[self.field_index]
        self._write(stdscr, 3, 0, f"{field_name}: space toggles, enter/back returns")
        selected = self.state.selected_values.get(field_name, set())
        start = max(0, self.value_index - max(0, height - 8))
        for row, value in enumerate(self.current_values[start:], start=5):
            if row >= height:
                break
            absolute_index = start + row - 5
            marker = ">" if absolute_index == self.value_index else " "
            check = "[x]" if value in selected else "[ ]"
            attr = curses.A_REVERSE if marker == ">" else curses.A_NORMAL
            self._write(stdscr, row, 0, f"{marker} {check} {value}", attr, width)

    def _render_results(self, stdscr: Any, height: int, width: int) -> None:
        page = self.state.page + 1
        max_page = max(1, (self.result_total + self.state.page_size - 1) // self.state.page_size)
        self._write(
            stdscr,
            3,
            0,
            f"Results page {page}/{max_page}; j/k select, enter read, n/p page, e export, b back",
        )
        for row, record in enumerate(self.results, start=5):
            if row >= height:
                break
            label = " | ".join(
                str(record.get(key) or "")
                for key in ("type", "code", "status", "title")
            )
            absolute_index = row - 5
            marker = ">" if absolute_index == self.result_index else " "
            attr = curses.A_REVERSE if marker == ">" else curses.A_NORMAL
            self._write(stdscr, row, 0, f"{marker} {label}", attr, width)

    def _render_read(self, stdscr: Any, height: int, width: int) -> None:
        self._write(stdscr, 3, 0, "Record detail; j/k scroll, b back")
        start = max(0, self.read_scroll - max(0, height - 8))
        for row, line in enumerate(self.read_lines[start:], start=5):
            if row >= height:
                break
            absolute_index = start + row - 5
            attr = curses.A_REVERSE if absolute_index == self.read_scroll else curses.A_NORMAL
            self._write(stdscr, row, 0, line, attr, width)

    def _field_summary(self, field_name: str) -> str:
        if field_name in self.state.selected_values:
            count = len(self.state.selected_values[field_name])
            return f"({count} checked)"
        if field_name in self.state.text_filters:
            return f"({self.state.text_filters[field_name]!r})"
        return ""

    def _prompt(self, stdscr: Any, label: str, default: str) -> str:
        height, width = stdscr.getmaxyx()
        prompt = f"{label} [{default}]: "
        self._write(stdscr, height - 1, 0, " " * max(0, width - 1))
        self._write(stdscr, height - 1, 0, prompt, curses.A_BOLD, width)
        curses.curs_set(1)
        curses.echo()
        try:
            raw = stdscr.getstr(height - 1, min(len(prompt), width - 1), max(1, width - len(prompt) - 1))
        finally:
            curses.noecho()
            curses.curs_set(0)
        value = raw.decode("utf-8", errors="ignore").strip()
        return value or default

    def _write(
        self,
        stdscr: Any,
        row: int,
        col: int,
        text: str,
        attr: int = curses.A_NORMAL,
        width: int | None = None,
    ) -> None:
        safe_addnstr(stdscr, row, col, text, attr, width=width)


def _dedupe_fields(fields: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    unique: list[str] = []
    for field_name in fields:
        if field_name in seen:
            continue
        seen.add(field_name)
        unique.append(field_name)
    return tuple(unique)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Filter stored MongoDB vulnerability records.")
    parser.add_argument("--mongo-uri", help="MongoDB URI. Overrides env vars and mongodb.toml.")
    parser.add_argument("--mongo-db", help="MongoDB database. Overrides env vars and mongodb.toml.")
    parser.add_argument(
        "--mongo-collection",
        help="MongoDB collection. Skips the collection picker.",
    )
    parser.add_argument(
        "--mongo-config",
        type=Path,
        default=DEFAULT_MONGO_CONFIG_FILE,
        help=f"MongoDB config file. Default: {DEFAULT_MONGO_CONFIG_FILE}",
    )
    args = parser.parse_args(argv)
    settings = ScraperSettings(
        mongo_enabled=True,
        mongo_uri=args.mongo_uri,
        mongo_database=args.mongo_db,
        mongo_collection=args.mongo_collection,
        mongo_config_file=args.mongo_config,
    )
    run_mongo_filter_tui(settings)
