from __future__ import annotations

import asyncio
import curses
import logging
from pathlib import Path
from typing import Any

from .config import MAX_RESULT_LIMIT, default_scrape_settings, error_log_path_for_settings
from .error_log import log_uncaught_provider_error
from .filters import validate_limit
from .scrapers import get_provider, provider_keys
from .runner import ScraperRunner
from .tui import safe_addnstr

logger = logging.getLogger(__name__)


def run_scrape_tui() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    curses.wrapper(ScrapeTUI().run)


class ScrapeTUI:
    def __init__(self) -> None:
        self.providers = provider_keys()
        self.provider_index = 0
        self.mode = "provider"
        self.limit_text = str(MAX_RESULT_LIMIT)
        self.message = ""
        self.result_lines: list[str] = []

    def run(self, stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        while True:
            self._render(stdscr)
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")) and self.mode != "running":
                return
            if self.mode == "provider":
                self._handle_provider_key(key)
            elif self.mode == "amount":
                self._handle_amount_key(stdscr, key)
            elif self.mode == "result":
                return

    def _handle_provider_key(self, key: int) -> None:
        if key in (curses.KEY_UP, ord("k")):
            self.provider_index = max(0, self.provider_index - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.provider_index = min(len(self.providers) - 1, self.provider_index + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            self.mode = "amount"
            self.message = ""

    def _handle_amount_key(self, stdscr: Any, key: int) -> None:
        if key in (curses.KEY_BACKSPACE, 127, 8):
            self.limit_text = self.limit_text[:-1]
            return
        if key in (curses.KEY_ENTER, 10, 13):
            self._run_scrape(stdscr)
            return
        if ord("0") <= key <= ord("9"):
            candidate = self.limit_text + chr(key)
            if len(candidate) <= len(str(MAX_RESULT_LIMIT)):
                self.limit_text = candidate
            return
        if key in (ord("b"), ord("B")):
            self.mode = "provider"

    def _run_scrape(self, stdscr: Any) -> None:
        if not self.limit_text:
            self.message = "Enter an amount between 1 and 1000"
            return
        try:
            limit = validate_limit(int(self.limit_text))
        except ValueError as exc:
            self.message = str(exc)
            return

        provider_key = self.providers[self.provider_index]
        self.mode = "running"
        self._render(stdscr)
        stdscr.refresh()

        provider = get_provider(provider_key)
        settings = default_scrape_settings(limit=limit).for_provider(
            provider.key,
            default_collection=provider.default_mongo_collection,
            browser_fallback=provider.browser_fallback,
            default_request_delay=provider.default_request_delay,
            default_concurrency=getattr(provider, "default_concurrency", None),
            manual_verification=getattr(provider, "manual_verification", None),
        ).normalized()
        try:
            output = asyncio.run(ScraperRunner(settings, provider=provider).run())
        except Exception as exc:
            logger.exception("Scrape failed")
            log_uncaught_provider_error(
                data_dir=settings.data_dir,
                error_log_name=settings.error_log,
                provider=provider_key,
                error=exc,
            )
            self.result_lines = [f"Scrape failed: {exc}"]
            resolved = error_log_path_for_settings(settings)
            if resolved is not None:
                self.result_lines.append(f"Error log: {resolved}")
            self.mode = "result"
            return

        vulnerabilities = output.get("vulnerabilities", [])
        completed = sum(
            1
            for item in vulnerabilities
            if isinstance(item.get("details"), dict)
            and isinstance(item["details"].get(provider_key), dict)
        )
        self.result_lines = [
            f"Provider: {provider_key}",
            f"Collection: {settings.mongo_collection}",
            f"Fetched: {len(vulnerabilities)} ({completed} with details)",
        ]
        mongo = output.get("mongo_sync")
        if mongo:
            self.result_lines.append(
                "MongoDB: "
                f"inserted={mongo['inserted']} "
                f"overwritten={mongo['overwritten']} "
                f"skipped={mongo['skipped']} "
                f"conflicts={mongo['conflicts']}"
            )
        failures = output.get("failed") or []
        if failures:
            self.result_lines.append(f"Failures: {len(failures)}")
            first_failure = failures[0] if isinstance(failures[0], dict) else {}
            error = first_failure.get("error")
            if error:
                self.result_lines.append(f"First error: {error}")
        error_log_path = output.get("error_log")
        if not error_log_path:
            resolved = error_log_path_for_settings(settings)
            if resolved is not None:
                error_log_path = str(resolved)
        if error_log_path:
            self.result_lines.append(f"Error log: {Path(error_log_path).resolve()}")
        self.mode = "result"

    def _render(self, stdscr: Any) -> None:
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        row = 0
        if self.mode == "provider":
            self._write(stdscr, row, 0, "Select scraper (↑/↓, Enter, q quit)", curses.A_BOLD, width)
            row += 2
            for index, key in enumerate(self.providers):
                attr = curses.A_REVERSE if index == self.provider_index else curses.A_NORMAL
                self._write(stdscr, row, 2, key, attr, width)
                row += 1
        elif self.mode == "amount":
            provider_key = self.providers[self.provider_index]
            self._write(stdscr, row, 0, f"Scraper: {provider_key}", curses.A_BOLD, width)
            row += 2
            self._write(stdscr, row, 0, f"Amount to scrape (1-{MAX_RESULT_LIMIT}, Enter run, b back):", width=width)
            row += 1
            self._write(stdscr, row, 2, self.limit_text, curses.A_REVERSE, width)
            row += 2
            if self.message:
                self._write(stdscr, row, 0, self.message, curses.A_DIM, width)
        elif self.mode == "running":
            self._write(stdscr, 0, 0, "Scraping…", curses.A_BOLD, width)
        else:
            self._write(stdscr, 0, 0, "Done (any key to exit)", curses.A_BOLD, width)
            row = 2
            for line in self.result_lines:
                self._write(stdscr, row, 0, line, width=width)
                row += 1
        stdscr.refresh()

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
