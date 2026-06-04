from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from vuln_scraper.models import ListPage, normalize_cve_code
from vuln_scraper.scrapers.cve.config import (
    DEFAULT_COLLECTION,
    MAX_DATE_WINDOW_DAYS,
    NVD_BASE,
    RESULTS_PER_PAGE,
    SOURCE_URL,
)
from vuln_scraper.scrapers.cve.parsers.detail import CVEDetailRecord, parse_cve_detail_response
from vuln_scraper.scrapers.cve.parsers.list import parse_cve_list


@dataclass(frozen=True, slots=True)
class CVEProvider:
    key: str = "cve"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 6.0
    stop_on_first_known: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        start, end, start_index = _window_from_checkpoint(checkpoint, page)
        return self.modified_url(start, end, start_index=start_index)

    def detail_url(self, identity_display: str) -> str:
        code = normalize_cve_code(identity_display)
        if code is None:
            raise ValueError(f"invalid CVE identifier: {identity_display!r}")
        return self.cve_url(code)

    def cve_url(self, code: str) -> str:
        normalized = normalize_cve_code(code)
        if normalized is None:
            raise ValueError(f"invalid CVE code: {code!r}")
        return f"{NVD_BASE}?{urlencode({'cveId': f'CVE-{normalized}'})}"

    def modified_url(self, start: str, end: str, *, start_index: int = 0) -> str:
        params = {
            "lastModStartDate": start,
            "lastModEndDate": end,
            "resultsPerPage": str(RESULTS_PER_PAGE),
            "startIndex": str(max(0, start_index)),
        }
        return f"{NVD_BASE}?{urlencode(params)}"

    def request_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        return headers

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_cve_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> CVEDetailRecord:
        return parse_cve_detail_response(data)


def default_window(now: datetime | None = None) -> tuple[str, str]:
    current = now or datetime.now(UTC)
    start = current - timedelta(days=MAX_DATE_WINDOW_DAYS)
    return _format_nvd_datetime(start), _format_nvd_datetime(current)


def _window_from_checkpoint(checkpoint: object | None, page: int) -> tuple[str, str, int]:
    start = getattr(checkpoint, "nvd_last_mod_start", None)
    end = getattr(checkpoint, "nvd_last_mod_end", None)
    start_index = getattr(checkpoint, "nvd_start_index", None)

    if not start or not end:
        start, end = default_window()
    if start_index is None:
        start_index = max(0, page - 1) * RESULTS_PER_PAGE
    return str(start), str(end), int(start_index)


def _format_nvd_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
