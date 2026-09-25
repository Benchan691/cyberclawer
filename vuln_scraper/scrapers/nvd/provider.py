from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
from typing import Any
from urllib.parse import quote, urlencode

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.nvd.config import (
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    DEFAULT_WINDOW_DAYS,
    DETAIL_URL,
    LIST_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.nvd.parsers.detail import NvdDetailRecord, parse_cve_record
from vuln_scraper.scrapers.nvd.parsers.list import parse_advisory_list

# Plain-dict schema export: picked up by schema_v2 without importing it here
# (keeps the provider package free of registry/schema imports).
PROVIDER_SCHEMA = {
    "identity_fields": ("cve_id",),
    "title_fields": ("title",),
    "cve_fields": ("cve_id",),
    "severity_fields": ("severity",),
    "published_fields": ("published_date",),
    "updated_fields": ("last_modified",),
    "volatile_fields": ("vuln_status",),
    "source_fields": ("detail_url",),
}


@dataclass(frozen=True, slots=True)
class NvdProvider:
    key: str = "nvd"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "json"
    # Unauthenticated NVD allows 5 requests per rolling 30s window.
    default_request_delay: float = 6.5
    stop_on_first_known: bool = False
    window_days: int = DEFAULT_WINDOW_DAYS
    page_size: int = DEFAULT_PAGE_SIZE

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        end = datetime.now(UTC)
        start = end - timedelta(days=self.window_days)
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "resultsPerPage": str(self.page_size),
            "startIndex": str(max(0, (page - 1)) * self.page_size),
        }
        return f"{LIST_URL}?{urlencode(params)}"

    def detail_url(self, identity_display: str) -> str:
        return f"{DETAIL_URL}/{quote(identity_display, safe='')}"

    def detail_url_for_entry(self, entry: object) -> str | None:
        embedded_detail = getattr(entry, "embedded_detail", None)
        if isinstance(embedded_detail, dict) and embedded_detail:
            return None
        return self.detail_url(getattr(entry, "display_id"))

    def request_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        api_key = os.getenv("NVD_API_KEY")
        if api_key and api_key.strip():
            headers["apiKey"] = api_key.strip()
        return headers

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_advisory_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> NvdDetailRecord:
        if isinstance(data, dict) and isinstance(data.get("cve"), dict):
            data = data["cve"]
        return parse_cve_record(data)
