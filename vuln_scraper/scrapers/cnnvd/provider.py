from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.cnnvd.config import (
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    DETAIL_API_URL,
    LIST_API_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.cnnvd.parsers.detail import CNNVDDetailRecord, parse_warn_detail
from vuln_scraper.scrapers.cnnvd.parsers.list import parse_warn_list


@dataclass(frozen=True, slots=True)
class CNNVDProvider:
    key: str = "cnnvd"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_API_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("CNNVD-").strip()
        if not code:
            raise ValueError(f"invalid CNNVD warning identifier: {identity_display!r}")
        return f"{SOURCE_URL}?{urlencode({'warnId': code})}"

    def request_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json;charset=UTF-8",
            "Referer": SOURCE_URL,
        }

    def list_json_request(self, page: int, *, checkpoint: object | None = None) -> dict[str, Any]:
        return {
            "method": "POST",
            "url": LIST_API_URL,
            "headers": self.request_headers(),
            "json": {
                "pageIndex": max(1, page),
                "pageSize": DEFAULT_PAGE_SIZE,
                "keyword": "",
                "reportType": 1,
                "beginTime": "",
                "endTime": "",
                "dateType": [],
            },
        }

    def detail_json_request(self, entry: ListEntry, *, detail_url: str) -> dict[str, Any]:
        return {
            "method": "POST",
            "url": DETAIL_API_URL,
            "headers": {
                "Accept": "application/json",
                "Referer": detail_url,
            },
            "data": {"warnId": entry.identity.code},
        }

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_warn_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> CNNVDDetailRecord:
        return parse_warn_detail(data)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        if not merged.get("warn_id"):
            merged["warn_id"] = entry.identity.code
        if not merged.get("published_date"):
            merged["published_date"] = list_detail.get("published_date")
        if not merged.get("summary"):
            merged["summary"] = list_detail.get("summary")
        links = list(merged.get("reference_links") or [])
        if detail_url not in links:
            links.insert(0, detail_url)
        merged["reference_links"] = links
        return merged
