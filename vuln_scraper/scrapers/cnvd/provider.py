from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.cnvd.config import (
    DEFAULT_COLLECTION,
    DETAIL_URL,
    LIST_URL,
    PAGE_SIZE,
    SOURCE_URL,
)
from vuln_scraper.scrapers.cnvd.session import CNVD_REQUEST_HEADERS
from vuln_scraper.scrapers.cnvd.parsers.detail import CNVDDetailRecord, parse_detail_page
from vuln_scraper.scrapers.cnvd.parsers.list import parse_flaw_list


@dataclass(frozen=True, slots=True)
class CNVDProvider:
    key: str = "cnvd"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    always_use_browser: bool = False
    manual_verification: bool = False
    content_type: str = "html"
    default_request_delay: float = 3.0
    default_concurrency: int = 1
    stop_on_first_known: bool = True

    def request_headers(self) -> dict[str, str]:
        return dict(CNVD_REQUEST_HEADERS)

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        offset = (max(1, page) - 1) * PAGE_SIZE
        return f"{LIST_URL}?{urlencode({'max': PAGE_SIZE, 'offset': offset})}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("CNVD-").strip()
        if not code:
            raise ValueError(f"invalid CNVD flaw identifier: {identity_display!r}")
        return f"{DETAIL_URL}/CNVD-{quote(code, safe='')}"

    def detail_url_for_entry(self, entry: ListEntry) -> str | None:
        detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        links = detail.get("reference_links")
        if isinstance(links, list):
            for link in links:
                if isinstance(link, str) and link.strip():
                    return link.strip()
        return None

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_flaw_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> CNVDDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        if not merged.get("cnvd_id"):
            merged["cnvd_id"] = f"CNVD-{entry.identity.code}"
        for key in ("title", "severity", "published_date"):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        for key in ("click_count", "comment_count", "follow_count"):
            if merged.get(key) is None:
                merged[key] = list_detail.get(key)
        links = list(merged.get("reference_links") or [])
        if detail_url not in links:
            links.insert(0, detail_url)
        merged["reference_links"] = links
        return merged
