from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.hikvision.config import (
    CONTENT_ADVISORY_URL,
    DEFAULT_COLLECTION,
    HSRC_CODE_RE,
    LIST_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.hikvision.parsers.detail import HikvisionDetailRecord, parse_detail_page
from vuln_scraper.scrapers.hikvision.parsers.list import parse_advisory_list


@dataclass(frozen=True, slots=True)
class HikvisionProvider:
    key: str = "hikvision"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = True
    always_use_browser: bool = True
    content_type: str = "html"
    default_request_delay: float = 1.5
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        if page <= 1:
            return LIST_URL
        return f"{LIST_URL}?{urlencode({'page': page})}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("HIKVISION-").strip()
        if not code:
            raise ValueError(f"invalid Hikvision advisory identifier: {identity_display!r}")
        if HSRC_CODE_RE.match(code):
            return f"{LIST_URL}{quote(code, safe='')}/"
        return f"{CONTENT_ADVISORY_URL}{quote(code, safe='')}.html"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_advisory_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> HikvisionDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        for key in ("advisory_id", "published_date", "severity", "summary"):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        links = list(merged.get("reference_links") or [])
        if detail_url not in links:
            links.insert(0, detail_url)
        merged["reference_links"] = links
        return merged
