from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, urlencode

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.paloalto.config import (
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    LIST_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.paloalto.parsers.detail import PaloAltoDetailRecord, parse_detail_page
from vuln_scraper.scrapers.paloalto.parsers.list import parse_advisory_list


@dataclass(frozen=True, slots=True)
class PaloAltoProvider:
    key: str = "paloalto"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        query = urlencode({"page": max(1, page), "limit": DEFAULT_PAGE_SIZE})
        return f"{LIST_URL}/?{query}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("PALOALTO-").strip()
        if not code:
            raise ValueError(f"invalid Palo Alto Networks advisory identifier: {identity_display!r}")
        return f"{LIST_URL}/{quote(code, safe='')}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_advisory_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> PaloAltoDetailRecord:
        return parse_detail_page(html)
