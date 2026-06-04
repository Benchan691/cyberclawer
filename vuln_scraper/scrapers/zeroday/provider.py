from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.zeroday.config import DEFAULT_COLLECTION, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.zeroday.parsers.detail import ZeroDayDetailRecord, parse_detail_page
from vuln_scraper.scrapers.zeroday.parsers.list import parse_database_list


@dataclass(frozen=True, slots=True)
class ZeroDayProvider:
    key: str = "zeroday"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("ZERODAY-").strip()
        if not code.isdigit():
            raise ValueError(f"invalid zero-day.cz identifier: {identity_display!r}")
        return f"{LIST_URL}{quote(code)}/"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_database_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> ZeroDayDetailRecord:
        return parse_detail_page(html)
