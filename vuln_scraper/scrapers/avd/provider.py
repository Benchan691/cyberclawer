from __future__ import annotations

from dataclasses import dataclass

from vuln_scraper.models import DetailRecord, ListPage
from vuln_scraper.scrapers.avd.config import DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.avd.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.avd.parsers.list import parse_high_risk_list


@dataclass(frozen=True, slots=True)
class AVDProvider:
    key: str = "avd"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = True
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return f"{LIST_URL}?page={page}"

    def detail_url(self, identity_display: str) -> str:
        return f"{DETAIL_URL}?id={identity_display}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_high_risk_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> DetailRecord:
        return parse_detail_page(html)
