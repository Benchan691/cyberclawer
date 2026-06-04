from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.hkcert.config import DEFAULT_COLLECTION, ITEMS_PER_PAGE, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.hkcert.parsers.detail import HKCERTDetailRecord, parse_detail_page
from vuln_scraper.scrapers.hkcert.parsers.list import parse_security_bulletin_list


@dataclass(frozen=True, slots=True)
class HKCERTProvider:
    key: str = "hkcert"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return f"{LIST_URL}?item_per_page={ITEMS_PER_PAGE}&page={page}"

    def detail_url(self, identity_display: str) -> str:
        slug = identity_display.removeprefix("HKCERT-")
        return f"{LIST_URL}/{quote(slug)}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_security_bulletin_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> HKCERTDetailRecord:
        return parse_detail_page(html)
