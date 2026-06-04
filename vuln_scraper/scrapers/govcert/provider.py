from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, urlencode

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.govcert.config import DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.govcert.parsers.detail import GovCERTDetailRecord, parse_detail_page
from vuln_scraper.scrapers.govcert.parsers.list import parse_alerts_list


@dataclass(frozen=True, slots=True)
class GovCERTProvider:
    key: str = "govcert"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return f"{LIST_URL}?{urlencode({'page': str(max(1, page))})}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("GOVCERT-").strip()
        if not code.isdigit():
            raise ValueError(f"invalid GovCERT alert identifier: {identity_display!r}")
        return f"{DETAIL_URL}?{urlencode({'id': quote(code)})}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_alerts_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> GovCERTDetailRecord:
        return parse_detail_page(html)
