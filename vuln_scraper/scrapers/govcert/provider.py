from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode
from xml.etree import ElementTree

from vuln_scraper.client import FetchError
from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.govcert.config import DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.govcert.parsers.detail import GovCERTDetailRecord, parse_detail_page
from vuln_scraper.scrapers.govcert.parsers.list import parse_alerts_list


@dataclass(frozen=True, slots=True)
class GovCERTProvider:
    key: str = "govcert"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True
    stop_on_timestamp_boundary: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("GOVCERT-").strip()
        if not code.isdigit():
            raise ValueError(f"invalid GovCERT alert identifier: {identity_display!r}")
        return f"{DETAIL_URL}?{urlencode({'id': code})}"

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        try:
            return parse_alerts_list(xml, page=page, provider=self.key, source_url=self.source_url)
        except (ValueError, ElementTree.ParseError) as exc:
            raise FetchError(f"Invalid GovCERT security alerts feed at {LIST_URL}: {exc}") from exc

    def parse_detail(self, html: str) -> GovCERTDetailRecord:
        return parse_detail_page(html)
