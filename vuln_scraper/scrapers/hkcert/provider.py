from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote
from xml.etree import ElementTree

from vuln_scraper.client import FetchError
from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.hkcert.config import DEFAULT_COLLECTION, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.hkcert.parsers.detail import HKCERTDetailRecord, parse_detail_page
from vuln_scraper.scrapers.hkcert.parsers.list import parse_security_bulletin_list


@dataclass(frozen=True, slots=True)
class HKCERTProvider:
    key: str = "hkcert"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False
    stop_on_timestamp_boundary: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        slug = identity_display.removeprefix("HKCERT-")
        return f"{SOURCE_URL}/{quote(slug)}"

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        try:
            return parse_security_bulletin_list(xml, page=page, provider=self.key, source_url=self.source_url)
        except (ValueError, ElementTree.ParseError) as exc:
            raise FetchError(f"Invalid HKCERT security bulletin feed at {LIST_URL}: {exc}") from exc

    def parse_detail(self, html: str) -> HKCERTDetailRecord:
        return parse_detail_page(html)
