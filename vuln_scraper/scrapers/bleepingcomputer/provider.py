from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree

from vuln_scraper.models import ListPage

from .config import ARTICLE_BASE_URL, DEFAULT_COLLECTION, LIST_URL, SOURCE_URL
from .parsers.detail import ARTICLE_CODE_RE, BleepingComputerDetailRecord, parse_rss_item
from .parsers.list import parse_rss_list


PROVIDER_SCHEMA = {
    "cve_fields": ("cve_ids",),
    "published_fields": ("published_at",),
}


@dataclass(frozen=True, slots=True)
class BleepingComputerProvider:
    key: str = "bleepingcomputer"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False

    def request_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/rss+xml, application/xml, text/xml;q=0.9",
            "User-Agent": "Cyberclawer RSS Reader",
        }

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("BLEEPINGCOMPUTER-")
        if not ARTICLE_CODE_RE.fullmatch(code):
            raise ValueError(f"Invalid BleepingComputer article identifier: {identity_display!r}")
        return f"{ARTICLE_BASE_URL}{code}/"

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        return parse_rss_list(xml, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, xml: str) -> BleepingComputerDetailRecord:
        return parse_rss_item(ElementTree.fromstring(xml))
