from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.paloalto.config import (
    DEFAULT_COLLECTION,
    BASE_URL,
    LIST_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.paloalto.parsers.detail import PaloAltoDetailRecord, parse_detail_page
from vuln_scraper.scrapers.paloalto.parsers.rss import parse_rss_list


@dataclass(frozen=True, slots=True)
class PaloAltoProvider:
    key: str = "paloalto"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False
    catch_up_full_feed: bool = True
    sync_discovery_version: str = "rss-v1"

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("PALOALTO-").strip()
        if not code:
            raise ValueError(f"invalid Palo Alto Networks advisory identifier: {identity_display!r}")
        return f"{BASE_URL}/{quote(code, safe='')}"

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        return parse_rss_list(xml, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> PaloAltoDetailRecord:
        detail = parse_detail_page(html)
        if not detail.advisory_id or not detail.title or not detail.description:
            raise ValueError("Palo Alto detail page is missing its full advisory")
        return detail
