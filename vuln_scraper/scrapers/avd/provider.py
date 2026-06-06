from __future__ import annotations

import os
from dataclasses import dataclass

from vuln_scraper.config import DEFAULT_HEADERS
from vuln_scraper.models import DetailRecord, ListEntry, ListPage
from vuln_scraper.scrapers.avd.config import BASE_URL, DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL
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

    def request_headers(self) -> dict[str, str]:
        headers = dict(DEFAULT_HEADERS)
        cookie = _env("AVD_COOKIE", "AVD_COOKIES", "ALIYUN_AVD_COOKIE")
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return f"{LIST_URL}?page={page}"

    def detail_url(self, identity_display: str) -> str:
        return f"{DETAIL_URL}?id={identity_display}"

    def detail_url_for_entry(self, entry: ListEntry) -> str | None:
        detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        links = detail.get("reference_links")
        if isinstance(links, list):
            for link in links:
                if isinstance(link, str) and link.strip():
                    return link.strip()
        if entry.display_id:
            return self.detail_url(entry.display_id)
        return None

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_high_risk_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> DetailRecord:
        return parse_detail_page(html)


def _env(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value.strip()
    return None
