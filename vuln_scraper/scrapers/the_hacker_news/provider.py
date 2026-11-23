from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.the_hacker_news.config import DEFAULT_COLLECTION, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.the_hacker_news.parsers.detail import TheHackerNewsDetailRecord, parse_detail_page
from vuln_scraper.scrapers.the_hacker_news.parsers.list import parse_rss_list


PROVIDER_SCHEMA = {
    "identity_fields": ("feed_guid",),
    "title_fields": ("title",),
    "cve_fields": ("cve_ids",),
    "published_fields": ("published_at",),
    "updated_fields": ("updated_at",),
    "source_fields": ("article_url",),
}


@dataclass(frozen=True, slots=True)
class TheHackerNewsProvider:
    key: str = "the_hacker_news"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False
    catch_up_full_feed: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("THN-").strip()
        match = re.fullmatch(r"(\d{4})-(0[1-9]|1[0-2])-([a-z0-9]+(?:-[a-z0-9]+)*)", code)
        if match is None:
            raise ValueError(f"invalid The Hacker News article identifier: {identity_display!r}")
        year, month, slug = match.groups()
        return f"{SOURCE_URL}{year}/{month}/{slug}.html"

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        return parse_rss_list(xml, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> TheHackerNewsDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        listing = entry.embedded_detail or {}
        for key in ("feed_guid", "title", "article_url", "published_at", "summary", "author"):
            if merged.get(key) in (None, "", []):
                merged[key] = listing.get(key)
        for key in ("categories", "cve_ids"):
            merged[key] = list(dict.fromkeys([*merged.get(key, []), *listing.get(key, [])]))
        links = [merged.get("article_url"), detail_url, *merged.get("reference_links", [])]
        merged["reference_links"] = list(dict.fromkeys(link for link in links if link))
        return merged
