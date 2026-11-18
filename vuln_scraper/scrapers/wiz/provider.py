from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.wiz.config import BASE_URL, DEFAULT_COLLECTION, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.wiz.parsers.detail import WizDetailRecord, parse_detail_page
from vuln_scraper.scrapers.wiz.parsers.list import parse_rss_list


PROVIDER_SCHEMA = {
    "identity_fields": ("feed_guid",),
    "title_fields": ("title",),
    "cve_fields": ("cve_ids",),
    "published_fields": ("published_at",),
    "updated_fields": ("updated_at",),
    "source_fields": ("article_url",),
}


@dataclass(frozen=True, slots=True)
class WizProvider:
    key: str = "wiz"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False
    catch_up_full_feed: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("WIZ-").strip()
        try:
            guid = UUID(code)
        except ValueError as exc:
            raise ValueError(f"invalid Wiz incident identifier: {identity_display!r}") from exc
        # The site redirects its permanent Notion ID to the current article slug.
        return f"{BASE_URL}/{guid.hex}"

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        return parse_rss_list(xml, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> WizDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        listing = entry.embedded_detail or {}
        for key in ("feed_guid", "title", "article_url", "threat_type", "published_at", "summary", "author"):
            if merged.get(key) in (None, "", []):
                merged[key] = listing.get(key)
        merged["cve_ids"] = list(dict.fromkeys([*merged.get("cve_ids", []), *listing.get("cve_ids", [])]))
        links = [detail_url, merged.get("article_url"), *merged.get("reference_links", [])]
        merged["reference_links"] = list(dict.fromkeys(link for link in links if link))
        return merged
