from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.juniper.config import ARTICLE_URL, DEFAULT_COLLECTION, PAGE_SIZE, SEARCH_URL, SOURCE_URL
from vuln_scraper.scrapers.juniper.parsers.detail import JuniperDetailRecord, parse_detail_page
from vuln_scraper.scrapers.juniper.parsers.list import parse_advisory_list


@dataclass(frozen=True, slots=True)
class JuniperProvider:
    key: str = "juniper"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = True
    always_use_browser: bool = True
    content_type: str = "html"
    default_request_delay: float = 1.5
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        first_result = max(0, (max(1, page) - 1) * PAGE_SIZE)
        fragment = (
            "sortCriteria=date%20descending"
            "&f-sf_primarysourcename=Knowledge"
            "&f-sf_articletype=Security%20Advisories"
            f"&firstResult={first_result}"
        )
        return f"{SEARCH_URL}#{fragment}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("JUNIPER-").strip()
        if not code:
            raise ValueError(f"invalid Juniper advisory identifier: {identity_display!r}")
        return f"{ARTICLE_URL}/{quote(code, safe='')}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_advisory_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> JuniperDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        for key in ("article_id", "published_date", "updated_date", "article_type", "source_name", "summary"):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        links = list(merged.get("reference_links") or [])
        if detail_url not in links:
            links.insert(0, detail_url)
        merged["reference_links"] = links
        return merged
