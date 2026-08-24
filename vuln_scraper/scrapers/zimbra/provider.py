from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urljoin

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.zimbra.config import BASE_URL, DEFAULT_COLLECTION, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.zimbra.parsers.detail import ZimbraDetailRecord, parse_detail_page
from vuln_scraper.scrapers.zimbra.parsers.list import parse_release_list


@dataclass(frozen=True, slots=True)
class ZimbraProvider:
    key: str = "zimbra"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("ZIMBRA-").strip()
        if not code:
            raise ValueError(f"invalid Zimbra release identifier: {identity_display!r}")
        return urljoin(BASE_URL, f"/wiki/Zimbra_Releases/{quote(code, safe='/.')}")

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_release_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> ZimbraDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        if list_detail.get("version"):
            merged["version"] = list_detail["version"]
        for key in ("product_release", "codename", "third_party_patch_level", "general_availability"):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        links = list(merged.get("reference_links") or [])
        for link in (detail_url, *list_detail.get("reference_links", [])):
            if link and link not in links:
                links.insert(0, link)
        merged["reference_links"] = links
        return merged
