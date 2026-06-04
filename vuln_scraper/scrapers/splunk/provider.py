from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.splunk.config import DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.splunk.parsers.detail import SplunkDetailRecord, parse_detail_page
from vuln_scraper.scrapers.splunk.parsers.list import parse_advisory_list


@dataclass(frozen=True, slots=True)
class SplunkProvider:
    key: str = "splunk"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("SPLUNK-").strip()
        if not code.upper().startswith("SVD-"):
            raise ValueError(f"invalid Splunk advisory identifier: {identity_display!r}")
        return f"{DETAIL_URL}/{quote(code, safe='')}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_advisory_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> SplunkDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        for key in (
            "advisory_id",
            "last_modified",
            "severity",
            "cvss_vector",
            "cvss_score",
            "cwe",
            "bug_ids",
            "affected_products",
            "fixed_versions",
            "affected_versions",
            "all_affected_versions",
            "affected_components",
            "description",
            "solution",
            "mitigations",
            "severity_summary",
            "oss",
            "credit",
        ):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        if merged.get("published_date") in (None, ""):
            merged["published_date"] = entry.disclosure_date
        links = list(merged.get("reference_links") or [])
        if detail_url not in links:
            links.insert(0, detail_url)
        merged["reference_links"] = links
        return merged
