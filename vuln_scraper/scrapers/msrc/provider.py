from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.msrc.config import DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.msrc.parsers.detail import (
    MSRCMonthlyRecord,
    expand_cvrf_document,
    parse_cvrf_document,
)
from vuln_scraper.scrapers.msrc.parsers.list import parse_update_list


@dataclass(frozen=True, slots=True)
class MSRCProvider:
    key: str = "msrc"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 0.5
    stop_on_first_known: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return f"{LIST_URL}?$orderby=currentReleaseDate%20desc"

    def detail_url(self, identity_display: str) -> str:
        update_id = identity_display.removeprefix("MSRC-").strip()
        if not update_id:
            raise ValueError(f"invalid MSRC update identifier: {identity_display!r}")
        return f"{DETAIL_URL}/{quote(update_id, safe='')}"

    def detail_url_for_entry(self, entry: ListEntry) -> str | None:
        embedded_detail = getattr(entry, "embedded_detail", None)
        if isinstance(embedded_detail, dict):
            cvrf_url = embedded_detail.get("cvrf_url")
            if cvrf_url:
                return str(cvrf_url)
        return self.detail_url(getattr(entry, "display_id"))

    def request_headers(self) -> dict[str, str]:
        return {"Accept": "application/json"}

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_update_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> MSRCMonthlyRecord:
        return parse_cvrf_document(data)

    def expand_detail_records(
        self,
        entry: ListEntry,
        detail: dict[str, Any],
        *,
        detail_url: str | None,
    ) -> list[dict[str, Any]]:
        return expand_cvrf_document(entry, detail, detail_url=detail_url, provider=self.key)
