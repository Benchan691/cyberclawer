from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.infosec.config import DEFAULT_COLLECTION, GOVCERT_DETAIL_URL, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.infosec.parsers.detail import InfoSecDetailRecord, parse_detail_page
from vuln_scraper.scrapers.infosec.parsers.list import parse_alerts_list


HK_TIMEZONE = ZoneInfo("Asia/Hong_Kong")


@dataclass(frozen=True, slots=True)
class InfoSecProvider:
    key: str = "infosec"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        current_year = datetime.now(HK_TIMEZONE).year
        year = current_year - max(1, page) + 1
        return f"{LIST_URL}/{year}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("INFOSEC-").strip()
        if not code.isdigit():
            raise ValueError(f"invalid InfoSec alert identifier: {identity_display!r}")
        return f"{GOVCERT_DETAIL_URL}?{urlencode({'id': quote(code)})}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_alerts_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> InfoSecDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        if not merged.get("summary"):
            merged["summary"] = list_detail.get("summary")
        merged["govcert_detail_url"] = detail_url
        return merged
