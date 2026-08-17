from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.fortiguard.config import (
    DEFAULT_COLLECTION,
    LIST_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.fortiguard.parsers.detail import (
    FortiguardDetailRecord,
    parse_detail_page,
)
from vuln_scraper.scrapers.fortiguard.parsers.list import parse_advisory_list

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class FortiguardProvider:
    key: str = "fortiguard"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        query = urlencode({"page": max(1, page), "filter": 1})
        return f"{LIST_URL}?{query}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("FORTIGUARD-").strip()
        if not code:
            raise ValueError(f"invalid FortiGuard advisory identifier: {identity_display!r}")
        return f"{LIST_URL}/{quote(code, safe='')}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_advisory_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> FortiguardDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        for key in (
            "advisory_id",
            "title",
            "summary",
            "severity",
            "component",
            "discovered",
            "attack_type",
            "published_date",
            "cve_ids",
        ):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        if not merged.get("products") and list_detail.get("products"):
            merged["products"] = list_detail.get("products")
        return merged

    async def enrich_detail(
        self,
        client: Any,
        detail: dict[str, Any],
        *,
        entry: ListEntry,
        detail_url: str,
    ) -> dict[str, Any]:
        enriched = dict(detail)
        csaf_url = enriched.get("csaf_url")
        if not csaf_url or enriched.get("csaf") is not None:
            return enriched
        try:
            result = await client.get_json(str(csaf_url))
            data = result.data
            if isinstance(data, dict):
                enriched["csaf"] = data
            else:
                logger.warning(
                    "fortiguard CSAF response for %s was not an object: %s",
                    entry.key,
                    type(data).__name__,
                )
        except Exception as exc:
            logger.warning("fortiguard CSAF fetch failed for %s at %s: %s", entry.key, csaf_url, exc)
        return enriched
