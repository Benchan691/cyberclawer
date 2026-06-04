from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.qianxin.config import (
    DEFAULT_CATEGORY,
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    DETAIL_API_URL,
    DETAIL_URL,
    LIST_API_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.qianxin.parsers.detail import QianxinDetailRecord, parse_article_detail
from vuln_scraper.scrapers.qianxin.parsers.list import parse_article_notice_list


@dataclass(frozen=True, slots=True)
class QianxinProvider:
    key: str = "qianxin"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_API_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("QIANXIN-").strip()
        if not code.isdigit():
            raise ValueError(f"invalid Qianxin article identifier: {identity_display!r}")
        return f"{DETAIL_URL}/{code}?type=risk"

    def request_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Referer": SOURCE_URL,
            "lang": "zh-CN",
        }

    def list_json_request(self, page: int, *, checkpoint: object | None = None) -> dict[str, Any]:
        return {
            "method": "POST",
            "url": LIST_API_URL,
            "headers": self.request_headers(),
            "json": {
                "page_no": max(1, page),
                "page_size": DEFAULT_PAGE_SIZE,
                "category": DEFAULT_CATEGORY,
            },
        }

    def detail_json_request(self, entry: ListEntry, *, detail_url: str) -> dict[str, Any]:
        article_id = entry.identity.code
        return {
            "method": "GET",
            "url": f"{DETAIL_API_URL}?{urlencode({'id': article_id})}",
            "headers": {
                "Accept": "application/json, text/plain, */*",
                "Referer": detail_url,
                "lang": "zh-CN",
            },
        }

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_article_notice_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> QianxinDetailRecord:
        return parse_article_detail(data)

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        for key in (
            "article_id",
            "title",
            "threat_status",
            "category",
            "level",
            "author",
            "digest",
            "cover_url",
            "read_num",
            "updated_at",
            "updated_date",
        ):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        for key in ("vuln_ids", "cve_ids"):
            values = list(merged.get(key) or [])
            for value in list_detail.get(key) or []:
                if value not in values:
                    values.append(value)
            merged[key] = values
        links = list(merged.get("reference_links") or [])
        if detail_url not in links:
            links.insert(0, detail_url)
        merged["reference_links"] = links
        return merged
