from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.cnnvd.config import (
    BASE_URL,
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    DETAIL_API_URL,
    LIST_API_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.cnnvd.parsers.detail import CNNVDDetailRecord, parse_vulnerability_detail
from vuln_scraper.scrapers.cnnvd.parsers.list import parse_vulnerability_list


@dataclass(frozen=True, slots=True)
class CNNVDProvider:
    key: str = "cnnvd"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_API_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("CNNVD-").strip()
        if not code:
            raise ValueError(f"invalid CNNVD vulnerability identifier: {identity_display!r}")
        return SOURCE_URL

    def request_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": BASE_URL,
            "Referer": SOURCE_URL,
        }

    def list_json_request(self, page: int, *, checkpoint: object | None = None) -> dict[str, Any]:
        return {
            "method": "POST",
            "url": LIST_API_URL,
            "headers": self.request_headers(),
            "json": {
                "pageIndex": max(1, page),
                "pageSize": DEFAULT_PAGE_SIZE,
                "keyword": "",
                "hazardLevel": "",
                "vulType": "",
            },
        }

    def detail_json_requests(self, entry: ListEntry, *, detail_url: str) -> list[dict[str, Any]]:
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        record_id = list_detail.get("id")
        cnnvd_code = list_detail.get("cnnvdCode") or entry.display_id
        cve_code = list_detail.get("cveCode")
        vul_type = list_detail.get("vulType") or "0"
        payloads = [
            {"id": record_id, "cnnvdCode": cnnvd_code, "cveCode": cve_code, "vulType": vul_type},
            {"id": record_id, "vulType": vul_type},
            {"cnnvdCode": cnnvd_code, "vulType": vul_type},
        ]
        headers = self.request_headers()
        return [
            {
                "method": "POST",
                "url": DETAIL_API_URL,
                "headers": headers,
                "json": {key: value for key, value in payload.items() if value is not None},
            }
            for payload in payloads
        ]

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_vulnerability_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> CNNVDDetailRecord:
        return parse_vulnerability_detail(data)
