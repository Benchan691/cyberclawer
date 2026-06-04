from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import quote

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.huawei_sa.config import (
    API_URL,
    DEFAULT_COLLECTION,
    DETAIL_URL,
    PAGE_SIZE,
    PAYLOAD,
    SOURCE_URL,
)
from vuln_scraper.scrapers.huawei_sa.parsers.detail import HuaweiSADetailRecord, parse_detail_payload
from vuln_scraper.scrapers.huawei_sa.parsers.list import parse_advisories_payload


@dataclass(frozen=True, slots=True)
class HuaweiSAProvider:
    key: str = "huawei_sa"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 1.2
    stop_on_first_known: bool = True
    request_method: str = "POST"

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        safe_page = max(1, page)
        return f"{API_URL}?pageIndex={safe_page}&pageSize={PAGE_SIZE}"

    def detail_url(self, identity_display: str) -> str:
        sasn_no = identity_display.removeprefix("HUAWEI_SA-").strip()
        return f"{DETAIL_URL}/{quote(sasn_no)}"

    def request_payload(self, page: int) -> dict[str, object]:
        return dict(PAYLOAD)

    def request_headers(self) -> dict[str, str]:
        headers = {
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json",
            "x-lang": "en",
            "referer": SOURCE_URL,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        x_ck = os.getenv("HUAWEI_SA_X_CK")
        csrf_token = os.getenv("HUAWEI_SA_CSRF_TOKEN")
        if x_ck:
            headers["x-ck"] = x_ck
        if csrf_token:
            headers["x-csrf-token"] = csrf_token
        return headers

    def parse_list(self, content: object, *, page: int) -> ListPage:
        return parse_advisories_payload(content, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, content: object) -> HuaweiSADetailRecord:
        return parse_detail_payload(content)
