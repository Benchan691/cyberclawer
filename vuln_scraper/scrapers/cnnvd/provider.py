from __future__ import annotations

from dataclasses import dataclass
import secrets
import string
import time
from typing import Any
from urllib.parse import urlsplit

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.cnnvd.config import (
    BASE_URL,
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    DETAIL_API_URL,
    LIST_API_URL,
    SIGN_API_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.cnnvd.parsers.detail import CNNVDDetailRecord, parse_vulnerability_detail
from vuln_scraper.scrapers.cnnvd.parsers.list import parse_vulnerability_list


APP_ID = "6i8417579268034679HXvp0Kb6r1C2A9"
NONCE_ALPHABET = string.ascii_letters + string.digits


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
            "User-Agent": "Mozilla/5.0",
        }

    def list_json_request(self, page: int, *, checkpoint: object | None = None) -> dict[str, Any]:
        return {
            "method": "POST",
            "url": LIST_API_URL,
            "headers": self.request_headers(),
            "json": {
                "sortOrder": "desc",
                "sortField": "publishDate",
                "page": max(1, page),
                "pageSize": DEFAULT_PAGE_SIZE,
            },
        }

    def detail_json_requests(self, entry: ListEntry, *, detail_url: str) -> list[dict[str, Any]]:
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        record_id = list_detail.get("id")
        if not record_id:
            raise ValueError(f"CNNVD list entry is missing detail id: {entry.display_id}")
        return [
            {
                "method": "POST",
                "url": DETAIL_API_URL,
                "headers": self.request_headers(),
                "json": {"id": record_id},
            }
        ]

    async def finalize_json_request(self, client: Any, request: dict[str, Any]) -> dict[str, Any]:
        request = dict(request)
        headers = dict(request.get("headers") or {})
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or "")
        timestamp = str(int(time.time() * 1000))
        nonce = "".join(secrets.choice(NONCE_ALPHABET) for _ in range(32))
        sign_input = method + urlsplit(url).path + timestamp + nonce
        sign_result = await client.request_json(
            "POST",
            SIGN_API_URL,
            headers={
                **self.request_headers(),
                "X-Appid": APP_ID,
                "X-Timestamp": timestamp,
                "X-Nonce": nonce,
            },
            json_body={"signStr": sign_input},
        )
        sign = sign_result.data.get("data") if isinstance(sign_result.data, dict) else None
        if not sign:
            raise ValueError("CNNVD sign response did not contain a signature")
        headers.update(
            {
                "X-Appid": APP_ID,
                "X-Timestamp": timestamp,
                "X-Nonce": nonce,
                "X-Sign": str(sign),
            }
        )
        request["headers"] = headers
        return request

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_vulnerability_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> CNNVDDetailRecord:
        return parse_vulnerability_detail(data)
