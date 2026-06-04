from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.cisco.config import (
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    DETAIL_URL,
    LIST_URL,
    SOURCE_URL,
    TOKEN_EXPIRY_SKEW_SECONDS,
    TOKEN_URL,
)
from vuln_scraper.scrapers.cisco.parsers.detail import CiscoDetailRecord, parse_detail_response
from vuln_scraper.scrapers.cisco.parsers.list import parse_advisories_list


class CiscoAuthError(RuntimeError):
    """Raised when Cisco OpenVuln credentials are missing or invalid."""


@dataclass(slots=True)
class CiscoProvider:
    key: str = "cisco"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 0.5
    stop_on_first_known: bool = False
    _cached_access_token: str | None = field(default=None, init=False, repr=False)
    _token_expires_at: float = field(default=0.0, init=False, repr=False)

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        page_index = max(1, page)
        query = urlencode({"pageIndex": page_index, "pageSize": DEFAULT_PAGE_SIZE})
        return f"{LIST_URL}?{query}"

    def detail_url(self, identity_display: str) -> str:
        advisory_id = identity_display.removeprefix("CISCO-").strip()
        if not advisory_id:
            raise ValueError(f"invalid Cisco advisory identifier: {identity_display!r}")
        return f"{DETAIL_URL}/{quote(advisory_id, safe='')}"

    def request_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        token = self._static_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def async_request_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        token = self._static_token() or await self._access_token()
        headers["Authorization"] = f"Bearer {token}"
        return headers

    def parse_list(self, data: object, *, page: int) -> ListPage:
        return parse_advisories_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: object) -> CiscoDetailRecord:
        return parse_detail_response(data)

    def _static_token(self) -> str | None:
        token = os.getenv("CISCO_OPENVULN_TOKEN")
        if token:
            return token.strip() or None
        return None

    async def _access_token(self) -> str:
        now = time.monotonic()
        if self._cached_access_token and now < self._token_expires_at:
            return self._cached_access_token

        client_id = _credential(
            "CISCO_OPENVULN_CLIENT_ID",
            "CISCO_OPENVULN_CLIENT_KEY",
            "CISCO_CLIENT_ID",
            "CISCO_CLIENT_KEY",
        )
        client_secret = _credential("CISCO_OPENVULN_CLIENT_SECRET", "CISCO_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise CiscoAuthError(
                "Cisco OpenVuln API requires authentication. Set CISCO_OPENVULN_TOKEN "
                "or set CISCO_OPENVULN_CLIENT_ID/CISCO_OPENVULN_CLIENT_KEY "
                "and CISCO_OPENVULN_CLIENT_SECRET."
            )

        payload = await self._fetch_access_token(client_id, client_secret)
        token = str(payload.get("access_token") or "").strip()
        if not token:
            raise CiscoAuthError("Cisco OpenVuln token response did not include access_token.")

        expires_in = _optional_int(payload.get("expires_in")) or 3600
        self._cached_access_token = token
        self._token_expires_at = now + max(0, expires_in - TOKEN_EXPIRY_SKEW_SECONDS)
        return token

    async def _fetch_access_token(self, client_id: str, client_secret: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
                response = await client.post(
                    TOKEN_URL,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={"grant_type": "client_credentials"},
                    auth=(client_id, client_secret),
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CiscoAuthError(f"Failed to obtain Cisco OpenVuln access token: {exc}") from exc
        if not isinstance(data, dict):
            raise CiscoAuthError("Cisco OpenVuln token response was not a JSON object.")
        return data


def _credential(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
