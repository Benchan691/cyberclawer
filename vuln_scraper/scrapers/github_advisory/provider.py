from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urlparse
import re

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.github_advisory.config import (
    DEFAULT_COLLECTION,
    DEFAULT_PAGE_SIZE,
    DETAIL_URL,
    GITHUB_API_VERSION,
    LIST_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.github_advisory.parsers.detail import (
    GitHubAdvisoryDetailRecord,
    ghsa_code,
    parse_advisory_response,
)
from vuln_scraper.scrapers.github_advisory.parsers.list import parse_advisory_list


@dataclass(frozen=True, slots=True)
class GitHubAdvisoryProvider:
    key: str = "github_advisory"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "json"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        params = {
            "type": "reviewed",
            "sort": "published",
            "direction": "desc",
            "per_page": str(DEFAULT_PAGE_SIZE),
            "page": str(max(1, page)),
        }
        return f"{LIST_URL}?{urlencode(params)}"

    def detail_url(self, identity_display: str) -> str:
        code = ghsa_code(identity_display)
        if code is None:
            raise ValueError(f"invalid GitHub advisory identifier: {identity_display!r}")
        return f"{DETAIL_URL}/{quote(f'GHSA-{code}', safe='')}"

    def sync_list_url(self, context: Any, page: int) -> str:
        if context.cursor:
            target = urlparse(context.cursor)
            if target.scheme != "https" or target.netloc != "api.github.com" or target.path != "/advisories":
                raise ValueError("invalid GitHub advisory pagination URL")
            return context.cursor
        params = {"type": "reviewed", "sort": "updated", "direction": "desc",
                  "per_page": DEFAULT_PAGE_SIZE,
                  "modified": f"{context.since.isoformat()}..{context.until.isoformat()}"}
        return f"{LIST_URL}?{urlencode(params)}"

    def parse_sync_list(self, data: Any, *, page: int, context: Any, headers: dict[str, str]) -> ListPage:
        if not isinstance(data, list):
            raise ValueError("GitHub advisory response must be an array")
        result = self.parse_list(data, page=page)
        if len(result.entries) != len(data):
            raise ValueError("GitHub advisory response contains an invalid advisory identity")
        link = headers.get("link", headers.get("Link", ""))
        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        result.next_cursor = match.group(1) if match else None
        if result.next_cursor:
            self.sync_list_url(type("Cursor", (), {"cursor": result.next_cursor})(), page + 1)
        else:
            result.total_pages = page
            result.exhausted = not data
        return result

    def detail_url_for_entry(self, entry: object) -> str | None:
        embedded_detail = getattr(entry, "embedded_detail", None)
        if isinstance(embedded_detail, dict) and embedded_detail:
            return None
        return self.detail_url(getattr(entry, "display_id"))

    def request_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        token = os.getenv("GITHUB_TOKEN")
        if token and token.strip():
            headers["Authorization"] = f"Bearer {token.strip()}"
        return headers

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_advisory_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> GitHubAdvisoryDetailRecord:
        return parse_advisory_response(data)
