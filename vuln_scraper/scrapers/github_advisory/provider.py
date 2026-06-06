from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

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
    browser_fallback: bool = False
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
