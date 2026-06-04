from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.ransomwarelive.config import (
    DEFAULT_COLLECTION,
    RECENT_VICTIMS_URL,
    SOURCE_URL,
    VICTIM_URL,
)
from vuln_scraper.scrapers.ransomwarelive.parsers.detail import (
    RansomwareLiveVictimRecord,
    parse_victim_response,
)
from vuln_scraper.scrapers.ransomwarelive.parsers.list import parse_recent_victims


class RansomwareLiveAuthError(RuntimeError):
    """Raised when ransomware.live PRO API credentials are missing."""


@dataclass(frozen=True, slots=True)
class RansomwareLiveProvider:
    key: str = "ransomwarelive"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        query = urlencode({"order": "discovered"})
        return f"{RECENT_VICTIMS_URL}?{query}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("RANSOMWARELIVE-").strip()
        if not code:
            raise ValueError(f"invalid ransomware.live victim identifier: {identity_display!r}")
        return f"{VICTIM_URL}/{quote(code, safe='')}"

    def request_headers(self) -> dict[str, str]:
        api_key = _api_key()
        if not api_key or not api_key.strip():
            raise RansomwareLiveAuthError(
                "ransomware.live PRO API requires authentication. Set RANSOMWARE_LIVE_API_KEY "
                "or RANSOM_API_KEY."
            )
        return {
            "Accept": "application/json",
            "X-API-KEY": api_key.strip(),
        }

    def parse_list(self, data: Any, *, page: int) -> ListPage:
        return parse_recent_victims(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> RansomwareLiveVictimRecord:
        return parse_victim_response(data)


def _api_key() -> str | None:
    from vuln_scraper.env_file import read_dotenv

    for name in ("RANSOMWARE_LIVE_API_KEY", "RANSOM_API_KEY"):
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    dotenv = read_dotenv(Path.cwd() / ".env")
    for name in ("RANSOMWARE_LIVE_API_KEY", "RANSOM_API_KEY"):
        value = dotenv.get(name)
        if value and value.strip():
            return value.strip()
    return None
