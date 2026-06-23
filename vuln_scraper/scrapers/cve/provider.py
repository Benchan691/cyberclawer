from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId, normalize_cve_code
from vuln_scraper.scrapers.cve.config import (
    DEFAULT_COLLECTION,
    DELTA_LOG_URL,
    RAW_CVE_BASE,
    SOURCE_URL,
)
from vuln_scraper.scrapers.cve.parsers.detail import (
    CVEDetailRecord,
    english_description,
    parse_cve_detail_response,
)
from vuln_scraper.scrapers.cve.parsers.list import parse_cve_list, parse_cve_list_updated_since


@dataclass(frozen=True, slots=True)
class CVEProvider:
    key: str = "cve"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    content_type: str = "json"
    default_request_delay: float = 0.2
    stop_on_first_known: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return DELTA_LOG_URL

    def detail_url(self, identity_display: str) -> str:
        code = normalize_cve_code(identity_display)
        if code is None:
            raise ValueError(f"invalid CVE identifier: {identity_display!r}")
        return self.cve_url(code)

    def cve_url(self, code: str) -> str:
        normalized = normalize_cve_code(code)
        if normalized is None:
            raise ValueError(f"invalid CVE code: {code!r}")
        year, sequence = normalized.split("-", 1)
        directory = f"{sequence[:-3]}xxx"
        return f"{RAW_CVE_BASE}/{year}/{directory}/CVE-{normalized}.json"

    def request_headers(self) -> dict[str, str]:
        return {"Accept": "application/json"}

    def parse_list(self, data: Any, *, page: int, updated_since: datetime | None = None) -> ListPage:
        if updated_since is not None:
            return parse_cve_list_updated_since(
                data,
                updated_since=updated_since,
                page=page,
                provider=self.key,
                source_url=self.source_url,
            )
        return parse_cve_list(data, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> CVEDetailRecord:
        return parse_cve_detail_response(data)

    def entry_from_record(self, data: Any, *, detail_url: str) -> ListEntry:
        detail = self.parse_detail(data).to_dict()
        cve_id = detail.get("cve_id")
        code = normalize_cve_code(cve_id)
        if code is None:
            raise ValueError("CVE v5 record did not contain a valid cveMetadata.cveId")
        return ListEntry(
            identity=VulnerabilityId(type="CVE", code=code),
            title=detail.get("title") or english_description(detail) or str(cve_id),
            vuln_type=None,
            disclosure_date=detail.get("published"),
            status=detail.get("vuln_status"),
            provider=self.key,
            source_url=self.source_url,
            embedded_detail=detail,
        )
