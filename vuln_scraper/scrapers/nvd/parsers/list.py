from __future__ import annotations

import math
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.nvd.config import DEFAULT_PAGE_SIZE, SOURCE_URL
from vuln_scraper.scrapers.nvd.parsers.detail import parse_cve_record


def parse_advisory_list(
    payload: dict[str, Any],
    *,
    page: int,
    provider: str = "nvd",
    source_url: str | None = SOURCE_URL,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> ListPage:
    results_per_page = int(payload.get("resultsPerPage") or 0)
    total_results = int(payload.get("totalResults") or 0)
    start_index = payload.get("startIndex")
    raw_entries = payload.get("vulnerabilities")
    exhausted = (
        raw_entries == []
        and type(start_index) is int
        and type(payload.get("totalResults")) is int
        and type(payload.get("resultsPerPage")) is int
        and results_per_page == 0
        and start_index >= total_results >= 0
    )

    entries: list[ListEntry] = []
    seen: set[str] = set()
    for item in raw_entries or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        detail = parse_cve_record(cve).to_dict()
        code = str(detail.get("cve_id") or "").strip()
        if not code or code in seen:
            continue
        seen.add(code)
        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="NVD", code=code),
                title=str(detail.get("title") or code),
                vuln_type="CVE",
                disclosure_date=detail.get("published_date"),
                status=detail.get("severity") or detail.get("vuln_status"),
                provider=provider,
                source_url=source_url,
                embedded_detail=detail,
            )
        )

    # Response resultsPerPage is the returned count, which can shrink on the
    # final page. Offsets use the requested page size throughout the run.
    total_pages = (
        math.ceil(total_results / page_size)
        if total_results
        else 0 if exhausted else 1 if entries else None
    )
    return ListPage(
        page=page,
        entries=entries,
        total_pages=total_pages,
        total_records=total_results if "totalResults" in payload else len(entries),
        start_index=start_index,
        results_per_page=results_per_page,
        exhausted=exhausted,
    )
