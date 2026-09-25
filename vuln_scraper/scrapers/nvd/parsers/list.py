from __future__ import annotations

import math
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.nvd.config import SOURCE_URL
from vuln_scraper.scrapers.nvd.parsers.detail import parse_cve_record


def parse_advisory_list(
    payload: dict[str, Any],
    *,
    page: int,
    provider: str = "nvd",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    results_per_page = int(payload.get("resultsPerPage") or 0)
    total_results = int(payload.get("totalResults") or 0)

    entries: list[ListEntry] = []
    seen: set[str] = set()
    for item in payload.get("vulnerabilities") or []:
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

    total_pages = (
        math.ceil(total_results / results_per_page)
        if total_results and results_per_page
        else 1 if entries else None
    )
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_results or len(entries))
