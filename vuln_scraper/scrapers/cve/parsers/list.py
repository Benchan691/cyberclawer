from __future__ import annotations

import json
import math
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId, normalize_cve_code
from vuln_scraper.scrapers.cve.config import SOURCE_URL
from vuln_scraper.scrapers.cve.parsers.detail import english_description, parse_cve_detail


def parse_cve_list(
    data: Any,
    *,
    page: int,
    provider: str = "cve",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(data)
    if not isinstance(payload, dict):
        raise ValueError("NVD CVE list response must be a JSON object")

    results_per_page = _optional_int(payload.get("resultsPerPage"))
    start_index = _optional_int(payload.get("startIndex"))
    total_records = _optional_int(payload.get("totalResults"))
    total_pages = (
        math.ceil(total_records / results_per_page)
        if total_records is not None and results_per_page
        else None
    )

    entries: list[ListEntry] = []
    vulnerabilities = payload.get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        for item in vulnerabilities:
            if isinstance(item, dict) and isinstance(item.get("cve"), dict):
                entry = entry_from_cve(item["cve"], provider=provider, source_url=source_url)
                if entry is not None:
                    entries.append(entry)

    return ListPage(
        page=page,
        entries=entries,
        total_pages=total_pages,
        total_records=total_records,
        start_index=start_index,
        results_per_page=results_per_page,
    )


def entry_from_cve(
    cve: dict[str, Any],
    *,
    provider: str = "cve",
    source_url: str | None = SOURCE_URL,
) -> ListEntry | None:
    cve_id = cve.get("id")
    code = normalize_cve_code(str(cve_id)) if cve_id else None
    if code is None:
        return None

    detail = parse_cve_detail(cve).to_dict()
    title = english_description(detail) or str(cve_id)
    return ListEntry(
        identity=VulnerabilityId(type="CVE", code=code),
        title=title,
        vuln_type=None,
        disclosure_date=detail.get("published"),
        status=None,
        provider=provider,
        source_url=source_url,
        embedded_detail=detail,
    )


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
