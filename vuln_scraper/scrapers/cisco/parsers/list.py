from __future__ import annotations

import json
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId, normalize_cve_code
from vuln_scraper.scrapers.cisco.config import SOURCE_URL
from vuln_scraper.scrapers.cisco.parsers.detail import parse_detail_response


def parse_advisories_list(
    data: Any,
    *,
    page: int,
    provider: str = "cisco",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(data)
    advisories = _extract_advisories(payload)
    entries: list[ListEntry] = []
    for advisory in advisories:
        entry = _entry_from_advisory(advisory, provider=provider, source_url=source_url)
        if entry is not None:
            entries.append(entry)
    return ListPage(
        page=page,
        entries=entries,
        total_pages=None,
        total_records=_extract_total_records(payload),
    )


def _extract_advisories(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        advisories = payload.get("advisories")
        if isinstance(advisories, list):
            return [dict(item) for item in advisories if isinstance(item, dict)]
        if payload.get("advisoryId"):
            return [dict(payload)]
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    return []


def _entry_from_advisory(
    advisory: dict[str, Any],
    *,
    provider: str,
    source_url: str | None,
) -> ListEntry | None:
    advisory_id = str(advisory.get("advisoryId") or "").strip()
    if not advisory_id:
        return None
    detail = parse_detail_response(advisory).to_dict()
    cve_ids = detail.get("cve_ids") if isinstance(detail, dict) else None
    cve_code = _top_level_cve_code(cve_ids if isinstance(cve_ids, list) else [])
    return ListEntry(
        identity=VulnerabilityId(type="CISCO", code=advisory_id),
        title=str(advisory.get("advisoryTitle") or advisory_id),
        vuln_type=_optional_str(advisory.get("sir")),
        disclosure_date=_optional_str(advisory.get("firstPublished")),
        status=_optional_str(advisory.get("status")),
        provider=provider,
        source_url=source_url,
        embedded_detail={**detail, "cve_id": cve_code},
    )


def _top_level_cve_code(cve_ids: list[str]) -> str | None:
    normalized = [normalize_cve_code(value) for value in cve_ids]
    clean = [value for value in normalized if value]
    if len(clean) == 1:
        return f"CVE-{clean[0]}"
    return None


def _extract_total_records(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    paging = payload.get("paging")
    if not isinstance(paging, dict):
        return None
    count = paging.get("count")
    try:
        return int(count)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
