from __future__ import annotations

import json
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.github_advisory.config import SOURCE_URL
from vuln_scraper.scrapers.github_advisory.parsers.detail import ghsa_code, record_from_advisory


def parse_advisory_list(
    data: Any,
    *,
    page: int,
    provider: str = "github_advisory",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(data)
    advisories = _extract_advisories(payload)
    entries: list[ListEntry] = []
    for advisory in advisories:
        entry = _entry_from_advisory(advisory, provider=provider, source_url=source_url)
        if entry is not None:
            entries.append(entry)
    total_pages = page if len(entries) == 0 else None
    return ListPage(page=page, entries=entries, total_pages=total_pages)


def _entry_from_advisory(
    advisory: dict[str, Any],
    *,
    provider: str,
    source_url: str | None,
) -> ListEntry | None:
    code = ghsa_code(advisory.get("ghsa_id"))
    if not code:
        return None
    detail = record_from_advisory(advisory).to_dict()
    return ListEntry(
        identity=VulnerabilityId(type="GHSA", code=code),
        title=str(advisory.get("summary") or advisory.get("ghsa_id") or code),
        vuln_type=_optional_str(advisory.get("type")),
        disclosure_date=_optional_str(advisory.get("published_at")),
        status=_optional_str(advisory.get("severity")),
        provider=provider,
        source_url=source_url,
        embedded_detail=detail,
    )


def _extract_advisories(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("advisories", "items", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [dict(item) for item in value if isinstance(item, dict)]
        if payload.get("ghsa_id"):
            return [dict(payload)]
    return []


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
