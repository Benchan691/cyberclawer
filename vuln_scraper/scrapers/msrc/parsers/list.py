from __future__ import annotations

import json
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.msrc.config import SOURCE_URL


def parse_update_list(
    content: Any,
    *,
    page: int,
    provider: str = "msrc",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(content)
    updates = _updates(payload)
    entries: list[ListEntry] = []
    for update in updates:
        entry = _entry_from_update(update, provider=provider, source_url=source_url)
        if entry is not None:
            entries.append(entry)

    return ListPage(
        page=page,
        entries=entries,
        total_pages=1 if entries else None,
        total_records=len(entries) if entries else None,
    )


def _entry_from_update(
    update: dict[str, Any],
    *,
    provider: str,
    source_url: str | None,
) -> ListEntry | None:
    update_id = _clean(update.get("ID")) or _clean(update.get("Alias"))
    if not update_id:
        return None

    title = _clean(update.get("DocumentTitle")) or update_id
    embedded_detail = {
        "_list_summary": True,
        "id": update_id,
        "alias": _clean(update.get("Alias")),
        "document_title": title,
        "severity": _clean(update.get("Severity")),
        "initial_release_date": _clean(update.get("InitialReleaseDate")),
        "current_release_date": _clean(update.get("CurrentReleaseDate")),
        "cvrf_url": _clean(update.get("CvrfUrl")),
    }
    return ListEntry(
        identity=VulnerabilityId(type="MSRC", code=update_id),
        title=title,
        vuln_type=None,
        disclosure_date=embedded_detail["current_release_date"],
        status=embedded_detail["severity"],
        provider=provider,
        source_url=source_url,
        embedded_detail=embedded_detail,
    )


def _updates(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        value = payload.get("value")
        if isinstance(value, list):
            return [dict(item) for item in value if isinstance(item, dict)]
        if payload.get("ID"):
            return [dict(payload)]
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    return []


def _coerce_json(content: Any) -> Any:
    if isinstance(content, str):
        return json.loads(content)
    return content


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
