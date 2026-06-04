from __future__ import annotations

import json
import math
import re
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.cnnvd.config import DEFAULT_PAGE_SIZE, SOURCE_URL


TITLE_TYPE_RE = re.compile(r"^【(?P<type>[^】]+)】(?P<title>.+)$")


def parse_warn_list(
    data: Any,
    *,
    page: int,
    provider: str = "cnnvd",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(data)
    container = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(container, dict):
        container = {}

    records = container.get("records") if isinstance(container.get("records"), list) else []
    entries = [
        entry
        for item in records
        if isinstance(item, dict)
        if (entry := _entry_from_item(item, provider=provider, source_url=source_url)) is not None
    ]
    total_records = _optional_int(container.get("total")) or len(entries)
    page_size = _optional_int(container.get("pageSize")) or DEFAULT_PAGE_SIZE
    total_pages = math.ceil(total_records / page_size) if total_records and page_size else None
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def _entry_from_item(item: dict[str, Any], *, provider: str, source_url: str | None) -> ListEntry | None:
    code = _optional_str(item.get("warnId") or item.get("id"))
    title = _optional_str(item.get("warnName") or item.get("title"))
    if not code or not title:
        return None

    alert_type, clean_title = _title_parts(title)
    published_date = _iso_date(_optional_str(item.get("publishTime") or item.get("published")))
    summary = _optional_str(item.get("contentStr") or item.get("summary"))
    detail_url = f"{SOURCE_URL}?warnId={code}"

    return ListEntry(
        identity=VulnerabilityId(type="CNNVD", code=code),
        title=clean_title,
        vuln_type=alert_type,
        disclosure_date=published_date,
        status=alert_type,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "warn_id": code,
            "alert_type": alert_type,
            "published_date": published_date,
            "created_by": _optional_str(item.get("createUname")),
            "summary": summary,
            "reference_links": [detail_url],
            "raw": dict(item),
        },
    )


def _title_parts(title: str) -> tuple[str | None, str]:
    match = TITLE_TYPE_RE.match(title.strip())
    if not match:
        return None, title.strip()
    return match.group("type").strip() or None, match.group("title").strip() or title.strip()


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"\d{4}-\d{1,2}-\d{1,2}", value)
    if not match:
        return value.strip() or None
    year, month, day = match.group(0).split("-")
    return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
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
