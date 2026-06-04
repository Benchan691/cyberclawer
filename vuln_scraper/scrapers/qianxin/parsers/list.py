from __future__ import annotations

import json
import math
import re
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.qianxin.config import DEFAULT_PAGE_SIZE, DETAIL_URL, SOURCE_URL


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.IGNORECASE)
TITLE_STATUS_RE = re.compile(r"^【(?P<status>[^】]+)】(?P<title>.+)$")


def parse_article_notice_list(
    data: Any,
    *,
    page: int,
    provider: str = "qianxin",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(data)
    container = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(container, dict):
        container = {}

    records = container.get("data") if isinstance(container.get("data"), list) else []
    entries = [
        entry
        for item in records
        if isinstance(item, dict)
        if (entry := _entry_from_item(item, provider=provider, source_url=source_url)) is not None
    ]
    total_records = _optional_int(container.get("total")) or len(entries)
    total_pages = math.ceil(total_records / DEFAULT_PAGE_SIZE) if total_records else None
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def _entry_from_item(item: dict[str, Any], *, provider: str, source_url: str | None) -> ListEntry | None:
    code = _optional_str(item.get("id"))
    title = _optional_str(item.get("title"))
    if not code or not title:
        return None

    threat_status, clean_title = _title_parts(title)
    category = _optional_str(item.get("category"))
    level = _optional_str(item.get("level"))
    digest = _clean_text(item.get("digest"))
    update_time = _optional_str(item.get("update_time"))
    detail_url = f"{DETAIL_URL}/{code}?type=risk"
    text_for_ids = "\n".join(value for value in (title, digest) if value)

    return ListEntry(
        identity=VulnerabilityId(type="QIANXIN", code=code),
        title=clean_title,
        vuln_type=category,
        disclosure_date=_iso_date(update_time),
        status=level,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "article_id": code,
            "title": clean_title,
            "threat_status": threat_status,
            "category": category,
            "level": level,
            "author": _optional_str(item.get("author")),
            "digest": digest,
            "cover_url": _optional_str(item.get("cover")),
            "read_num": _optional_int(item.get("read_num")),
            "updated_at": update_time,
            "updated_date": _iso_date(update_time),
            "vuln_ids": _split_ids(item.get("vuln_ids")),
            "cve_ids": _cve_ids(text_for_ids),
            "reference_links": [detail_url],
            "raw": dict(item),
        },
    )


def _title_parts(title: str) -> tuple[str | None, str]:
    match = TITLE_STATUS_RE.match(title.strip())
    if not match:
        return None, title.strip()
    return match.group("status").strip() or None, match.group("title").strip() or title.strip()


def _split_ids(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = _optional_str(value)
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,，;；\s]+", text) if part.strip()]


def _cve_ids(text: str) -> list[str]:
    result: list[str] = []
    for cve_id in CVE_RE.findall(text):
        normalized = cve_id.upper()
        if normalized not in result:
            result.append(normalized)
    return result


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"\d{4}-\d{1,2}-\d{1,2}", value)
    if not match:
        return value.strip() or None
    year, month, day = match.group(0).split("-")
    return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"


def _clean_text(value: Any) -> str | None:
    text = _optional_str(value)
    return " ".join(text.replace("\xa0", " ").split()) if text else None


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
