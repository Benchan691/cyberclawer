from __future__ import annotations

import json
import math
import re
from typing import Any

from vuln_scraper.client import CaptchaRequiredError
from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.cnnvd.config import DEFAULT_PAGE_SIZE, SOURCE_URL


HAZARD_LEVELS = {"1": "超危", "2": "高危", "3": "中危", "4": "低危"}
LEVELS = {"Critical": "超危", "High": "高危", "Medium": "中危", "Low": "低危", "None": "无风险"}


def parse_vulnerability_list(
    data: Any,
    *,
    page: int,
    provider: str = "cnnvd",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(data)
    if isinstance(payload, dict):
        _raise_if_captcha_required(payload)
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
    page_size = _optional_int(container.get("pageSize")) or _optional_int(container.get("size")) or DEFAULT_PAGE_SIZE
    total_pages = math.ceil(total_records / page_size) if total_records and page_size else None
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def _entry_from_item(item: dict[str, Any], *, provider: str, source_url: str | None) -> ListEntry | None:
    cnnvd_code = _optional_str(item.get("cnnvdId")) or _optional_str(item.get("cnnvdCode"))
    title = _optional_str(item.get("vulName"))
    if not cnnvd_code or not title:
        return None

    code = cnnvd_code.removeprefix("CNNVD-")
    hazard_level = _hazard_level(item.get("vulLevel")) or _hazard_level(item.get("hazardLevel"))
    vuln_type = (
        _optional_str(item.get("vulTypeName"))
        or _optional_str(item.get("typeName"))
        or _optional_str(item.get("vulType"))
    )
    embedded_detail = {key: _clean_text(value) for key, value in item.items()}
    embedded_detail["_list_summary"] = True

    return ListEntry(
        identity=VulnerabilityId(type="CNNVD", code=code),
        title=title,
        vuln_type=vuln_type,
        disclosure_date=_iso_date(_optional_str(item.get("publishDate")) or _optional_str(item.get("publishTime"))),
        status=hazard_level,
        provider=provider,
        source_url=source_url,
        embedded_detail=embedded_detail,
    )


def _hazard_level(value: Any) -> str | None:
    text = _optional_str(value)
    if text in (None, "0"):
        return None
    return HAZARD_LEVELS.get(text, LEVELS.get(text, text))


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
    text = _clean_text(value).strip()
    return text or None


def _clean_text(value: Any) -> Any:
    if isinstance(value, str):
        return re.sub(r"</?mark>", "", value)
    return value


def _raise_if_captcha_required(payload: dict[str, Any]) -> None:
    message = str(payload.get("message") or payload.get("msg") or "")
    code = str(payload.get("code") or "")
    if code == "4010" or "人机验证" in message:
        raise CaptchaRequiredError(f"CNNVD captcha required: {message or code}")


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
