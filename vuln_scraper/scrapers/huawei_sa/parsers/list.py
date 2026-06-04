from __future__ import annotations

from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.huawei_sa.config import SOURCE_URL


STATUS = "NEW"


def parse_advisories_payload(
    content: Any,
    *,
    page: int,
    provider: str = "huawei_sa",
    source_url: str | None = None,
) -> ListPage:
    payload = _payload_dict(content)
    if payload is None:
        return ListPage(page=page, entries=[], total_pages=None, total_records=None)

    data = _data_items(payload)
    entries: list[ListEntry] = []
    for advisory in data:
        entry = _entry_from_advisory(advisory, provider=provider, source_url=source_url or SOURCE_URL)
        if entry is not None:
            entries.append(entry)

    page_info = payload.get("page") if isinstance(payload, dict) else None
    return ListPage(
        page=page,
        entries=entries,
        total_pages=_int_value(page_info, "totalPages"),
        total_records=_int_value(page_info, "total") or len(entries),
    )


def _payload_dict(content: Any) -> dict[str, Any] | None:
    if isinstance(content, list):
        return {"data": content, "page": {"totalPages": 1, "total": len(content)}}
    if not isinstance(content, dict):
        return None

    status = content.get("status")
    if status is not None and str(status) != "200":
        message = content.get("message") or content.get("error") or status
        raise RuntimeError(f"Huawei SA API error: {message}")
    return content


def _data_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _entry_from_advisory(
    advisory: dict[str, Any],
    *,
    provider: str,
    source_url: str | None,
) -> ListEntry | None:
    sasn_no = _clean(advisory.get("sasnNo"))
    if not sasn_no:
        return None

    title = _clean(advisory.get("title")) or sasn_no
    detail = dict(advisory)
    detail["cve_ids"] = _cve_ids(advisory)

    return ListEntry(
        identity=VulnerabilityId(type="HUAWEI_SA", code=sasn_no),
        title=title,
        vuln_type=_clean(advisory.get("type")),
        disclosure_date=_clean(advisory.get("publishDate")),
        status=STATUS,
        provider=provider,
        source_url=source_url,
        embedded_detail=detail,
    )


def _cve_ids(advisory: dict[str, Any]) -> list[str]:
    cves: list[str] = []
    vul = advisory.get("vul")
    if not isinstance(vul, list):
        return cves

    for item in vul:
        if not isinstance(item, dict):
            continue
        cve = _clean(item.get("cveId"))
        if cve and cve.upper().startswith("CVE-") and cve not in cves:
            cves.append(cve)
    return cves


def _int_value(payload: Any, key: str) -> int | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
