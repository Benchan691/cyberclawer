from __future__ import annotations

import base64
import json
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.ransomwarelive.config import SOURCE_URL
from vuln_scraper.scrapers.ransomwarelive.parsers.detail import parse_victim_response


def parse_recent_victims(
    data: Any,
    *,
    page: int,
    provider: str = "ransomwarelive",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    payload = _coerce_json(data)
    victims = _extract_victims(payload)
    entries: list[ListEntry] = []
    for victim in victims:
        entry = _entry_from_victim(victim, provider=provider, source_url=source_url)
        if entry is not None:
            entries.append(entry)
    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=len(entries),
    )


def _entry_from_victim(
    victim: dict[str, Any],
    *,
    provider: str,
    source_url: str | None,
) -> ListEntry | None:
    detail = parse_victim_response(victim).to_dict()
    victim_name = detail.get("victim")
    group = detail.get("group")
    code = _victim_id(victim, victim_name=victim_name, group=group)
    if not code:
        return None
    return ListEntry(
        identity=VulnerabilityId(type="RANSOMWARELIVE", code=code),
        title=str(victim_name or code),
        vuln_type=_optional_str(detail.get("activity")),
        disclosure_date=_optional_str(detail.get("discovered") or detail.get("attackdate")),
        status=_optional_str(group),
        provider=provider,
        source_url=source_url,
        embedded_detail=detail,
    )


def _victim_id(victim: dict[str, Any], *, victim_name: Any, group: Any) -> str | None:
    raw_id = _optional_str(victim.get("id"))
    if raw_id:
        return raw_id
    victim_text = _optional_str(victim_name)
    group_text = _optional_str(group)
    if not victim_text or not group_text:
        return None
    raw = f"{victim_text}@{group_text}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _extract_victims(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("victims", "results", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [dict(item) for item in value if isinstance(item, dict)]
        for key in ("data", "result", "response"):
            value = payload.get(key)
            victims = _extract_victims(value)
            if victims:
                return victims
        if payload.get("id") or payload.get("victim") or payload.get("post_title"):
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
