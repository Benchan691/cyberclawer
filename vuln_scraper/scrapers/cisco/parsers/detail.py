from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from vuln_scraper.models import normalize_cve_code


@dataclass(slots=True)
class CiscoDetailRecord:
    advisory_id: str | None = None
    advisory_title: str | None = None
    sir: str | None = None
    first_published: str | None = None
    last_updated: str | None = None
    status: str | None = None
    version: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    bug_ids: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    cvss_base_score: float | None = None
    product_names: list[str] = field(default_factory=list)
    publication_url: str | None = None
    cvrf_url: str | None = None
    csaf_url: str | None = None
    summary: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_response(data: Any) -> CiscoDetailRecord:
    payload = _coerce_json(data)
    advisory = _extract_advisory(payload)
    if advisory is None:
        raise ValueError("Cisco OpenVuln detail response did not contain advisory data")
    return _record_from_advisory(advisory)


def _extract_advisory(payload: Any) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        if isinstance(payload.get("advisory"), dict):
            return dict(payload["advisory"])
        advisories = payload.get("advisories")
        if isinstance(advisories, list) and advisories and isinstance(advisories[0], dict):
            return dict(advisories[0])
        if payload.get("advisoryId"):
            return dict(payload)
    return None


def _record_from_advisory(advisory: dict[str, Any]) -> CiscoDetailRecord:
    return CiscoDetailRecord(
        advisory_id=_optional_str(advisory.get("advisoryId")),
        advisory_title=_optional_str(advisory.get("advisoryTitle")),
        sir=_optional_str(advisory.get("sir")),
        first_published=_optional_str(advisory.get("firstPublished")),
        last_updated=_optional_str(advisory.get("lastUpdated")),
        status=_optional_str(advisory.get("status")),
        version=_optional_float(advisory.get("version")),
        cve_ids=_split_ids(advisory.get("cves"), normalize=True),
        bug_ids=_split_ids(advisory.get("bugIDs"), normalize=False),
        cwe=_split_ids(advisory.get("cwe"), normalize=False),
        cvss_base_score=_optional_float(advisory.get("cvssBaseScore")),
        product_names=_split_ids(advisory.get("productNames"), normalize=False),
        publication_url=_optional_str(advisory.get("publicationUrl")),
        cvrf_url=_optional_str(advisory.get("cvrfUrl")),
        csaf_url=_optional_str(advisory.get("csafUrl")),
        summary=_optional_str(advisory.get("summary")),
        raw=dict(advisory),
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _split_ids(value: Any, *, normalize: bool) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        parts = [item.strip() for item in str(value).split(",") if item.strip()]
    seen: set[str] = set()
    normalized: list[str] = []
    for part in parts:
        item = part
        if normalize:
            code = normalize_cve_code(part)
            item = f"CVE-{code}" if code else part.upper()
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return normalized


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
