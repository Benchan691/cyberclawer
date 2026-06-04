from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


METRIC_KEY_MAP = {
    "cvssMetricV40": "cvss_v40",
    "cvssMetricV31": "cvss_v31",
    "cvssMetricV30": "cvss_v30",
    "cvssMetricV2": "cvss_v2",
}


@dataclass(slots=True)
class CVEDetailRecord:
    cve_id: str | None = None
    source_identifier: str | None = None
    published: str | None = None
    last_modified: str | None = None
    vuln_status: str | None = None
    descriptions: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    weaknesses: list[dict[str, Any]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    configurations: list[dict[str, Any]] = field(default_factory=list)
    cve_tags: list[Any] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_cve_detail_response(data: Any) -> CVEDetailRecord:
    payload = _coerce_json(data)
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if isinstance(vulnerabilities, list) and vulnerabilities:
        first = vulnerabilities[0]
        if isinstance(first, dict) and isinstance(first.get("cve"), dict):
            return parse_cve_detail(first["cve"])
    if isinstance(payload, dict) and isinstance(payload.get("cve"), dict):
        return parse_cve_detail(payload["cve"])
    if isinstance(payload, dict):
        return parse_cve_detail(payload)
    raise ValueError("NVD CVE detail response did not contain a CVE object")


def parse_cve_detail(cve: dict[str, Any]) -> CVEDetailRecord:
    return CVEDetailRecord(
        cve_id=_optional_str(cve.get("id")),
        source_identifier=_optional_str(cve.get("sourceIdentifier")),
        published=_optional_str(cve.get("published")),
        last_modified=_optional_str(cve.get("lastModified")),
        vuln_status=_optional_str(cve.get("vulnStatus")),
        descriptions=_list_of_dicts(cve.get("descriptions")),
        metrics=_normalize_metrics(cve.get("metrics")),
        weaknesses=_list_of_dicts(cve.get("weaknesses")),
        references=_list_of_dicts(cve.get("references")),
        configurations=_list_of_dicts(cve.get("configurations")),
        cve_tags=list(cve.get("cveTags") or []),
        raw=dict(cve),
    )


def english_description(detail: dict[str, Any]) -> str | None:
    descriptions = detail.get("descriptions")
    if not isinstance(descriptions, list):
        return None

    for description in descriptions:
        if (
            isinstance(description, dict)
            and str(description.get("lang") or "").casefold() == "en"
            and description.get("value")
        ):
            return str(description["value"]).strip() or None

    for description in descriptions:
        if isinstance(description, dict) and description.get("value"):
            return str(description["value"]).strip() or None
    return None


def _normalize_metrics(metrics: Any) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        return {}
    normalized: dict[str, Any] = {}
    for source_key, value in metrics.items():
        target_key = METRIC_KEY_MAP.get(source_key, source_key)
        normalized[target_key] = value
    return normalized


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
