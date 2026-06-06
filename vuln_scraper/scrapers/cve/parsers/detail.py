from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


METRIC_KEY_MAP = {
    "cvssV4_0": "cvss_v40",
    "cvssV3_1": "cvss_v31",
    "cvssV3_0": "cvss_v30",
    "cvssV2_0": "cvss_v2",
}


@dataclass(slots=True)
class CVEDetailRecord:
    cve_id: str | None = None
    title: str | None = None
    source_identifier: str | None = None
    published: str | None = None
    last_modified: str | None = None
    vuln_status: str | None = None
    descriptions: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    weaknesses: list[dict[str, Any]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    configurations: list[dict[str, Any]] = field(default_factory=list)
    affected: list[dict[str, Any]] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    cve_tags: list[Any] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_cve_detail_response(data: Any) -> CVEDetailRecord:
    payload = _coerce_json(data)
    if not isinstance(payload, dict) or not isinstance(payload.get("cveMetadata"), dict):
        raise ValueError("CVE v5 record did not contain cveMetadata")
    return parse_cve_detail(payload)


def parse_cve_detail(cve: dict[str, Any]) -> CVEDetailRecord:
    metadata = cve.get("cveMetadata") if isinstance(cve.get("cveMetadata"), dict) else {}
    containers = _containers(cve)
    affected = _combined_list(containers, "affected")
    return CVEDetailRecord(
        cve_id=_optional_str(metadata.get("cveId")),
        title=_first_container_text(containers, "title"),
        source_identifier=_optional_str(
            metadata.get("assignerShortName") or metadata.get("assignerOrgId")
        ),
        published=_optional_str(metadata.get("datePublished")),
        last_modified=_optional_str(metadata.get("dateUpdated")),
        vuln_status=_optional_str(metadata.get("state")),
        descriptions=_combined_list(containers, "descriptions"),
        metrics=_normalize_metrics(_combined_list(containers, "metrics")),
        weaknesses=_combined_list(containers, "problemTypes"),
        references=_dedupe_references(_combined_list(containers, "references")),
        configurations=_combined_list(containers, "cpeApplicability"),
        affected=affected,
        affected_products=_affected_product_lines(affected),
        cve_tags=_combined_values(containers, "tags"),
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
    normalized: dict[str, Any] = {}
    for metric in _list_of_dicts(metrics):
        for source_key, target_key in METRIC_KEY_MAP.items():
            cvss_data = metric.get(source_key)
            if not isinstance(cvss_data, dict):
                continue
            item = {
                key: value
                for key, value in metric.items()
                if key not in METRIC_KEY_MAP
            }
            item["cvssData"] = dict(cvss_data)
            normalized.setdefault(target_key, []).append(item)
    return normalized


def _containers(cve: dict[str, Any]) -> list[dict[str, Any]]:
    raw = cve.get("containers")
    if not isinstance(raw, dict):
        return []
    containers: list[dict[str, Any]] = []
    cna = raw.get("cna")
    if isinstance(cna, dict):
        containers.append(cna)
    adp = raw.get("adp")
    if isinstance(adp, list):
        containers.extend(item for item in adp if isinstance(item, dict))
    return containers


def _combined_list(containers: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    combined: list[dict[str, Any]] = []
    for container in containers:
        combined.extend(_list_of_dicts(container.get(key)))
    return combined


def _combined_values(containers: list[dict[str, Any]], key: str) -> list[Any]:
    combined: list[Any] = []
    for container in containers:
        value = container.get(key)
        if isinstance(value, list):
            combined.extend(value)
    return combined


def _first_container_text(containers: list[dict[str, Any]], key: str) -> str | None:
    for container in containers:
        text = _optional_str(container.get(key))
        if text:
            return text
    return None


def _affected_product_lines(affected: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for item in affected:
        vendor = _optional_str(item.get("vendor"))
        product = _optional_str(item.get("product"))
        base = " ".join(part for part in (vendor, product) if part)
        versions = _list_of_dicts(item.get("versions"))
        affected_versions = [
            line
            for version in versions
            if str(version.get("status") or "").casefold() == "affected"
            and (line := _affected_version_line(base, version))
        ]
        if affected_versions:
            lines.extend(affected_versions)
        elif str(item.get("defaultStatus") or "").casefold() == "affected" and base:
            lines.append(base)
    return list(dict.fromkeys(lines))


def _affected_version_line(base: str, version: dict[str, Any]) -> str:
    version_text = _optional_str(version.get("version"))
    less_than = _optional_str(version.get("lessThan"))
    less_than_equal = _optional_str(version.get("lessThanOrEqual"))
    version_type = _optional_str(version.get("versionType"))
    parts = [base, version_text]
    if less_than:
        parts.append(f"<{less_than}")
    if less_than_equal:
        parts.append(f"<={less_than_equal}")
    if version_type:
        parts.append(f"({version_type})")
    return " ".join(part for part in parts if part)


def _dedupe_references(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for reference in references:
        url = _optional_str(reference.get("url"))
        key = url or json.dumps(reference, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(reference)
    return deduped


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
