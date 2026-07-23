from __future__ import annotations

from typing import Any

CANONICAL_SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")

_SEVERITY_ALIASES: dict[str, str] = {
    "1": "Critical",
    "超危": "Critical",
    "严重": "Critical",
    "critical": "Critical",
    "crit": "Critical",
    "2": "High",
    "高危": "High",
    "高": "High",
    "high": "High",
    "important": "High",
    "3": "Medium",
    "中危": "Medium",
    "中": "Medium",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "4": "Low",
    "低危": "Low",
    "低": "Low",
    "low": "Low",
    "informational": "Low",
    "info": "Low",
    "none": "Low",
}


def normalize_severity(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        text = str(int(value))
    else:
        text = str(value).strip()
    if not text:
        return None

    direct = _SEVERITY_ALIASES.get(text)
    if direct:
        return direct

    folded = text.casefold()
    direct = _SEVERITY_ALIASES.get(folded)
    if direct:
        return direct

    for prefix, canonical in (
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("moderate", "Medium"),
        ("low", "Low"),
    ):
        if folded.startswith(prefix):
            return canonical

    if any(char.isdigit() for char in text):
        return None
    return "Unknown"


def severity_from_record(record: dict[str, Any]) -> str | None:
    provider = str(record.get("type") or "").strip().lower()
    if not provider:
        return None

    details = record.get("details")
    detail = details.get(provider) if isinstance(details, dict) else None
    if not isinstance(detail, dict):
        detail = {}

    raw = _raw_severity_for_provider(provider, record, detail)
    return normalize_severity(raw)


def _raw_severity_for_provider(provider: str, document: dict[str, Any], detail: dict[str, Any]) -> Any:
    extractors: dict[str, Any] = {
        "avd": lambda: detail.get("danger_level"),
        "hkcert": lambda: detail.get("risk_level") or _first_nested(detail.get("table"), "risk_level"),
        "cve": lambda: _first_available(
            detail,
            (
                ("metrics", "cvss_v40", "cvssData", "baseSeverity"),
                ("metrics", "cvss_v31", "cvssData", "baseSeverity"),
                ("metrics", "cvss_v30", "cvssData", "baseSeverity"),
                ("metrics", "cvss_v2", "cvssData", "baseSeverity"),
                ("metrics", "cvss_v2", "baseSeverity"),
            ),
        ),
        "cisco": lambda: detail.get("sir"),
        "github_advisory": lambda: detail.get("severity"),
        "zeroday": lambda: None,
        "govcert": lambda: None,
        "infosec": lambda: None,
        "huawei_sa": lambda: detail.get("severity") or _path(detail, "raw", "severity"),
        "paloalto": lambda: detail.get("severity"),
        "qianxin": lambda: _first_non_empty(
            detail.get("level"),
            _path(detail, "description", "threat_assessment", "cvss_3_1_rating"),
            _path(detail, "description", "vulnerability_information", "risk", "qianxin_cert_rating"),
            _path(detail, "description", "vulnerability_information", "risk", "risk_level"),
        ),
        "ransomwarelive": lambda: None,
        "splunk": lambda: _first_non_empty(
            detail.get("severity"),
            detail.get("severity_summary"),
            detail.get("severity_detail"),
        ),
        "hikvision": lambda: detail.get("severity"),
        "cnnvd": lambda: _first_non_empty(detail.get("hazardLevel"), document.get("status")),
        "cnvd": lambda: _first_non_empty(document.get("status"), detail.get("severity")),
        "juniper": lambda: _path(detail, "raw_fields", "severity"),
        "msrc": lambda: _msrc_severity(detail),
    }
    extractor = extractors.get(provider)
    if extractor is None:
        return detail.get("severity") or document.get("status")
    return extractor()


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _first_available(detail: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> Any:
    for path in paths:
        value = _path(detail, *path)
        if _has_text(value):
            return value
    return None


def _first_nested(values: Any, field: str) -> Any:
    if not isinstance(values, list):
        return None
    for item in values:
        if isinstance(item, dict):
            value = item.get(field)
            if _has_text(value):
                return value
    return None


def _msrc_severity(detail: dict[str, Any]) -> Any:
    for severity in _values_at_paths(
        detail,
        (
            ("threats", "description"),
            ("raw", "Threats", "Description", "Value"),
        ),
    ):
        normalized = normalize_severity(severity)
        if normalized and normalized != "Unknown":
            return normalized

    score = _first_available(
        detail,
        (
            ("cvss", "base_score"),
            ("raw", "CVSSScoreSets", "BaseScore"),
        ),
    )
    return _severity_from_cvss_score(score)


def _values_at_paths(value: Any, paths: tuple[tuple[str, ...], ...]) -> list[Any]:
    values: list[Any] = []
    for path in paths:
        found = _path(value, *path)
        if isinstance(found, list):
            values.extend(found)
        elif found is not None:
            values.append(found)
    return values


def _severity_from_cvss_score(value: Any) -> str | None:
    if isinstance(value, list):
        for item in value:
            severity = _severity_from_cvss_score(item)
            if severity:
                return severity
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return None


def _path(value: Any, *parts: str) -> Any:
    nodes: list[Any] = [value]
    for part in parts:
        next_nodes: list[Any] = []
        for node in nodes:
            if isinstance(node, dict) and part in node:
                child = node[part]
                next_nodes.extend(child if isinstance(child, list) else [child])
        nodes = next_nodes
        if not nodes:
            return None
    return nodes[0] if len(nodes) == 1 else nodes


def _has_text(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True
