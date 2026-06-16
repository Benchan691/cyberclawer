from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any

from vuln_scraper.models import ListEntry, VulnerabilityId, normalize_cve_code


@dataclass(slots=True)
class MSRCMonthlyRecord:
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.raw)


def parse_cvrf_document(content: Any) -> MSRCMonthlyRecord:
    payload = _coerce_json(content)
    if not isinstance(payload, dict):
        raise ValueError("MSRC CVRF response was not a JSON object")
    return MSRCMonthlyRecord(raw=payload)


def expand_cvrf_document(
    entry: ListEntry,
    document: dict[str, Any],
    *,
    detail_url: str | None,
    provider: str = "msrc",
) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []

    product_names = _product_names(document.get("ProductTree"))
    tracking = document.get("DocumentTracking") if isinstance(document.get("DocumentTracking"), dict) else {}
    document_id = _path_text(tracking, "Identification", "ID", "Value") or entry.identity.code
    document_title = _path_text(document, "DocumentTitle", "Value") or entry.title
    initial_release_date = _clean(tracking.get("InitialReleaseDate"))
    current_release_date = _clean(tracking.get("CurrentReleaseDate")) or entry.disclosure_date
    status = _clean(tracking.get("Status")) or entry.status
    revision_history = tracking.get("RevisionHistory") if isinstance(tracking.get("RevisionHistory"), list) else []
    vulnerabilities = document.get("Vulnerability")
    if not isinstance(vulnerabilities, list):
        return []

    records: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve_id = _clean(vulnerability.get("CVE"))
        code = normalize_cve_code(cve_id)
        if code is None:
            continue
        detail = _detail_from_vulnerability(
            vulnerability,
            product_names=product_names,
            document_id=document_id,
            document_title=document_title,
            initial_release_date=initial_release_date,
            current_release_date=current_release_date,
            revision_history=revision_history,
            cvrf_url=detail_url,
        )
        title = detail.get("title") or cve_id or code
        record = ListEntry(
            identity=VulnerabilityId(type="MSRC", code=code),
            title=str(title),
            vuln_type=_first_threat_description(detail),
            disclosure_date=current_release_date or initial_release_date,
            status=status,
            provider=provider,
            source_url=entry.source_url,
        ).to_record(detail, detail_url=detail_url)
        records.append(record)
    return records


def _detail_from_vulnerability(
    vulnerability: dict[str, Any],
    *,
    product_names: dict[str, str],
    document_id: str | None,
    document_title: str | None,
    initial_release_date: str | None,
    current_release_date: str | None,
    revision_history: list[Any],
    cvrf_url: str | None,
) -> dict[str, Any]:
    notes = [_note(item) for item in _dict_items(vulnerability.get("Notes"))]
    cve_id = _clean(vulnerability.get("CVE"))
    detail: dict[str, Any] = {
        "cve_id": cve_id,
        "title": _path_text(vulnerability, "Title", "Value") or cve_id,
        "description": _description(notes),
        "cwe": [_cwe(item) for item in _dict_items(vulnerability.get("CWE"))],
        "product_statuses": [
            _product_status(item, product_names)
            for item in _dict_items(vulnerability.get("ProductStatuses"))
        ],
        "threats": [
            _threat(item, product_names)
            for item in _dict_items(vulnerability.get("Threats"))
        ],
        "remediations": [
            _remediation(item, product_names)
            for item in _dict_items(vulnerability.get("Remediations"))
        ],
        "acknowledgments": [
            _acknowledgment(item)
            for item in _dict_items(vulnerability.get("Acknowledgments"))
        ],
        "notes": notes,
        "cvss": [
            _cvss_score_set(item, product_names)
            for item in _dict_items(vulnerability.get("CVSSScoreSets"))
        ],
        "revision_history": revision_history,
        "initial_release_date": initial_release_date,
        "current_release_date": current_release_date,
        "document_id": document_id,
        "document_title": document_title,
        "cvrf_url": cvrf_url,
        "raw": dict(vulnerability),
    }
    return detail


def _note(item: dict[str, Any]) -> dict[str, Any]:
    value = _clean(item.get("Value"))
    return {
        "title": _clean(item.get("Title")),
        "type": _clean(item.get("Type")),
        "ordinal": _clean(item.get("Ordinal")),
        "value": _plain_text(value),
        "raw_value": value,
    }


def _cwe(item: dict[str, Any]) -> dict[str, Any]:
    return {"id": _clean(item.get("ID")), "value": _clean(item.get("Value"))}


def _product_status(item: dict[str, Any], product_names: dict[str, str]) -> dict[str, Any]:
    product_ids = _str_list(item.get("ProductID"))
    return {
        "type": _clean(item.get("Type")),
        "product_ids": product_ids,
        "product_names": _names_for_ids(product_ids, product_names),
    }


def _threat(item: dict[str, Any], product_names: dict[str, str]) -> dict[str, Any]:
    product_ids = _str_list(item.get("ProductID"))
    return {
        "type": _clean(item.get("Type")),
        "description": _path_text(item, "Description", "Value"),
        "date": _clean(item.get("Date")),
        "product_ids": product_ids,
        "product_names": _names_for_ids(product_ids, product_names),
    }


def _remediation(item: dict[str, Any], product_names: dict[str, str]) -> dict[str, Any]:
    product_ids = _str_list(item.get("ProductID"))
    return {
        "type": _clean(item.get("Type")),
        "date": _clean(item.get("Date")),
        "description": _path_text(item, "Description", "Value"),
        "url": _clean(item.get("URL")),
        "product_ids": product_ids,
        "product_names": _names_for_ids(product_ids, product_names),
    }


def _acknowledgment(item: dict[str, Any]) -> dict[str, Any]:
    names = item.get("Name")
    return {
        "names": [_clean(name.get("Value")) for name in names if isinstance(name, dict)]
        if isinstance(names, list)
        else [],
        "urls": [_clean(url.get("Value")) for url in item.get("URL", []) if isinstance(url, dict)]
        if isinstance(item.get("URL"), list)
        else [],
    }


def _cvss_score_set(item: dict[str, Any], product_names: dict[str, str]) -> dict[str, Any]:
    product_ids = _str_list(item.get("ProductID"))
    return {
        "base_score": _clean(item.get("BaseScore")),
        "temporal_score": _clean(item.get("TemporalScore")),
        "vector": _clean(item.get("Vector")),
        "product_ids": product_ids,
        "product_names": _names_for_ids(product_ids, product_names),
    }


def _product_names(product_tree: Any) -> dict[str, str]:
    names: dict[str, str] = {}
    _collect_product_names(product_tree, names)
    return names


def _collect_product_names(node: Any, names: dict[str, str]) -> None:
    if isinstance(node, list):
        for item in node:
            _collect_product_names(item, names)
        return
    if not isinstance(node, dict):
        return
    product_id = _clean(node.get("ProductID"))
    value = _clean(node.get("Value"))
    if product_id and value:
        names[product_id] = value
    for key in ("Branch", "Items", "FullProductName", "Relationship"):
        child = node.get(key)
        if child is not None:
            _collect_product_names(child, names)


def _names_for_ids(product_ids: list[str], product_names: dict[str, str]) -> list[str]:
    return [product_names[item] for item in product_ids if item in product_names]


def _description(notes: list[dict[str, Any]]) -> str | None:
    for note in notes:
        if str(note.get("title") or "").casefold() == "description":
            return _clean(note.get("value"))
    return None


def _first_threat_description(detail: dict[str, Any]) -> str | None:
    threats = detail.get("threats")
    if not isinstance(threats, list):
        return None
    for threat in threats:
        if isinstance(threat, dict) and threat.get("description"):
            return str(threat["description"])
    return None


def _dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _path_text(value: Any, *parts: str) -> str | None:
    node = value
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return _clean(node)


def _plain_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = re.sub(r"<[^>]+>", " ", value)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text or None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(content: Any) -> Any:
    if isinstance(content, str):
        return json.loads(content)
    return content
