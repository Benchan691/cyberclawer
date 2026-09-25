from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from vuln_scraper.scrapers.nvd.config import DETAIL_URL

CWE_RE = re.compile(r"\bCWE-\d+\b")
# Metric preference: newest CVSS version first, Primary source before Secondary.
METRIC_PREFERENCE = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass(slots=True)
class NvdDetailRecord:
    cve_id: str | None = None
    title: str | None = None
    description: str | None = None
    vuln_status: str | None = None
    severity: str | None = None
    base_score: float | None = None
    cvss_vector: str | None = None
    cvss: dict[str, Any] = field(default_factory=dict)
    published_date: str | None = None
    last_modified: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    source_identifier: str | None = None
    detail_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_cve_record(cve: dict[str, Any]) -> NvdDetailRecord:
    descriptions = [
        str(item.get("value") or "").strip()
        for item in cve.get("descriptions") or []
        if item.get("lang") == "en"
    ]
    description = next((text for text in descriptions if text), None)

    severity, base_score, cvss_vector, cvss_version = _parse_metrics(cve.get("metrics"))

    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = str(item.get("value") or "").strip()
            if value and value not in cwe_ids and CWE_RE.search(value):
                cwe_ids.append(value)

    references: list[str] = []
    for reference in cve.get("references") or []:
        url = str(reference.get("url") or "").strip()
        if url and url not in references:
            references.append(url)

    affected = _affected_products(cve)

    cve_id = str(cve.get("id") or "").strip()
    return NvdDetailRecord(
        cve_id=cve_id or None,
        title=description or cve_id or None,
        description=description,
        vuln_status=str(cve.get("vulnStatus") or "").strip() or None,
        severity=severity,
        base_score=base_score,
        cvss_vector=cvss_vector,
        # Nested so consumers (e.g. the newsletter renderer's cvss walker)
        # can render vector, score and severity together.
        cvss={
            "vector_string": cvss_vector or "",
            "base_score": base_score if base_score is not None else "",
            "base_severity": severity or "",
            "version": cvss_version or "",
        },
        published_date=_date_part(cve.get("published")),
        last_modified=_date_part(cve.get("lastModified")),
        cwe_ids=cwe_ids,
        reference_links=references,
        affected_products=affected,
        source_identifier=str(cve.get("sourceIdentifier") or "").strip() or None,
        detail_url=f"{DETAIL_URL}/{cve_id}" if cve_id else None,
    )


def _parse_metrics(metrics: dict[str, Any] | None) -> tuple[str | None, float | None, str | None, str | None]:
    if not metrics:
        return None, None, None, None
    for key in METRIC_PREFERENCE:
        entries = metrics.get(key) or []
        primary = next((entry for entry in entries if entry.get("type") == "Primary"), None)
        entry = primary or (entries[0] if entries else None)
        if not entry:
            continue
        cvss_data = entry.get("cvssData") or {}
        severity = str(cvss_data.get("baseSeverity") or entry.get("baseSeverity") or "").strip() or None
        version = str(cvss_data.get("version") or "").strip() or None
        return severity, _as_float(cvss_data.get("baseScore")), str(cvss_data.get("vectorString") or "").strip() or None, version
    return None, None, None, None


def _affected_products(cve: dict[str, Any]) -> list[str]:
    products: list[str] = []
    # CPE 2.3 criteria from configurations (NVD enrichment).
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "").strip()
                if criteria and criteria not in products:
                    products.append(criteria)
    # CVE List v5 "affected" blocks (CNA-provided).
    for item in cve.get("affected") or []:
        vendor = str(item.get("vendor") or "").strip()
        product = str(item.get("product") or "").strip()
        rendered = f"{vendor}:{product}" if vendor and product else (product or vendor)
        if rendered and rendered not in products:
            products.append(rendered)
    return products


def _date_part(value: Any) -> str | None:
    text = str(value or "").strip()
    return text.split("T", 1)[0] or None if text else None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
