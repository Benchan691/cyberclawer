from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

try:
    from .cpe_dictionary import vendor_product_from_cpe
except ImportError:
    from cpe_dictionary import vendor_product_from_cpe


CPE_RE = re.compile(r"\bcpe:2\.3:[^\s\"'<>,)\]]+", re.IGNORECASE)


@dataclass(frozen=True)
class VendorProductEvidence:
    vendor: str | None = None
    product: str | None = None
    cpe: str | None = None
    text: str | None = None
    source: str = ""


def _cve_detail(document: dict[str, Any]) -> dict[str, Any]:
    detail = (document.get("details") or {}).get("cve") or {}
    return detail if isinstance(detail, dict) else {}


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


def extract_vendor_product_evidence(document: dict[str, Any]) -> list[VendorProductEvidence]:
    detail = _cve_detail(document)
    evidence: list[VendorProductEvidence] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(
        *,
        vendor: str | None = None,
        product: str | None = None,
        cpe: str | None = None,
        text: str | None = None,
        source: str,
    ) -> None:
        key = (
            (vendor or "").casefold(),
            (product or "").casefold(),
            (cpe or "").casefold(),
            (text or "").casefold(),
        )
        if key == ("", "", "", ""):
            return
        if key in seen:
            return
        seen.add(key)
        evidence.append(
            VendorProductEvidence(
                vendor=vendor,
                product=product,
                cpe=cpe,
                text=text,
                source=source,
            )
        )

    for field in ("configurations", "affected_products"):
        value = detail.get(field)
        for cpe in _iter_cpes(value):
            vendor, product = vendor_product_from_cpe(cpe)
            add(vendor=vendor or None, product=product or None, cpe=cpe, source=f"cve.{field}")

    affected = detail.get("affected")
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            vendor = str(item.get("vendor") or "").strip() or None
            product = str(item.get("product") or "").strip() or None
            if vendor or product:
                add(vendor=vendor, product=product, source="cve.affected")

    title = str(document.get("title") or "").strip()
    if title:
        add(text=title, source="title")

    description = english_description(detail)
    if description:
        add(text=description, source="cve.description")

    return evidence


def extract_cpe_evidence(document: dict[str, Any]) -> list[str]:
    detail = _cve_detail(document)
    if not detail:
        return []

    evidence: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            evidence.append(text)

    for field in ("configurations", "affected", "affected_products"):
        value = detail.get(field)
        for cpe in _iter_cpes(value):
            add(cpe)
        if field == "affected":
            for item in value if isinstance(value, list) else []:
                if isinstance(item, dict):
                    add(" ".join(str(item.get(key) or "").strip() for key in ("vendor", "product") if item.get(key)))
        elif isinstance(value, list):
            for item in value:
                if not isinstance(item, (dict, list)):
                    add(item)

    return evidence


def extract_embedding_evidence(document: dict[str, Any]) -> list[str]:
    evidence = extract_cpe_evidence(document)
    seen = set(evidence)
    detail = _cve_detail(document)
    for text in (str(document.get("title") or "").strip(), english_description(detail) or ""):
        if text and text not in seen:
            seen.add(text)
            evidence.append(text)
    return evidence


def _iter_cpes(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_cpes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_cpes(child)
    elif isinstance(value, str):
        yield from (match.group(0) for match in CPE_RE.finditer(value))
