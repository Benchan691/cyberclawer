from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from bs4 import Tag

from vuln_scraper.scrapers.splunk.config import BASE_URL
from vuln_scraper.scrapers.splunk.parsers.common import (
    clean_multiline,
    clean_text,
    cve_ids_from_text,
    normalize_key,
    soup,
    unique_links,
)


SECTION_KEYS = {
    "description": "description",
    "solution": "solution",
    "mitigations": "mitigations",
    "product_status": "product_status_text",
    "severity": "severity_detail",
    "credit": "credit",
}


@dataclass(slots=True)
class SplunkDetailRecord:
    advisory_id: str | None = None
    cve_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    published_date: str | None = None
    last_modified: str | None = None
    title: str | None = None
    cvss_vector: str | None = None
    cvss_score: str | None = None
    cwe: str | None = None
    bug_ids: list[str] = field(default_factory=list)
    affected_products: str | None = None
    fixed_versions: str | None = None
    affected_versions: str | None = None
    all_affected_versions: str | None = None
    affected_components: str | None = None
    description: str | None = None
    description_tables: list[dict[str, Any]] = field(default_factory=list)
    solution: str | None = None
    mitigations: str | None = None
    severity_summary: str | None = None
    severity_detail: str | None = None
    oss: str | None = None
    packages: list[dict[str, str | None]] = field(default_factory=list)
    product_status: list[dict[str, str | None]] = field(default_factory=list)
    tables: list[dict[str, Any]] = field(default_factory=list)
    credit: str | None = None
    reference_links: list[str] = field(default_factory=list)
    raw_fields: dict[str, str | None] = field(default_factory=dict)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> SplunkDetailRecord:
    parsed = soup(html)
    text = parsed.get_text("\n", strip=True)
    fields = _label_fields(parsed)
    sections = _sections(parsed)
    tables = _tables(parsed)
    section_tables = _section_tables(parsed)
    cve_ids = cve_ids_from_text("\n".join((text, "\n".join(_flatten_table_values(tables)))))

    return SplunkDetailRecord(
        advisory_id=fields.get("advisory_id"),
        cve_id=cve_ids[0] if cve_ids else None,
        cve_ids=cve_ids,
        published_date=fields.get("published"),
        last_modified=fields.get("last_update"),
        title=_title(parsed),
        cvss_vector=fields.get("cvss_vector"),
        cvss_score=fields.get("cvss_score"),
        cwe=fields.get("cwe"),
        bug_ids=_split_values(fields.get("bug")),
        affected_products=fields.get("affected_products"),
        fixed_versions=fields.get("fixed_versions"),
        affected_versions=fields.get("affected_versions"),
        all_affected_versions=fields.get("all_affected_versions"),
        affected_components=fields.get("affected_components"),
        description=sections.get("description"),
        description_tables=section_tables.get("description", []),
        solution=sections.get("solution"),
        mitigations=sections.get("mitigations"),
        severity_summary=fields.get("severity_summary"),
        severity_detail=sections.get("severity_detail"),
        oss=fields.get("oss"),
        packages=_classified_rows(tables, {"package", "remediation", "cve"}),
        product_status=_classified_rows(tables, {"product", "base_version", "affected_version"}),
        tables=_uncategorized_tables(tables),
        credit=sections.get("credit") or fields.get("credit"),
        reference_links=unique_links(parsed.find_all("a", href=True), base_url=BASE_URL),
        raw_fields=fields,
        raw_sections=sections,
    )


def _title(parsed) -> str | None:
    for selector in ("h1", "h2", "title"):
        text = clean_text(parsed.select_one(selector))
        if text:
            return text
    return None


def _label_fields(parsed) -> dict[str, str | None]:
    fields: dict[str, str | None] = {}
    lines = [line.strip().rstrip(":") for line in parsed.get_text("\n", strip=True).splitlines()]
    for index, line in enumerate(lines):
        key = normalize_key(line)
        if not key:
            continue
        value: str | None = None
        if ":" in line:
            label, inline_value = line.split(":", 1)
            key = normalize_key(label)
            value = inline_value.strip() or None
        elif index + 1 < len(lines):
            value = lines[index + 1].strip() or None
        if key and value and key not in fields:
            fields[key] = _none_if_na(value)
    return fields


def _sections(parsed) -> dict[str, str]:
    sections: dict[str, str] = {}
    for heading in parsed.find_all(["h2", "h3", "h4"]):
        key = SECTION_KEYS.get(normalize_key(clean_text(heading)))
        if key is None:
            continue
        chunks: list[str] = []
        for sibling in heading.next_siblings:
            if isinstance(sibling, Tag):
                if sibling.name in {"h2", "h3", "h4"}:
                    break
                if sibling.name == "table":
                    continue
                text = clean_multiline(sibling)
                if text:
                    chunks.append(text)
        text = "\n".join(chunks).strip()
        if text:
            sections[key] = text
    return sections


def _section_tables(parsed) -> dict[str, list[dict[str, Any]]]:
    section_tables: dict[str, list[dict[str, Any]]] = {}
    for heading in parsed.find_all(["h2", "h3", "h4"]):
        key = SECTION_KEYS.get(normalize_key(clean_text(heading)))
        if key is None:
            continue
        tables: list[dict[str, Any]] = []
        for sibling in heading.next_siblings:
            if isinstance(sibling, Tag):
                if sibling.name in {"h2", "h3", "h4"}:
                    break
                if sibling.name == "table":
                    parsed_table = _parse_table(sibling)
                    if parsed_table is not None:
                        tables.append(parsed_table)
                    continue
                for nested in sibling.find_all("table"):
                    parsed_table = _parse_table(nested)
                    if parsed_table is not None:
                        tables.append(parsed_table)
        if tables:
            section_tables[key] = tables
    return section_tables


def _tables(parsed) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    for table in parsed.find_all("table"):
        parsed_table = _parse_table(table)
        if parsed_table is not None:
            tables.append(parsed_table)
    return tables


def _parse_table(table: Tag) -> dict[str, Any] | None:
    headers = [normalize_key(clean_text(cell)) for cell in table.find_all("th")]
    if not headers:
        first_row = table.find("tr")
        headers = [normalize_key(clean_text(cell)) for cell in first_row.find_all("td")] if first_row else []
    rows: list[dict[str, str | None]] = []
    for row in table.find_all("tr"):
        cells = row.find_all("td", recursive=False)
        if not cells:
            continue
        item: dict[str, str | None] = {}
        for index, cell in enumerate(cells):
            key = headers[index] if index < len(headers) and headers[index] else f"column_{index + 1}"
            text = clean_multiline(cell) or clean_text(cell)
            item[key] = text or None
        if any(value for value in item.values()):
            rows.append(item)
    if not rows:
        return None
    return {"headers": headers, "rows": rows}


def _classified_rows(tables: list[dict[str, Any]], required_headers: set[str]) -> list[dict[str, str | None]]:
    rows: list[dict[str, str | None]] = []
    for table in tables:
        headers = set(table.get("headers", []))
        if required_headers.issubset(headers):
            rows.extend(table.get("rows", []))
    return rows


def _uncategorized_tables(tables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    uncategorized: list[dict[str, Any]] = []
    classified = ({"package", "remediation", "cve"}, {"product", "base_version", "affected_version"})
    for table in tables:
        headers = set(table.get("headers", []))
        if not any(required.issubset(headers) for required in classified):
            uncategorized.append(table)
    return uncategorized


def _flatten_table_values(tables: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for table in tables:
        for row in table.get("rows", []):
            values.extend(str(value) for value in row.values() if value)
    return values


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    parts = [part.strip() for part in value.replace("\n", ",").split(",")]
    return [part for part in parts if part and part.casefold() not in {"na", "n/a"}]


def _none_if_na(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return None if text.casefold() in {"", "na", "n/a", "none"} else text
