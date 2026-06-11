from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.hikvision.config import BASE_URL
from vuln_scraper.table_extractor import _table_grid


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
DATE_RE = re.compile(r"\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{4}|[A-Z][a-z]+ \d{1,2}, \d{4}")
HSRC_ID_RE = re.compile(r"\bHSRC-\d{4,6}-\d+\b", re.IGNORECASE)
TITLE_SELECTOR = ".common-title.aem-GridColumn.aem-GridColumn--default--12"
SUMMARY_SELECTOR = ".rte.fixed-width-container.aem-GridColumn.aem-GridColumn--default--12"
BASE_SCORE_RE = re.compile(
    r"Base score\s*[:：]\s*([\d.]+)\s*\(([^)]+)\)",
    re.IGNORECASE,
)

SECTION_LABELS = {
    "summary",
    "cve id",
    "scoring",
    "affected versions and fix",
    "description",
    "overview",
    "affected products",
    "affected versions",
    "affected product",
    "solution",
    "remediation",
    "mitigation",
    "recommendation",
    "obtaining fixed version",
    "source of vulnerability information",
}

METADATA_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^SN No\.?\s*:?\s*(.+)$", re.IGNORECASE), "sn_no"),
    (re.compile(r"^Edit\s*:?\s*(.+)$", re.IGNORECASE), "edit"),
    (re.compile(r"^Published by\s*:?\s*(.+)$", re.IGNORECASE), "edit"),
    (re.compile(r"^Initial Release Date\s*:?\s*(.+)$", re.IGNORECASE), "initial_release_date"),
    (re.compile(r"^Published Date\s*:?\s*(.+)$", re.IGNORECASE), "published_date"),
    (re.compile(r"^Published at\s*:?\s*(.+)$", re.IGNORECASE), "published_date"),
    (re.compile(r"^Updated Date\s*:?\s*(.+)$", re.IGNORECASE), "updated_date"),
    (re.compile(r"^Last Updated\s*:?\s*(.+)$", re.IGNORECASE), "updated_date"),
)


@dataclass(slots=True)
class HikvisionDetailRecord:
    advisory_id: str | None = None
    title: str | None = None
    sn_no: str | None = None
    edit: str | None = None
    initial_release_date: str | None = None
    published_date: str | None = None
    updated_date: str | None = None
    severity: str | None = None
    summary: str | None = None
    description: str | None = None
    affected_products: list[str] = field(default_factory=list)
    affected_versions_and_fix: list[dict[str, str]] = field(default_factory=list)
    solution: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    scoring: list[dict[str, str]] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> HikvisionDetailRecord:
    parsed = _soup(html)
    text = _clean_multiline(parsed)
    title = _title(parsed)
    root = _content_root(parsed)
    article = parsed.select_one("article") or parsed
    metadata = _parse_metadata(article)
    labeled_sections, tables = _parse_labeled_content(root)
    heading_sections = _sections(parsed)
    sections = {**heading_sections, **labeled_sections}

    sn_no = metadata.get("sn_no")
    advisory_id = _advisory_id_from_sn(sn_no) or _advisory_id(parsed, title)
    published_date = (
        metadata.get("initial_release_date")
        or metadata.get("published_date")
        or _date_from_labels(text, ("published", "release date", "date"))
    )
    updated_date = metadata.get("updated_date") or _date_from_labels(
        text, ("updated", "last updated", "update date")
    )
    summary = _summary_text(sections, root)
    cve_section = sections.get("cve id")
    cve_ids = _cve_ids(cve_section) if cve_section else _cve_ids(text)
    scoring = _parse_scoring(sections.get("scoring"))
    affected_versions_and_fix = tables.get("affected versions and fix", [])
    affected_products = _affected_products(sections, affected_versions_and_fix)

    return HikvisionDetailRecord(
        advisory_id=advisory_id,
        title=title,
        sn_no=sn_no,
        edit=metadata.get("edit"),
        initial_release_date=metadata.get("initial_release_date"),
        published_date=published_date,
        updated_date=updated_date,
        severity=_severity(text),
        summary=summary,
        description=_section_by_names(sections, ("description", "overview", "summary")) or text or None,
        affected_products=affected_products,
        affected_versions_and_fix=affected_versions_and_fix,
        solution=_section_by_names(sections, ("solution", "remediation", "mitigation", "recommendation")),
        cve_ids=cve_ids,
        scoring=scoring,
        reference_links=_reference_links(parsed),
        raw_sections=sections,
    )


def _content_root(parsed: BeautifulSoup) -> Tag:
    return parsed.select_one(SUMMARY_SELECTOR) or parsed.select_one("article") or parsed


def _parse_metadata(container: Tag) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for paragraph in container.find_all("p"):
        if paragraph.find_parent("table"):
            continue
        text = _clean_text(paragraph)
        for pattern, key in METADATA_PATTERNS:
            match = pattern.match(text)
            if not match:
                continue
            value = match.group(1).strip()
            if key.endswith("_date"):
                value = _iso_date(value) or value
            metadata[key] = value
    return metadata


def _parse_labeled_content(root: Tag) -> tuple[dict[str, str], dict[str, list[dict[str, str]]]]:
    sections: dict[str, list[str]] = {}
    tables: dict[str, list[dict[str, str]]] = {}
    current_section: str | None = None

    for node in root.find_all(["p", "table", "h2", "h3", "h4", "ul", "ol", "pre"]):
        if node.find_parent("table") and node.name != "table":
            continue

        if node.name == "table":
            section_key = current_section or "affected versions and fix"
            records = _table_records(node)
            if records:
                tables.setdefault(section_key, []).extend(records)
            continue

        if node.name in {"h2", "h3", "h4"}:
            current_section = _normalize_key(_clean_text(node).rstrip(":"))
            sections.setdefault(current_section, [])
            continue

        if node.name in {"ul", "ol"}:
            if current_section:
                items = [_clean_text(item) for item in node.find_all("li")]
                sections[current_section].extend(item for item in items if item)
            continue

        text = _clean_multiline(node)
        if not text:
            continue

        metadata_key = _metadata_key(text)
        if metadata_key:
            continue

        label = _paragraph_section_label(node, text)
        if label:
            current_section = label
            sections.setdefault(current_section, [])
            continue

        if current_section:
            sections[current_section].append(text)

    flattened_sections = {
        key: "\n".join(chunks).strip()
        for key, chunks in sections.items()
        if chunks
    }
    return flattened_sections, tables


def _paragraph_section_label(node: Tag, text: str) -> str | None:
    strong = node.select_one("strong, b")
    if strong is not None:
        label_text = _clean_text(strong)
        if label_text and label_text == text:
            normalized = _normalize_key(label_text.rstrip(":"))
            if normalized in SECTION_LABELS:
                return normalized
    normalized = _normalize_key(text.rstrip(":"))
    if normalized in SECTION_LABELS:
        return normalized
    return None


def _metadata_key(text: str) -> str | None:
    for pattern, key in METADATA_PATTERNS:
        if pattern.match(text):
            return key
    return None


def _table_records(table: Tag) -> list[dict[str, str]]:
    grid = _table_grid(table)
    if len(grid) < 2:
        return []
    headers = [header.strip() for header in grid[0]]
    if not any(headers):
        return []
    records: list[dict[str, str]] = []
    for row in grid[1:]:
        if not any(cell.strip() for cell in row):
            continue
        record = {
            headers[index]: row[index].strip()
            for index in range(min(len(headers), len(row)))
            if headers[index]
        }
        if record:
            records.append(record)
    return records


def _parse_scoring(section_text: str | None) -> list[dict[str, str]]:
    if not section_text:
        return []

    entries: list[dict[str, str]] = []
    lines = [line.strip() for line in section_text.splitlines() if line.strip()]
    index = 0
    while index < len(lines):
        if not CVE_RE.fullmatch(lines[index]):
            index += 1
            continue
        cve_id = lines[index].upper()
        details: list[str] = []
        index += 1
        while index < len(lines) and not CVE_RE.fullmatch(lines[index]):
            details.append(lines[index])
            index += 1
        entry = {"cve_id": cve_id}
        if details:
            entry["text"] = " ".join(details)
        for detail in details:
            match = BASE_SCORE_RE.search(detail)
            if match:
                entry["base_score"] = match.group(1)
                entry["vector"] = match.group(2)
        entries.append(entry)
    return entries


def _summary_text(sections: dict[str, str], root: Tag) -> str | None:
    summary = sections.get("summary")
    if summary:
        return summary
    candidates: list[str] = []
    for node in root.find_all("p"):
        if node.find_parent("table"):
            continue
        text = _clean_multiline(node)
        if not text or _metadata_key(text) or _paragraph_section_label(node, text):
            continue
        if node.find_previous(["h2", "h3", "h4"]) is not None:
            break
        candidates.append(text)
    if not candidates:
        return None
    long_candidates = [text for text in candidates if len(text) > 40]
    if long_candidates:
        return long_candidates[0]
    return candidates[-1]


def _affected_products(
    sections: dict[str, str],
    affected_versions_and_fix: list[dict[str, str]],
) -> list[str]:
    if affected_versions_and_fix:
        products: list[str] = []
        for row in affected_versions_and_fix:
            product = next(
                (value for key, value in row.items() if _normalize_key(key) == "product name"),
                "",
            )
            affected = next(
                (
                    value
                    for key, value in row.items()
                    if _normalize_key(key) in {"affected versions", "affected version"}
                ),
                "",
            )
            fixed = next(
                (
                    value
                    for key, value in row.items()
                    if _normalize_key(key) in {"fixed version", "fix version"}
                ),
                "",
            )
            parts = [part for part in (product, affected, fixed and f"fixed {fixed}") if part]
            if parts:
                rendered = " — ".join(parts[:2]) if len(parts) >= 2 else parts[0]
                if len(parts) == 3 and fixed:
                    rendered = f"{product}: {affected} (fixed {fixed})"
                products.append(rendered)
        return products

    section_value = _section_by_names(
        sections,
        ("affected products", "affected versions", "affected product"),
    )
    return _lines(section_value)


def _advisory_id_from_sn(sn_no: str | None) -> str | None:
    if not sn_no:
        return None
    match = HSRC_ID_RE.search(sn_no)
    return match.group(0).upper() if match else None


def _title(parsed: BeautifulSoup) -> str | None:
    for selector in (TITLE_SELECTOR, "h1", ".page-title", ".article-title", "h2", "title"):
        text = _clean_text(parsed.select_one(selector))
        if text:
            return text
    return None


def _advisory_id(parsed: BeautifulSoup, title: str | None) -> str | None:
    text = "\n".join([title or "", _clean_multiline(parsed)])
    match = HSRC_ID_RE.search(text)
    if match:
        return match.group(0).upper()
    for pattern in (r"\bHIKVISION[-\s]SA[-\s]\d{4}[-\s]\d+\b",):
        legacy = re.search(pattern, text, re.IGNORECASE)
        if legacy:
            return legacy.group(0).upper().replace(" ", "-")
    return None


def _sections(parsed: BeautifulSoup) -> dict[str, str]:
    sections: dict[str, str] = {}
    for heading in parsed.find_all(["h2", "h3", "h4"]):
        key = _normalize_key(_clean_text(heading).rstrip(":"))
        if not key:
            continue
        chunks: list[str] = []
        for sibling in heading.next_siblings:
            if isinstance(sibling, Tag):
                if sibling.name in {"h2", "h3", "h4"}:
                    break
                text = _clean_multiline(sibling)
                if text:
                    chunks.append(text)
        if chunks:
            sections[key] = "\n".join(chunks).strip()
    return sections


def _section_by_names(sections: dict[str, str], names: tuple[str, ...]) -> str | None:
    normalized = {_normalize_key(name) for name in names}
    for key, value in sections.items():
        if key in normalized:
            return value
    return None


def _date_from_labels(text: str, labels: tuple[str, ...]) -> str | None:
    lowered = text.casefold()
    for label in labels:
        index = lowered.find(label)
        if index < 0:
            continue
        match = DATE_RE.search(text[index : index + 120])
        if match:
            return _iso_date(match.group(0))
    match = DATE_RE.search(text)
    return _iso_date(match.group(0)) if match and "date" in labels else None


def _severity(text: str) -> str | None:
    upper = text.upper()
    for value in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if value in upper:
            return value.title()
    return None


def _reference_links(parsed: BeautifulSoup) -> list[str]:
    links: list[str] = []
    for link in parsed.find_all("a", href=True):
        href = str(link.get("href") or "").strip()
        if href and not href.startswith(("mailto:", "javascript:")):
            url = urljoin(BASE_URL, href)
            if url not in links:
                links.append(url)
    return links


def _cve_ids(text: str) -> list[str]:
    result: list[str] = []
    for cve_id in CVE_RE.findall(text):
        normalized = cve_id.upper()
        if normalized not in result:
            result.append(normalized)
    return result


def _lines(value: str | None) -> list[str]:
    if not value:
        return []
    return [line.strip() for line in value.splitlines() if line.strip()]


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if "-" in text:
        year, month, day = text.split("-")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    if "/" in text:
        month, day, year = text.split("/")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    return text


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _clean_text(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text(" ", strip=True)
    else:
        text = str(node)
    return " ".join(text.replace("\xa0", " ").split())


def _clean_multiline(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text("\n", strip=True)
    else:
        text = str(node)
    lines = [" ".join(line.replace("\xa0", " ").split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "lxml")
