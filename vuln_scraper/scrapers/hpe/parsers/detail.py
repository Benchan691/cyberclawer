from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.hpe.config import BASE_URL


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
SECTION_PREFIXES = {
    "vulnerability_summary": "vulnerability.summary",
    "supported_software_versions": "supported.software.versions",
    "background": "background",
    "resolution": "resolution",
}
SUMMARY_LABELS = {
    "summary": "summary",
    "affected products": "affected_products",
    "unaffected products": "unaffected_products",
    "details": "details",
    "workaround": "workaround",
    "exploitation and public discussion": "exploitation_and_public_discussion",
    "references": "references",
}


@dataclass(slots=True)
class HPEDetailRecord:
    bulletin_id: str | None = None
    doc_id: str | None = None
    doc_display_url: str | None = None
    title: str | None = None
    document_subtype: str | None = None
    last_updated: str | None = None
    release_date: str | None = None
    document_version: str | None = None
    severity: str | None = None
    potential_security_impact: str | None = None
    source: str | None = None
    summary: str | None = None
    affected_products: str | None = None
    unaffected_products: str | None = None
    details: str | None = None
    workaround: str | None = None
    exploitation_and_public_discussion: str | None = None
    references: str | None = None
    supported_versions: str | None = None
    supported_software_versions: str | None = None
    background: str | None = None
    resolution: str | None = None
    history: str | None = None
    cvss_text: str | None = None
    cvss_entries: list[dict[str, str | None]] = field(default_factory=list)
    cve_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)
    tables: list[dict[str, Any]] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> HPEDetailRecord:
    parsed = BeautifulSoup(html, "lxml")
    root = parsed.select_one("#docDisplayForSearch") or parsed
    metadata = _metadata(root)
    title = _title(root)
    blocks = {
        key: _section_blocks(root, prefix)
        for key, prefix in SECTION_PREFIXES.items()
    }
    reference_blocks = _section_blocks(root, "reference.number")
    raw_sections = _raw_sections(blocks, reference_blocks)
    summary_sections = _summary_sections(blocks["vulnerability_summary"])
    tables = _tables(root)
    all_text = root.get_text("\n", strip=True)
    cve_ids = _unique_cves("\n".join((all_text, _table_text(tables))))
    cvss_text = _cvss_text(all_text, tables)
    cvss_entries = _cvss_entries(tables)
    doc_id = metadata.get("document_id")
    resolution = _block_text(blocks["resolution"][:1])
    supported_versions = raw_sections.get("supported_software_versions")
    history = _history(blocks["resolution"])

    return HPEDetailRecord(
        bulletin_id=_bulletin_id(title, doc_id),
        doc_id=doc_id,
        title=title,
        document_subtype=metadata.get("document_subtype"),
        last_updated=metadata.get("last_updated"),
        release_date=metadata.get("release_date"),
        document_version=metadata.get("document_version"),
        severity=_severity(all_text),
        potential_security_impact=_value_after_label(
            _block_text(_section_blocks(root, "potential_security_impact")),
            "Potential Security Impact",
        ),
        source=_value_after_label(
            _block_text(_section_blocks(root, "source")),
            "Source",
        ),
        summary=summary_sections.get("summary"),
        affected_products=summary_sections.get("affected_products"),
        unaffected_products=summary_sections.get("unaffected_products"),
        details=summary_sections.get("details"),
        workaround=summary_sections.get("workaround"),
        exploitation_and_public_discussion=summary_sections.get("exploitation_and_public_discussion"),
        references=summary_sections.get("references") or raw_sections.get("references"),
        supported_versions=supported_versions,
        supported_software_versions=supported_versions,
        background=raw_sections.get("background"),
        resolution=resolution,
        history=history,
        cvss_text=cvss_text,
        cvss_entries=cvss_entries,
        cve_id=cve_ids[0] if cve_ids else None,
        cve_ids=cve_ids,
        reference_links=_links(root),
        tables=tables,
        raw_sections=raw_sections,
    )


def parse_document(html: str) -> HPEDetailRecord:
    """Alias for callers that identify the endpoint as a document API."""
    return parse_detail_page(html)


def _metadata(root: Tag) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in root.select(".metadata-span"):
        text = _clean_text(node)
        if ":" not in text:
            continue
        label, value = text.split(":", 1)
        if value.strip():
            values[_key(label)] = value.strip()
    return values


def _title(root: Tag) -> str | None:
    for selector in (".title h1", "h1", "title"):
        value = _clean_text(root.select_one(selector))
        if value:
            return value
    return None


def _section_blocks(root: Tag, prefix: str) -> list[Tag]:
    blocks: list[Tag] = []
    for node in root.find_all("div"):
        classes = [str(value) for value in node.get("class", [])]
        if any(value == prefix or value.startswith(f"{prefix}.") for value in classes):
            blocks.append(node)
    return blocks


def _raw_sections(blocks: dict[str, list[Tag]], reference_blocks: list[Tag]) -> dict[str, str]:
    sections: dict[str, str] = {}
    for key, values in blocks.items():
        text = _block_text(values)
        if text:
            sections[key] = text

    references = _block_text(reference_blocks)
    if references:
        sections["references"] = references
    return sections


def _block_text(blocks: list[Tag]) -> str | None:
    chunks: list[str] = []
    for block in blocks:
        direct_children = [child for child in block.find_all(recursive=False) if isinstance(child, Tag)]
        block_chunks = [
            _clean_multiline(child)
            for child in direct_children
            if child.name not in {"h1", "h2", "h3", "h4"}
        ]
        block_chunks = [chunk for chunk in block_chunks if chunk]
        if not block_chunks:
            block_chunks = [_clean_multiline(block)]
        for chunk in block_chunks:
            if chunk and chunk not in chunks:
                chunks.append(chunk)
    return "\n".join(chunks).strip() or None


def _summary_sections(blocks: list[Tag]) -> dict[str, str]:
    if not blocks:
        return {}
    nodes: list[Tag] = []
    for block in blocks:
        direct = [node for node in block.find_all(["p", "div"], recursive=False) if isinstance(node, Tag)]
        nodes.extend(direct or block.find_all(["p", "div"]))

    result: dict[str, str] = {}
    current: str | None = None
    chunks: list[str] = []
    for node in nodes:
        label = _summary_label(node)
        if label:
            if current:
                _save_section(result, current, chunks)
            current = label
            chunks = []
            inline = _inline_after_label(node)
            if inline:
                chunks.append(inline)
            continue
        if current:
            text = _clean_multiline(node)
            if text:
                chunks.append(text)
    if current:
        _save_section(result, current, chunks)
    return result


def _summary_label(node: Tag) -> str | None:
    bold = node.find("b")
    if bold is None:
        return None
    return SUMMARY_LABELS.get(_clean_text(bold).rstrip(":").casefold())


def _inline_after_label(node: Tag) -> str | None:
    bold = node.find("b")
    if bold is None:
        return None
    full = _clean_multiline(node)
    label = _clean_text(bold)
    if full.casefold().startswith(label.casefold()):
        value = full[len(label) :].lstrip(" :\n")
        return value or None
    return None


def _save_section(result: dict[str, str], key: str, chunks: list[str]) -> None:
    value = "\n".join(chunk for chunk in chunks if chunk).strip()
    if value:
        result[key] = value


def _history(blocks: list[Tag]) -> str | None:
    for block in blocks:
        for bold in block.find_all("b"):
            if _clean_text(bold).rstrip(":").casefold() != "history":
                continue
            parent = bold.parent if isinstance(bold.parent, Tag) else bold
            value = _clean_multiline(parent)
            label = _clean_text(bold)
            if value.casefold().startswith(label.casefold()):
                value = value[len(label) :].lstrip(" :\n")
            return value or None
    return None


def _tables(root: Tag) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    for table in root.find_all("table"):
        own_headers = [
            cell
            for cell in table.find_all("th")
            if cell.find_parent("table") is table
        ]
        if table.find("table") is not None and not own_headers:
            continue
        parsed = _parse_table(table)
        if parsed is not None:
            tables.append(parsed)
    return tables


def _parse_table(table: Tag) -> dict[str, Any] | None:
    rows = [row for row in table.find_all("tr") if row.find_parent("table") is table]
    headers = [
        _key(_clean_text(cell))
        for cell in table.find_all("th")
        if cell.find_parent("table") is table
    ]
    if not headers and rows:
        first_cells = _row_cells(rows[0])
        headers = [_key(_clean_text(cell)) for cell in first_cells]

    parsed_rows: list[dict[str, str | None]] = []
    for row in rows:
        cells = _row_cells(row)
        if not cells:
            continue
        if not row.find_all("td", recursive=False) and row.find_all("th", recursive=False):
            continue
        values: dict[str, str | None] = {}
        for index, cell in enumerate(cells):
            key = headers[index] if index < len(headers) and headers[index] else f"column_{index + 1}"
            value = _clean_multiline(cell) or None
            values[key] = value
        if any(value for value in values.values()):
            parsed_rows.append(values)
    if not headers and not parsed_rows:
        return None
    return {"headers": headers, "rows": parsed_rows}


def _row_cells(row: Tag) -> list[Tag]:
    return [cell for cell in row.find_all(["th", "td"], recursive=False) if isinstance(cell, Tag)]


def _cvss_entries(tables: list[dict[str, Any]]) -> list[dict[str, str | None]]:
    entries: list[dict[str, str | None]] = []
    for table in tables:
        headers = [str(header) for header in table.get("headers", [])]
        if not any("reference" in header or "cve" in header for header in headers):
            continue
        for row in table.get("rows", []):
            reference = _row_value(row, ("reference", "cve", "cve_id"))
            vector = _row_value(row, ("v3_vector", "cvss_vector", "vector"))
            score = _row_value(row, ("v3_base_score", "cvss_score", "base_score", "score"))
            if reference or vector or score:
                entries.append({"reference": reference, "vector": vector, "base_score": score})
    return entries


def _row_value(row: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = row.get(key)
        if value:
            return str(value)
    return None


def _cvss_text(text: str, tables: list[dict[str, Any]]) -> str | None:
    lines = [line.strip() for line in text.splitlines() if "cvss" in line.casefold()]
    for table in tables:
        for row in table.get("rows", []):
            for value in row.values():
                if value and ("cvss" in str(value).casefold() or "v3." in str(value).casefold()):
                    line = str(value).strip()
                    if line not in lines:
                        lines.append(line)
    return "\n".join(lines) or None


def _table_text(tables: list[dict[str, Any]]) -> str:
    return "\n".join(
        str(value)
        for table in tables
        for row in table.get("rows", [])
        for value in row.values()
        if value
    )


def _unique_cves(text: str) -> list[str]:
    result: list[str] = []
    for match in CVE_RE.findall(text or ""):
        value = match.upper()
        if value not in result:
            result.append(value)
    return result


def _severity(text: str) -> str | None:
    match = re.search(r"\bSeverity\s*:\s*([A-Za-z]+)", text, re.IGNORECASE)
    return match.group(1).capitalize() if match else None


def _links(root: Tag) -> list[str]:
    links: list[str] = []
    for node in root.select("a[href]"):
        href = str(node.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "javascript:")):
            continue
        link = urljoin(BASE_URL, href)
        if link not in links:
            links.append(link)
    return links


def _bulletin_id(title: str | None, doc_id: str | None) -> str | None:
    match = re.search(r"\b(HPESB[A-Z0-9]+)\b", title or "", re.IGNORECASE)
    if match:
        return match.group(1).upper()
    if doc_id:
        return re.sub(r"en_us$", "", doc_id, flags=re.IGNORECASE).upper()
    return None


def _value_after_label(value: str | None, label: str) -> str | None:
    if not value:
        return None
    return re.sub(rf"^\s*{re.escape(label)}\s*:?\s*", "", value, count=1, flags=re.IGNORECASE).strip() or None


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _clean_text(node: Tag | None) -> str:
    if node is None:
        return ""
    return " ".join(node.get_text(" ", strip=True).replace("\xa0", " ").split())


def _clean_multiline(node: Tag | None) -> str:
    if node is None:
        return ""
    lines = [re.sub(r"\s+", " ", line.replace("\xa0", " ")).strip() for line in node.get_text("\n", strip=True).splitlines()]
    return "\n".join(line for line in lines if line)
