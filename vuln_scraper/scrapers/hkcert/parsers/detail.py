from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.hkcert.config import BASE_URL


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SECTION_LABELS = {
    "impact": "Impact",
    "systems_affected": "System / Technologies affected",
    "solutions": "Solutions",
    "vulnerability_identifiers": "Vulnerability Identifier",
    "bulletin_source": "Source",
    "related_links": "Related Link",
}

_TABLE_HEADER_ALIASES = {
    # Column header can vary across HKCERT bulletin tables. We normalize it into
    # a single key name used by downstream consumers.
    "vulnerable product": "name",
    "vulnerable object name": "name",
    "risk level": "risk_level",
    "impacts": "impacts",
    "notes": "notes",
    "details (including cve)": "details",
    "details": "details",
}

_KNOWN_TABLE_HEADERS = set(_TABLE_HEADER_ALIASES)


@dataclass(slots=True)
class HKCERTDetailRecord:
    intro: str | None = None
    table: list[dict[str, str | None]] = field(default_factory=list)
    note: str | None = None
    impact: list[str] = field(default_factory=list)
    systems_affected: list[str] = field(default_factory=list)
    solutions: str | None = None
    solution_links: list[str] = field(default_factory=list)
    vulnerability_identifiers: list[dict[str, str]] = field(default_factory=list)
    bulletin_source: str | None = None
    related_links: list[str] = field(default_factory=list)
    risk_level: str | None = None
    release_date: str | None = None
    last_update_date: str | None = None
    summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> HKCERTDetailRecord:
    soup = BeautifulSoup(html, "lxml")
    sections = {key: _section_nodes(soup, label) for key, label in SECTION_LABELS.items()}
    release_date, last_update_date = _metadata(soup)

    table_rows = _table_rows_from_intro(soup)
    identifiers = _vulnerability_identifiers(sections["vulnerability_identifiers"])
    identifiers = _merge_identifiers(identifiers, _identifiers_from_table_rows(table_rows))

    return HKCERTDetailRecord(
        intro=_intro(soup),
        table=table_rows,
        note=_note(soup),
        impact=_split_section_to_list(_section_text(sections["impact"])),
        systems_affected=_split_section_to_list(_section_text(sections["systems_affected"])),
        solutions=_section_text(sections["solutions"]),
        solution_links=_links_from_nodes(sections["solutions"]),
        vulnerability_identifiers=identifiers,
        bulletin_source=_section_text(sections["bulletin_source"]),
        related_links=_links_from_nodes(sections["related_links"]),
        risk_level=_risk_level(soup),
        release_date=release_date,
        last_update_date=last_update_date,
        summary=_intro(soup) or _table_rows_summary(table_rows),
    )


def _intro(soup: BeautifulSoup) -> str | None:
    intro = soup.select_one(".page-intro")
    if intro is None:
        return None
    fragment = BeautifulSoup(str(intro), "lxml")
    container = fragment.select_one(".page-intro") or fragment
    for table in container.find_all("table"):
        table.decompose()
    text = _clean_multiline(container)
    return text or None


def normalize_hkcert_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Normalize stored hkcert detail payloads to the current MongoDB schema."""
    normalized = dict(detail)
    normalized.pop("views", None)
    if "intro_tables" in normalized:
        rows: list[dict[str, str | None]] = []
        for intro_table in normalized.pop("intro_tables", []):
            if not isinstance(intro_table, dict):
                continue
            for row in intro_table.get("rows", []):
                if isinstance(row, dict):
                    rows.append(dict(row))
        normalized["table"] = rows
    if "vulnerable_products" in normalized:
        if "table" not in normalized:
            legacy_rows = normalized.pop("vulnerable_products")
            if isinstance(legacy_rows, list):
                normalized["table"] = [dict(row) for row in legacy_rows if isinstance(row, dict)]
        else:
            normalized.pop("vulnerable_products")
    normalized.setdefault("table", [])

    # Migrate legacy key names:
    # - older payloads used `vulnerable_product`
    # - earlier schema used `table` for the product name column
    for row in normalized.get("table") or []:
        if not isinstance(row, dict):
            continue
        if "name" not in row:
            if "vulnerable_product" in row:
                row["name"] = row.pop("vulnerable_product")
            elif "table" in row:
                row["name"] = row.pop("table")

    normalized["impact"] = _split_section_to_list(normalized.get("impact"))
    normalized["systems_affected"] = _split_section_to_list(normalized.get("systems_affected"))

    return normalized


def _table_rows_from_intro(soup: BeautifulSoup) -> list[dict[str, str | None]]:
    intro = soup.select_one(".page-intro")
    if intro is None:
        return []
    products: list[dict[str, str | None]] = []
    for table in intro.find_all("table"):
        products.extend(_parse_product_table_rows(table))
    return products


def _table_rows_summary(table_rows: list[dict[str, str | None]]) -> str | None:
    if not table_rows:
        return None
    lines = [
        str(row.get("name") or "")
        for row in table_rows
        if row.get("name")
    ]
    return "\n".join(lines) or None


def _parse_product_table_rows(table: Tag) -> list[dict[str, str | None]]:
    headers: list[str] = []
    rows: list[dict[str, str | None]] = []

    for row_node in table.find_all("tr"):
        header_cells = row_node.find_all("th", recursive=False)
        if header_cells:
            headers = [_normalize_table_header(_table_cell_text(cell)) for cell in header_cells]
            continue

        data_cells = row_node.find_all("td", recursive=False)
        if not data_cells:
            continue

        if not headers:
            candidate_headers = [_table_cell_text(cell) for cell in data_cells]
            if _is_table_header_row(candidate_headers):
                headers = [_normalize_table_header(label) for label in candidate_headers]
                continue

        if not headers:
            headers = [f"column_{index + 1}" for index in range(len(data_cells))]

        row: dict[str, str | None] = {}
        for index, cell in enumerate(data_cells):
            key = headers[index] if index < len(headers) else f"column_{index + 1}"
            row[key] = _table_cell_text(cell) or None
            link = cell.find("a", href=True)
            if link and link.get("href"):
                href = str(link["href"])
                if href.startswith("/"):
                    href = urljoin(BASE_URL, href)
                row[f"{key}_url"] = href
        if any(value for value in row.values()):
            rows.append(row)

    return rows


def _is_table_header_row(labels: list[str]) -> bool:
    normalized = {label.strip().lower() for label in labels if label.strip()}
    return len(normalized & _KNOWN_TABLE_HEADERS) >= 2


def _normalize_table_header(label: str) -> str:
    lowered = label.strip().lower()
    if lowered in _TABLE_HEADER_ALIASES:
        return _TABLE_HEADER_ALIASES[lowered]
    slug = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    return slug or "column"


def _table_cell_text(cell: Tag) -> str:
    fragment = BeautifulSoup(str(cell), "lxml")
    node = fragment.find(["td", "th"]) or fragment
    for br in node.find_all("br"):
        br.replace_with("\n")
    return _clean_multiline(node)


def _note(soup: BeautifulSoup) -> str | None:
    for paragraph in soup.select(".page-intro p, .inner-context .ckec p"):
        text = _clean_text(paragraph)
        if text.startswith("Note:"):
            return text
    return None


def _section_nodes(soup: BeautifulSoup, label: str) -> list[Tag]:
    heading = next(
        (
            node
            for node in soup.find_all("h2")
            if _clean_text(node) == label
        ),
        None,
    )
    if heading is None:
        return []

    nodes: list[Tag] = []
    for sibling in heading.next_siblings:
        if isinstance(sibling, Tag) and sibling.name == "h2":
            break
        if isinstance(sibling, Tag) and sibling.name != "hr":
            nodes.append(sibling)
    return nodes


def _section_text(nodes: list[Tag]) -> str | None:
    text = "\n".join(_clean_multiline(node) for node in nodes if _clean_multiline(node)).strip()
    return text or None


def _split_section_to_list(value: Any) -> list[str]:
    """
    Convert an HKCERT section into an array of string values.

    Examples:
      - Impact is typically a list rendered as <ul><li>..</li></ul>, which we
        capture as newline-separated text.
      - Systems affected often looks like: "Android 13, Android 14 and Android 15".
    """
    if value is None:
        return []
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return parts

    text = str(value).strip()
    if not text:
        return []

    # First split by line breaks; then if we only got a single line, split on
    # common separators and the word "and".
    raw_lines = [line.strip() for line in re.split(r"[\r\n]+", text) if line.strip()]
    if not raw_lines:
        return []

    if len(raw_lines) == 1:
        expanded = re.split(r"\s*(?:,|;|\band\b)\s*", raw_lines[0])
    else:
        expanded = []
        for line in raw_lines:
            expanded.extend(re.split(r"\s*(?:,|;|\band\b)\s*", line))

    return [item.strip() for item in expanded if item and item.strip()]


def _vulnerability_identifiers(nodes: list[Tag]) -> list[dict[str, str]]:
    return _identifiers_from_text(_section_text(nodes) or "")


def _identifiers_from_table_rows(table_rows: list[dict[str, str | None]]) -> list[dict[str, str]]:
    chunks = [
        str(value)
        for row in table_rows
        for value in row.values()
        if value
    ]
    return _identifiers_from_text("\n".join(chunks))


def _identifiers_from_text(text: str) -> list[dict[str, str]]:
    identifiers: list[dict[str, str]] = []
    for cve_id in CVE_RE.findall(text):
        entry = {"cve_id": cve_id.upper()}
        if entry not in identifiers:
            identifiers.append(entry)
    return identifiers


def _merge_identifiers(
    primary: list[dict[str, str]],
    extra: list[dict[str, str]],
) -> list[dict[str, str]]:
    merged = list(primary)
    for entry in extra:
        if entry not in merged:
            merged.append(entry)
    return merged


def _links_from_nodes(nodes: list[Tag]) -> list[str]:
    links: list[str] = []
    for node in nodes:
        for link in node.find_all("a", href=True):
            href = urljoin(BASE_URL, link["href"])
            if href not in links:
                links.append(href)
    return links


def _risk_level(soup: BeautifulSoup) -> str | None:
    for selector in (".risk-meter__text", ".risk-meter .sr-only", ".sr-only"):
        node = soup.select_one(selector)
        text = _clean_text(node)
        if text:
            return text.removeprefix("RISK:").strip()
    return None


def _metadata(soup: BeautifulSoup) -> tuple[str | None, str | None]:
    text = _clean_text(soup.select_one(".page-date")) or _clean_text(soup.select_one(".listingcard__info"))
    release_date = _metadata_match(text, "Release Date")
    last_update_date = _metadata_match(text, "Last Update Date")
    return release_date, last_update_date


def _metadata_match(text: str, label: str) -> str | None:
    match = re.search(
        rf"{re.escape(label)}:\s*(.+?)(?:\s+Last Update Date:|\s+Release Date:|\s+\d[\d,]*\s+Views|$)",
        text,
    )
    return match.group(1).strip() if match else None


def _clean_text(node) -> str:
    if node is None:
        return ""
    return " ".join(node.get_text(" ", strip=True).split())


def _clean_multiline(node) -> str:
    if node is None:
        return ""
    lines = [line.strip() for line in node.get_text("\n", strip=True).splitlines()]
    return "\n".join(line for line in lines if line and line != "\xa0")
