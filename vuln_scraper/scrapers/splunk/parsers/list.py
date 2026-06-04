from __future__ import annotations

from bs4 import Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.splunk.config import SOURCE_URL
from vuln_scraper.scrapers.splunk.parsers.common import clean_multiline, clean_text, cve_ids_from_text, normalize_key, soup


def parse_advisory_list(
    html: str,
    *,
    page: int,
    provider: str = "splunk",
    source_url: str = SOURCE_URL,
) -> ListPage:
    parsed = soup(html)
    table = parsed.find("table")
    if table is None:
        return ListPage(page=page, entries=[], total_pages=1, total_records=0)

    headers = [_header_text(cell) for cell in table.find_all("th")]
    entries: list[ListEntry] = []
    for row in table.find_all("tr"):
        cells = row.find_all("td", recursive=False)
        if not cells:
            continue
        values = _row_values(headers, cells)
        code = values.get("svd")
        if not code or not code.upper().startswith("SVD-"):
            continue
        cve_ids = cve_ids_from_text("\n".join(str(value) for value in values.values() if value))
        detail = {
            "_list_summary": True,
            "advisory_id": code,
            "cve_id": cve_ids[0] if cve_ids else None,
            "cve_ids": cve_ids,
            "last_modified": values.get("last_modified"),
            "severity": values.get("severity"),
            "cvss_vector": _none_if_na(values.get("cvss_vector")),
            "cvss_score": _none_if_na(values.get("cvss_score")),
            "cwe": _none_if_na(values.get("cwe")),
            "bug_ids": _split_values(values.get("bug")),
            "affected_products": values.get("affected_products"),
            "fixed_versions": values.get("fixed_versions"),
            "affected_versions": values.get("affected_versions"),
            "all_affected_versions": values.get("all_affected_versions"),
            "affected_components": values.get("affected_components"),
            "description": values.get("description"),
            "solution": values.get("solution"),
            "mitigations": values.get("mitigations"),
            "severity_summary": values.get("severity_summary"),
            "oss": values.get("oss"),
            "credit": values.get("credit"),
            "raw": values,
        }
        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="SPLUNK", code=code),
                title=values.get("title") or code,
                vuln_type=values.get("affected_products"),
                disclosure_date=values.get("date"),
                status=values.get("severity"),
                provider=provider,
                source_url=source_url,
                embedded_detail=detail,
            )
        )

    return ListPage(page=page, entries=entries, total_pages=1, total_records=len(entries))


def _header_text(cell: Tag) -> str:
    return normalize_key(clean_text(cell))


def _row_values(headers: list[str], cells: list[Tag]) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for index, cell in enumerate(cells):
        key = headers[index] if index < len(headers) and headers[index] else f"column_{index + 1}"
        text = clean_multiline(cell) or clean_text(cell)
        values[key] = text or None
    return values


def _none_if_na(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return None if text.casefold() in {"", "na", "n/a", "none"} else text


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    parts = [part.strip() for part in value.replace("\n", ",").split(",")]
    return [part for part in parts if part and part.casefold() not in {"na", "n/a"}]
