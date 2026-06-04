from __future__ import annotations

import math
import re
from urllib.parse import urljoin

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.paloalto.config import BASE_URL, SOURCE_URL
from vuln_scraper.scrapers.paloalto.parsers.common import (
    clean_text,
    cve_ids_from_text,
    iso_date,
    soup,
)


TOTAL_RE = re.compile(r"\b\d+\s*-\s*\d+\s+of\s+(\d+)\b", re.IGNORECASE)


def parse_advisory_list(
    html: str,
    *,
    page: int,
    provider: str = "paloalto",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    parsed = soup(html)
    rows = parsed.select("form table tbody tr")
    entries = [
        entry
        for row in rows
        if (entry := _entry_from_row(row, provider=provider, source_url=source_url)) is not None
    ]
    total_records = _total_records(parsed)
    page_size = _page_size(parsed, len(entries))
    total_pages = math.ceil(total_records / page_size) if total_records and page_size else None
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def _entry_from_row(row, *, provider: str, source_url: str | None) -> ListEntry | None:
    cells = row.find_all("td", recursive=False)
    if len(cells) < 7:
        return None

    link = cells[1].find("a", href=True)
    href = link.get("href") if link else ""
    code = href.rsplit("/", 1)[-1].strip() if href else ""
    if not code:
        title_text = clean_text(link or cells[1])
        code = title_text.split(" ", 1)[0].strip()
    if not code:
        return None

    title = clean_text(link or cells[1])
    if title.upper().startswith(code.upper()):
        title = title[len(code) :].strip()
    title = title or code

    cvss_node = cells[0].find(class_=lambda value: value and "CVSS" in value.split())
    cvss_text = clean_text(cvss_node or cells[0])
    severity = _severity(cvss_node, cvss_text)
    cvss_score = _cvss_score(cvss_text)
    products = _lines(cells[2])
    published_date = _date_from_cell(cells[5])
    updated_date = _date_from_cell(cells[6])
    detail_url = urljoin(BASE_URL, href) if href else None
    cve_ids = cve_ids_from_text(f"{code} {title}")

    return ListEntry(
        identity=VulnerabilityId(type="PALOALTO", code=code),
        title=title,
        vuln_type=", ".join(products) if products else None,
        disclosure_date=published_date,
        status=severity,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "advisory_id": code,
            "severity": severity,
            "cvss_score": cvss_score,
            "products": products,
            "affected": _lines(cells[3]),
            "unaffected": _lines(cells[4]),
            "published_date": published_date,
            "updated_date": updated_date,
            "cve_ids": cve_ids,
            "reference_links": [detail_url] if detail_url else [],
        },
    )


def _lines(cell) -> list[str]:
    return [clean_text(node) for node in cell.select(".vflx > div") if clean_text(node)]


def _date_from_cell(cell) -> str | None:
    dated = cell.select_one("[data-date]")
    return iso_date(dated.get("data-date") if dated else clean_text(cell))


def _severity(node, fallback: str) -> str | None:
    classes = [str(item).upper() for item in (node.get("class", []) if node else [])]
    for value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        if value in classes or value in fallback.upper().split():
            return value
    return None


def _cvss_score(value: str) -> float | None:
    match = re.search(r"\d+(?:\.\d+)?", value)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _total_records(parsed) -> int | None:
    text = clean_text(parsed)
    match = TOTAL_RE.search(text)
    if not match:
        return None
    return int(match.group(1))


def _page_size(parsed, parsed_count: int) -> int | None:
    selected = parsed.select_one("select#limit option[selected]")
    if selected and selected.get("value", "").isdigit():
        return int(selected["value"])
    limit = parsed.select_one("select#limit")
    current = limit.find("option", value=True) if limit else None
    if current and str(current.get("value", "")).isdigit():
        return int(current["value"])
    return parsed_count or None
