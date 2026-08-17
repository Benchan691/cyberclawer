from __future__ import annotations

import math
import re

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.fortiguard.config import SOURCE_URL
from vuln_scraper.scrapers.fortiguard.parsers.common import (
    IR_CODE_RE,
    clean_text,
    cve_ids_from_text,
    iso_date,
    soup,
)

TOTAL_RE = re.compile(r"Total:\s*(\d+)", re.IGNORECASE)
ONCLICK_PATH_RE = re.compile(r"['\"](/psirt/FG-IR-[^'\"]+)['\"]", re.IGNORECASE)


def parse_advisory_list(
    html: str,
    *,
    page: int,
    provider: str = "fortiguard",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    parsed = soup(html)
    rows = parsed.select("section.table-body div.row[onclick]")
    entries = [
        entry
        for row in rows
        if (entry := _entry_from_row(row, provider=provider, source_url=source_url)) is not None
    ]
    total_records = _total_records(parsed)
    page_size = len(entries) or 15
    total_pages = _total_pages(parsed, total_records, page_size)
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def _entry_from_row(row, *, provider: str, source_url: str | None) -> ListEntry | None:
    onclick = row.get("onclick") or ""
    path_match = ONCLICK_PATH_RE.search(onclick)
    path = path_match.group(1) if path_match else ""
    code = path.rsplit("/", 1)[-1].strip() if path else ""

    title_node = row.select_one("div.col-md-3 > b")
    title_text = clean_text(title_node)
    if not code:
        ir_match = IR_CODE_RE.search(title_text)
        code = ir_match.group(0).upper() if ir_match else ""
    if not code:
        return None
    code = code.upper()

    title = title_text
    if title.upper().startswith(code.upper()):
        title = title[len(code) :].strip()
    title = title or code

    cve_ids = [
        clean_text(node).upper()
        for node in row.select("b.cve")
        if clean_text(node)
    ]
    if not cve_ids:
        cve_ids = cve_ids_from_text(clean_text(row))

    products = _products(row)
    published_date = _published_date(row)
    severity = _severity(row)
    component = _column_value(row, "Component")
    discovered = _column_value(row, "Discovered")
    attack_type = _column_value(row, "Attack Type")
    summary = clean_text(row.select_one("div.col-md-2 small"))

    return ListEntry(
        identity=VulnerabilityId(type="FORTIGUARD", code=code),
        title=title,
        vuln_type=", ".join(products) if products else None,
        disclosure_date=published_date,
        status=severity,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "advisory_id": code,
            "title": title,
            "summary": summary or None,
            "severity": severity,
            "component": component,
            "discovered": discovered,
            "attack_type": attack_type,
            "products": products,
            "published_date": published_date,
            "cve_ids": cve_ids,
        },
    )


def _products(row) -> list[str]:
    products: list[str] = []
    for group in row.select("span.item-group > b"):
        name = clean_text(group)
        if name and name not in products:
            products.append(name)
    return products


def _published_date(row) -> str | None:
    for node in row.select("small"):
        text = clean_text(node)
        if text.lower().startswith("published:"):
            return iso_date(text.split(":", 1)[-1])
    return None


def _severity(row) -> str | None:
    for node in row.select("p > b, div.col-md-1 b"):
        text = clean_text(node)
        if text and text.lower() not in {"others", "internal", "external", "unauthenticated", "authenticated"}:
            if re.fullmatch(r"(Critical|High|Medium|Low|Info)", text, re.IGNORECASE):
                return text.title()
    # fallback: last bold severity-looking text in mobile column labeled Severity
    for node in row.select("div.col-md-1"):
        text = clean_text(node)
        if "Severity" in text:
            match = re.search(r"(Critical|High|Medium|Low|Info)", text, re.IGNORECASE)
            if match:
                return match.group(1).title()
    return None


def _column_value(row, label: str) -> str | None:
    for node in row.select("div.col-md-1"):
        text = clean_text(node)
        if text.endswith(label):
            return normalize_label_value(text[: -len(label)])
    return None


def normalize_label_value(value: str) -> str | None:
    text = clean_text(value)
    return text or None


def _total_records(parsed) -> int | None:
    for node in parsed.select("p.mt-2, p"):
        match = TOTAL_RE.search(clean_text(node))
        if match:
            return int(match.group(1))
    return None


def _total_pages(parsed, total_records: int | None, page_size: int) -> int | None:
    page_numbers: list[int] = []
    for node in parsed.select("ul.pagination a.page-link"):
        text = clean_text(node)
        if text.isdigit():
            page_numbers.append(int(text))
    if page_numbers:
        return max(page_numbers)
    if total_records and page_size:
        return math.ceil(total_records / page_size)
    return None
