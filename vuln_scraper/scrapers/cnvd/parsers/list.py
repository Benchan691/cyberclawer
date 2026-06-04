from __future__ import annotations

import math
import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.cnvd.config import BASE_URL, PAGE_SIZE, SOURCE_URL


CNVD_ID_RE = re.compile(r"CNVD-(\d{4}-\d{4,})", re.IGNORECASE)
TOTAL_RECORDS_RE = re.compile(r"共\s*([\d,]+)\s*条")
DATE_RE = re.compile(r"\d{4}-\d{1,2}-\d{1,2}")


def parse_flaw_list(
    html: str,
    *,
    page: int,
    provider: str = "cnvd",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    parsed = BeautifulSoup(html or "", "lxml")
    entries = [
        entry
        for row in parsed.select("table tr")
        if (entry := _entry_from_row(row, provider=provider, source_url=source_url)) is not None
    ]

    total_records = _parse_total_records(parsed)
    total_pages = math.ceil(total_records / PAGE_SIZE) if total_records else _parse_total_pages(parsed)
    return ListPage(
        page=page,
        entries=entries,
        total_pages=total_pages,
        total_records=total_records,
    )


def _entry_from_row(row: Tag, *, provider: str, source_url: str | None) -> ListEntry | None:
    cells = row.find_all("td")
    if len(cells) < 2:
        return None

    link = _detail_link(row)
    cnvd_id = _cnvd_id_from_node(row, link)
    if not cnvd_id:
        return None

    title_cell = _title_cell(cells, link)
    title = _clean_text(title_cell)
    if not title and link:
        title = _clean_text(link)
    if not title:
        return None

    values = [_clean_text(cell) for cell in cells]
    severity = _severity_from_values(values)
    published_date = _date_from_values(values)
    numeric_values = [_optional_int(value) for value in values]
    counts = [value for value in numeric_values if value is not None]
    detail_url = urljoin(BASE_URL, link.get("href")) if link and link.get("href") else f"{BASE_URL}/flaw/show/{cnvd_id}"
    code = cnvd_id.removeprefix("CNVD-")

    return ListEntry(
        identity=VulnerabilityId(type="CNVD", code=code),
        title=title,
        vuln_type=None,
        disclosure_date=published_date,
        status=severity,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "cnvd_id": cnvd_id,
            "title": title,
            "severity": severity,
            "published_date": published_date,
            "click_count": counts[0] if len(counts) > 0 else None,
            "comment_count": counts[1] if len(counts) > 1 else None,
            "follow_count": counts[2] if len(counts) > 2 else None,
            "reference_links": [detail_url],
        },
    )


def _detail_link(row: Tag) -> Tag | None:
    for link in row.find_all("a", href=True):
        href = str(link.get("href") or "")
        if "/flaw/show/" in href or CNVD_ID_RE.search(href):
            return link
    return None


def _cnvd_id_from_node(row: Tag, link: Tag | None) -> str | None:
    candidates = []
    if link is not None:
        candidates.append(str(link.get("href") or ""))
        candidates.append(_clean_text(link))
    candidates.append(_clean_text(row))
    for value in candidates:
        match = CNVD_ID_RE.search(value)
        if match:
            return f"CNVD-{match.group(1)}"
    return None


def _title_cell(cells: list[Tag], link: Tag | None) -> Tag | None:
    if link is not None:
        for cell in cells:
            if link in cell.descendants or link is cell:
                return cell
    return cells[0] if cells else None


def _severity_from_values(values: list[str]) -> str | None:
    for value in values:
        if value in {"高", "中", "低", "严重", "高危", "中危", "低危", "超危"}:
            return value
    return None


def _date_from_values(values: list[str]) -> str | None:
    for value in values:
        match = DATE_RE.search(value)
        if match:
            year, month, day = match.group(0).split("-")
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    return None


def _parse_total_records(parsed: BeautifulSoup) -> int | None:
    match = TOTAL_RECORDS_RE.search(_clean_text(parsed))
    if not match:
        return None
    return int(match.group(1).replace(",", ""))


def _parse_total_pages(parsed: BeautifulSoup) -> int | None:
    pages: list[int] = []
    for link in parsed.find_all("a", href=True):
        href = urljoin(BASE_URL, str(link.get("href") or ""))
        query = parse_qs(urlparse(href).query)
        offset_values = query.get("offset", [])
        max_values = query.get("max", [])
        for value in offset_values:
            if value.isdigit():
                page_size = PAGE_SIZE
                if max_values and max_values[0].isdigit():
                    page_size = int(max_values[0]) or PAGE_SIZE
                pages.append((int(value) // page_size) + 1)
    return max(pages) if pages else None


def _optional_int(value: str) -> int | None:
    text = value.replace(",", "").strip()
    if not text.isdigit():
        return None
    return int(text)


def _clean_text(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text(" ", strip=True)
    else:
        text = str(node)
    return " ".join(text.replace("\xa0", " ").split())
