from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.avd.config import BASE_URL


AVD_ID_RE = re.compile(r"AVD-\d{4}-\d+", re.IGNORECASE)
TOTAL_PAGES_RE = re.compile(r"第\s*\d+\s*页\s*/\s*(\d+)\s*页")
TOTAL_RECORDS_RE = re.compile(r"总计\s*([\d,]+)\s*条")


def parse_high_risk_list(
    html: str,
    *,
    page: int,
    provider: str = "avd",
    source_url: str | None = None,
) -> ListPage:
    soup = BeautifulSoup(html, "lxml")
    entries: list[ListEntry] = []

    for row in soup.select("table tr"):
        cells = row.find_all("td")
        if len(cells) < 5:
            continue

        avd_id = _extract_avd_id(cells[0])
        if not avd_id:
            continue

        entries.append(
            ListEntry(
                identity=VulnerabilityId.parse(avd_id),
                title=_clean_text(cells[1]),
                vuln_type=_clean_text(cells[2]) or None,
                disclosure_date=_clean_text(cells[3]) or None,
                status=_clean_text(cells[4]) or None,
                provider=provider,
                source_url=source_url,
            )
        )

    total_pages, total_records = _parse_footer_totals(soup)
    if total_pages is None:
        total_pages = _parse_max_page_from_links(soup)

    return ListPage(
        page=page,
        entries=entries,
        total_pages=total_pages,
        total_records=total_records,
    )


def _extract_avd_id(cell: Tag) -> str | None:
    link = cell.find("a", href=True)
    if link:
        href = urljoin(BASE_URL, link["href"])
        query_id = parse_qs(urlparse(href).query).get("id", [None])[0]
        if query_id and AVD_ID_RE.fullmatch(query_id):
            return query_id.upper()

        match = AVD_ID_RE.search(href)
        if match:
            return match.group(0).upper()

    match = AVD_ID_RE.search(_clean_text(cell))
    if match:
        return match.group(0).upper()
    return None


def _parse_footer_totals(soup: BeautifulSoup) -> tuple[int | None, int | None]:
    text = _clean_text(soup)

    total_pages = None
    total_records = None

    pages_match = TOTAL_PAGES_RE.search(text)
    if pages_match:
        total_pages = int(pages_match.group(1).replace(",", ""))

    records_match = TOTAL_RECORDS_RE.search(text)
    if records_match:
        total_records = int(records_match.group(1).replace(",", ""))

    return total_pages, total_records


def _parse_max_page_from_links(soup: BeautifulSoup) -> int | None:
    pages: list[int] = []
    for link in soup.find_all("a", href=True):
        parsed = urlparse(urljoin(BASE_URL, link["href"]))
        page_values = parse_qs(parsed.query).get("page", [])
        for value in page_values:
            if value.isdigit():
                pages.append(int(value))
    return max(pages) if pages else None


def _clean_text(node) -> str:
    return " ".join(node.get_text(" ", strip=True).split())
