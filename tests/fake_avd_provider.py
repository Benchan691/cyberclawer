"""Test-only provider mimicking the removed Aliyun AVD scraper for runner unit tests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import DetailRecord, ListEntry, ListPage, VulnerabilityId

BASE_URL = "https://avd.aliyun.com"
LIST_URL = f"{BASE_URL}/high-risk/list"
DETAIL_URL = f"{BASE_URL}/detail"

AVD_ID_RE = re.compile(r"AVD-\d{4}-\d+", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
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
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def parse_detail_page(html: str) -> DetailRecord:
    soup = BeautifulSoup(html, "lxml")
    title_node = soup.select_one("span.header__title__text")
    title = _clean_text(title_node) if title_node else None
    cve_id = None
    if title:
        match = CVE_RE.search(title)
        if match:
            cve_id = match.group(0).upper()
    danger = soup.select_one("span.badge")
    return DetailRecord(
        cve_id=cve_id,
        danger_level=_clean_text(danger) if danger else None,
        description=_clean_text(soup.select_one("div.text-detail")),
    )


def _extract_avd_id(cell: Tag) -> str | None:
    link = cell.find("a", href=True)
    if link:
        href = urljoin(BASE_URL, link["href"])
        query_id = parse_qs(urlparse(href).query).get("id", [None])[0]
        if query_id and AVD_ID_RE.fullmatch(query_id):
            return query_id.upper()
    match = AVD_ID_RE.search(_clean_text(cell))
    return match.group(0).upper() if match else None


def _parse_footer_totals(soup: BeautifulSoup) -> tuple[int | None, int | None]:
    text = _clean_text(soup)
    pages_match = TOTAL_PAGES_RE.search(text)
    records_match = TOTAL_RECORDS_RE.search(text)
    total_pages = int(pages_match.group(1)) if pages_match else None
    total_records = int(records_match.group(1).replace(",", "")) if records_match else None
    return total_pages, total_records


def _clean_text(node: Tag | BeautifulSoup | None) -> str:
    if node is None:
        return ""
    return " ".join(node.stripped_strings)


@dataclass(frozen=True, slots=True)
class FakeAvdProvider:
    key: str = "avd"
    source_url: str = LIST_URL
    default_mongo_collection: str = "vulnerabilities"
    browser_fallback: bool = True
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return f"{LIST_URL}?page={page}"

    def detail_url(self, identity_display: str) -> str:
        return f"{DETAIL_URL}?id={identity_display}"

    def parse_list(self, html: str, *, page: int) -> ListPage:
        return parse_high_risk_list(html, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> DetailRecord:
        return parse_detail_page(html)
