from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.govcert.config import BASE_URL
from vuln_scraper.scrapers.govcert.parsers.common import clean_text, normalize_date, parse_alert_title, soup


DETAIL_PATH = "/en/alerts_detail.php"
EN_BASE_URL = f"{BASE_URL}/en/"


def parse_alerts_list(
    html: str,
    *,
    page: int,
    provider: str = "govcert",
    source_url: str | None = None,
) -> ListPage:
    parsed = soup(html)
    entries: list[ListEntry] = []

    for row in parsed.select(".view-row"):
        entry = _entry_from_row(row, provider=provider, source_url=source_url)
        if entry is not None:
            entries.append(entry)

    return ListPage(
        page=page,
        entries=entries,
        total_pages=_parse_total_pages(parsed),
        total_records=None,
    )


def _entry_from_row(row: Tag, *, provider: str, source_url: str | None) -> ListEntry | None:
    link = row.select_one('a[href*="alerts_detail.php"]')
    if link is None:
        return None

    code = _identity_code(str(link["href"]))
    if code is None:
        return None

    title = clean_text(link)
    if not title:
        return None

    alert_code, alert_type, title = parse_alert_title(title)
    published_date = normalize_date(clean_text(row.select_one(".label.label-primary")) or None)
    detail = {
        "_list_summary": True,
        "alert_code": alert_code,
        "alert_type": alert_type,
        "published_date": published_date,
        "detail_url": urljoin(EN_BASE_URL, str(link["href"])),
    }

    return ListEntry(
        identity=VulnerabilityId(type="GOVCERT", code=code),
        title=title,
        vuln_type=alert_code,
        disclosure_date=published_date,
        status=alert_type,
        provider=provider,
        source_url=source_url,
        embedded_detail=detail,
    )


def _identity_code(href: str) -> str | None:
    parsed = urlparse(urljoin(EN_BASE_URL, href))
    if parsed.path != DETAIL_PATH:
        return None
    identity = parse_qs(parsed.query).get("id", [None])[0]
    if identity and identity.isdigit():
        return identity
    return None


def _parse_total_pages(parsed: BeautifulSoup) -> int | None:
    pages: list[int] = []
    total = clean_text(parsed.select_one(".total_page"))
    if total.isdigit():
        pages.append(int(total))

    for link in parsed.find_all("a", href=True):
        for value in re.findall(r"chPage\((\d+)\)", str(link.get("href", ""))):
            pages.append(int(value))
    return max(pages) if pages else None
