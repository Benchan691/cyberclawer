from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.hkcert.config import BASE_URL


TOTAL_PAGES_RE = re.compile(r"page=(\d+)")


def parse_security_bulletin_list(
    html: str,
    *,
    page: int,
    provider: str = "hkcert",
    source_url: str | None = None,
) -> ListPage:
    soup = BeautifulSoup(html, "lxml")
    entries: list[ListEntry] = []

    for card in soup.select('a.listingcard__item[href*="/security-bulletin/"]'):
        slug = _slug_from_card(card)
        if not slug:
            continue

        title, status = _title_and_status(card)
        if not title:
            continue

        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="HKCERT", code=slug),
                title=title,
                vuln_type=None,
                disclosure_date=_metadata_value(card, "Release Date"),
                status=status,
                provider=provider,
                source_url=source_url,
            )
        )

    return ListPage(
        page=page,
        entries=entries,
        total_pages=_parse_total_pages(soup),
        total_records=None,
    )


def _slug_from_card(card: Tag) -> str | None:
    href = card.get("href")
    if not href:
        return None
    path = urlparse(urljoin(BASE_URL, href)).path.rstrip("/")
    if "/security-bulletin/" not in path:
        return None
    slug = path.rsplit("/", 1)[-1].strip()
    return slug or None


def _title_and_status(card: Tag) -> tuple[str | None, str | None]:
    title_node = card.select_one(".listingcard__title")
    if title_node is None:
        return None, None

    status_node = title_node.select_one(".cat-tag")
    status = _clean_text(status_node) if status_node else None
    if status_node:
        status_node.extract()
    title = _clean_text(title_node)
    return title or None, status or None


def _metadata_value(card: Tag, label: str) -> str | None:
    info = card.select_one(".listingcard__info")
    text = _clean_text(info)
    if not text:
        return None
    match = re.search(rf"{re.escape(label)}:\s*(.+?)(?:\s+\d+\s+Views|\s+Last Update Date:|\s+Release Date:|$)", text)
    if match:
        return match.group(1).strip()
    return None


def _parse_total_pages(soup: BeautifulSoup) -> int | None:
    pages: list[int] = []
    for link in soup.find_all("a", href=True):
        parsed = urlparse(urljoin(BASE_URL, link["href"]))
        for value in parse_qs(parsed.query).get("page", []):
            if value.isdigit():
                pages.append(int(value))
    return max(pages) if pages else None


def _clean_text(node) -> str:
    if node is None:
        return ""
    return " ".join(node.get_text(" ", strip=True).split())
