from __future__ import annotations

import math
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.hikvision.config import (
    BASE_URL,
    CONTENT_ADVISORY_PATH,
    HK_ADVISORY_PATH,
    SOURCE_URL,
)


DATE_RE = re.compile(
    r"(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{4}|[A-Z][a-z]+ \d{1,2}, \d{4})"
)


def parse_advisory_list(
    html: str,
    *,
    page: int,
    provider: str = "hikvision",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    parsed = _soup(html)
    entries: list[ListEntry] = []
    seen: set[str] = set()
    for link in parsed.select('a[href*="/support/cybersecurity/security-advisory/"]'):
        entry = _entry_from_link(link, provider=provider, source_url=source_url)
        if entry is not None and entry.identity.code not in seen:
            entries.append(entry)
            seen.add(entry.identity.code)

    total_records = _total_records(parsed) or len(entries)
    page_size = len(entries) or None
    total_pages = math.ceil(total_records / page_size) if total_records and page_size else None
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def _entry_from_link(link: Tag, *, provider: str, source_url: str | None) -> ListEntry | None:
    href = str(link.get("href") or "").strip()
    detail_url = urljoin(BASE_URL, href)
    code = _slug_from_url(detail_url)
    if not code:
        return None

    container = _container(link)
    title = _title(link, container)
    if not title:
        return None
    text = _clean_multiline(container or link)
    published_date = _iso_date(_first_match(DATE_RE, text))
    severity = _severity(text)

    return ListEntry(
        identity=VulnerabilityId(type="HIKVISION", code=code),
        title=title,
        vuln_type="Security Advisory",
        disclosure_date=published_date,
        status=severity or "Security Advisory",
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "advisory_id": code,
            "published_date": published_date,
            "severity": severity,
            "summary": _summary(container, title),
            "reference_links": [detail_url],
        },
    )


def _slug_from_url(url: str) -> str | None:
    parsed = urlparse(urljoin(BASE_URL, url))
    path = parsed.path.rstrip("/")
    if path.startswith(CONTENT_ADVISORY_PATH + "/"):
        slug = path[len(CONTENT_ADVISORY_PATH) + 1 :]
        if slug.endswith(".html"):
            slug = slug[:-5]
        return slug.strip() or None
    if path == HK_ADVISORY_PATH or not path.startswith(HK_ADVISORY_PATH + "/"):
        return None
    slug = path.rsplit("/", 1)[-1].strip()
    if slug.endswith(".html"):
        slug = slug[:-5]
    return slug or None


def _container(link: Tag) -> Tag:
    for selector in (".security-advisory", ".article-item", ".list-item", ".news-item", "li", "article", ".item"):
        parent = link.find_parent(class_=lambda value: value and selector.strip(".") in str(value).split())
        if parent is not None:
            return parent
    return link.find_parent("li") or link.find_parent("article") or link.parent or link


def _title(link: Tag, container: Tag) -> str:
    for node in (
        link,
        container.select_one(".title"),
        container.select_one(".card-title"),
        container.select_one("h1, h2, h3, h4"),
    ):
        text = _clean_text(node)
        if text:
            return text
    return ""


def _summary(container: Tag, title: str) -> str | None:
    text = _clean_multiline(container)
    if not text:
        return None
    lines = [line for line in text.splitlines() if line.strip() and line.strip() != title]
    return lines[0].strip() if lines else None


def _total_records(parsed: BeautifulSoup) -> int | None:
    text = _clean_text(parsed)
    for pattern in (r"\bof\s+(\d+)\b", r"\bTotal\s+(\d+)\b", r"共\s*(\d+)\s*条"):
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _severity(text: str) -> str | None:
    upper = text.upper()
    for value in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if value in upper:
            return value.title()
    return None


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match else None


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if "-" in text:
        year, month, day = text.split("-")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    if "/" in text:
        month, day, year = text.split("/")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    return text


def _clean_text(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text(" ", strip=True)
    else:
        text = str(node)
    return " ".join(text.replace("\xa0", " ").split())


def _clean_multiline(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text("\n", strip=True)
    else:
        text = str(node)
    lines = [" ".join(line.replace("\xa0", " ").split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "lxml")
