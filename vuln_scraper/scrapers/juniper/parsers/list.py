from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.juniper.config import BASE_URL, PAGE_SIZE, SOURCE_URL


ARTICLE_ID_RE = re.compile(r"\bJSA\d{5,}\b", re.IGNORECASE)
RESULT_COUNT_RE = re.compile(r"\bResults\s+[\d,]+\s*-\s*[\d,]+\s+of\s+([\d,]+)", re.IGNORECASE)
DATE_RE = re.compile(r"\d{4}-\d{1,2}-\d{1,2}|[A-Z][a-z]+ \d{1,2}, \d{4}")


def parse_advisory_list(
    html: str,
    *,
    page: int,
    provider: str = "juniper",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    parsed = _soup(html)
    entries: list[ListEntry] = []
    seen: set[str] = set()
    for link in _article_links(parsed):
        entry = _entry_from_link(link, provider=provider, source_url=source_url)
        if entry is not None and entry.identity.code not in seen:
            entries.append(entry)
            seen.add(entry.identity.code)

    total_records = _total_records(parsed) or len(entries)
    total_pages = _total_pages(total_records)
    return ListPage(page=page, entries=entries, total_pages=total_pages, total_records=total_records)


def _article_links(parsed: BeautifulSoup) -> list[Tag]:
    links: list[Tag] = []
    for link in parsed.select('a[href*="/s/article/"], a.CoveoResultLink, a.result-link'):
        href = str(link.get("href") or "")
        text = _clean_text(link)
        if "/s/article/" in href or ARTICLE_ID_RE.search(text):
            links.append(link)
    return links


def _entry_from_link(link: Tag, *, provider: str, source_url: str | None) -> ListEntry | None:
    href = str(link.get("href") or "").strip()
    detail_url = urljoin(BASE_URL, href)
    code = _article_id(detail_url, _clean_text(link))
    if not code:
        return None

    container = _container(link)
    title = _title(link, container, code)
    if not title:
        return None
    text = _clean_multiline(container)
    published_date = _iso_date(_first_match(DATE_RE, text))
    article_type = _article_type(text)

    return ListEntry(
        identity=VulnerabilityId(type="JUNIPER", code=code),
        title=title,
        vuln_type=article_type,
        disclosure_date=published_date,
        status=article_type,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "article_id": code,
            "article_type": article_type,
            "source_name": "Knowledge",
            "published_date": published_date,
            "summary": _summary(container, title),
            "reference_links": [detail_url],
        },
    )


def _article_id(url: str, text: str) -> str | None:
    match = ARTICLE_ID_RE.search(text)
    if match:
        return match.group(0).upper()
    path = urlparse(urljoin(BASE_URL, url)).path.rstrip("/")
    slug = path.rsplit("/", 1)[-1]
    match = ARTICLE_ID_RE.search(slug)
    return match.group(0).upper() if match else None


def _container(link: Tag) -> Tag:
    for selector in (
        "c-quantic-result",
        "c-quantic-result-template",
        ".CoveoResult",
        ".quantic-result",
        ".result",
        ".lgc-bg",
        "article",
        "li",
    ):
        if selector.startswith("."):
            parent = link.find_parent(class_=lambda value: value and selector.strip(".") in str(value).split())
        else:
            parent = link.find_parent(selector)
        if parent is not None:
            return parent
    return link.parent or link


def _title(link: Tag, container: Tag, code: str) -> str:
    for node in (link, container.select_one("h1, h2, h3, .title, .CoveoResultLink")):
        text = _clean_text(node)
        if text:
            return re.sub(rf"^\s*{re.escape(code)}\s*[-:]\s*", "", text, flags=re.IGNORECASE).strip()
    return ""


def _summary(container: Tag, title: str) -> str | None:
    text = _clean_multiline(container)
    lines = [line for line in text.splitlines() if line.strip() and line.strip() != title]
    return lines[0] if lines else None


def _article_type(text: str) -> str:
    return "Security Advisories" if "security advis" in text.casefold() else "Security Advisory"


def _total_records(parsed: BeautifulSoup) -> int | None:
    text = _clean_text(parsed)
    match = RESULT_COUNT_RE.search(text)
    if match:
        return int(match.group(1).replace(",", ""))
    for pattern in (r"\b([\d,]+)\s+results\b", r"\bof\s+([\d,]+)\b"):
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return int(match.group(1).replace(",", ""))
    return None


def _total_pages(total_records: int | None) -> int | None:
    if not total_records:
        return None
    return max(1, (total_records + PAGE_SIZE - 1) // PAGE_SIZE)


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(0) if match else None


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    if "-" in value:
        year, month, day = value.split("-")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    return value


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
