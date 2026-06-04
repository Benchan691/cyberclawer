from __future__ import annotations

from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.govcert.parsers.common import parse_alert_title
from vuln_scraper.scrapers.infosec.config import GOVCERT_BASE_URL, GOVCERT_DETAIL_URL, SOURCE_URL
from vuln_scraper.scrapers.infosec.parsers.common import clean_text, normalize_infosec_date, soup


DETAIL_PATH = "/en/alerts_detail.php"


def parse_alerts_list(
    html: str,
    *,
    page: int,
    provider: str = "infosec",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    parsed = soup(html)
    entries: list[ListEntry] = []
    for row in parsed.select(".listing .newsrow.alert"):
        entry = _entry_from_row(row, provider=provider, source_url=source_url)
        if entry is not None:
            entries.append(entry)
    return ListPage(page=page, entries=entries, total_pages=None, total_records=len(entries))


def _entry_from_row(row: Tag, *, provider: str, source_url: str | None) -> ListEntry | None:
    link = row.select_one('a[href*="alerts_detail.php"]')
    if link is None:
        return None

    code = _identity_code(str(link["href"]))
    if code is None:
        return None

    full_title = clean_text(row.select_one(".newstitle")) or clean_text(link)
    if not full_title:
        return None

    alert_code, alert_type, _ = parse_alert_title(full_title)
    published_date = normalize_infosec_date(clean_text(row.select_one(".newsdate")))
    summary = clean_text(row.select_one(".newscontent"))
    detail_url = _detail_url(str(link["href"]))

    return ListEntry(
        identity=VulnerabilityId(type="INFOSEC", code=code),
        title=full_title,
        vuln_type=alert_code,
        disclosure_date=published_date,
        status=alert_type,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "alert_code": alert_code,
            "alert_type": alert_type,
            "published_date": published_date,
            "summary": summary or None,
            "govcert_detail_url": detail_url,
        },
    )


def _identity_code(href: str) -> str | None:
    parsed = urlparse(_detail_url(href))
    if parsed.path != DETAIL_PATH:
        return None
    identity = parse_qs(parsed.query).get("id", [None])[0]
    if identity and identity.isdigit():
        return identity
    return None


def _detail_url(href: str) -> str:
    parsed = urlparse(urljoin(GOVCERT_BASE_URL, href))
    if parsed.netloc:
        return parsed.geturl()
    return f"{GOVCERT_DETAIL_URL}?{parsed.query}"
